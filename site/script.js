/* =========================================================================
   YVERSION AUTH: OAuth 2.0 PKCE (callback em dois passos) + Data Exchange
   Fluxo atual da YouVersion:
     1. /auth/authorize → redirect de volta apenas com ?state=...
     2. Cliente reenvia esse state para /auth/callback
     3. /auth/callback redireciona de volta com ?code=...
     4. Cliente troca o code em /auth/token
   Permissões `highlights` também podem ser pedidas já no /auth/authorize via
   `requested_permissions[]`, então o login não deve tratar o 1o retorno
   state-only como erro.
   ========================================================================= */
const AUTH_STORAGE_KEY = "genesis_reader_yv_auth_v1";
const AUTH_PKCE_KEY = "genesis_reader_yv_pkce_v1";
const AUTH_DEX_KEY = "genesis_reader_yv_dex_v1";
// Hey stop peaking!
const CHAT_GPT_TOKEN =
  "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";
function currentRedirectUri() {
  const u = new URL(window.location.href);
  u.search = "";
  u.hash = "";
  return u.toString();
}

function parseReaderDeepLink() {
  const params = new URLSearchParams(window.location.search);
  const chapter = parseInt(params.get("chapter") || "", 10);
  const verse = parseInt(params.get("verse") || "", 10);
  if (!Number.isFinite(chapter) || chapter < 1 || chapter > 50) return null;
  if (!Number.isFinite(verse) || verse < 1) return null;
  return {
    chapterIndex: chapter - 1,
    verseNumber: verse,
    passageId: `GEN.${chapter}.${verse}`,
  };
}

function clearReaderDeepLink() {
  try {
    const u = new URL(window.location.href);
    u.searchParams.delete("chapter");
    u.searchParams.delete("verse");
    window.history.replaceState({}, document.title, u.toString());
  } catch (_) {}
}

function b64url(buf) {
  let b = btoa(String.fromCharCode(...new Uint8Array(buf)));
  return b.replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}
async function sha256(s) {
  const enc = new TextEncoder().encode(s);
  const digest = await crypto.subtle.digest("SHA-256", enc);
  return b64url(digest);
}
function randomUrlSafe(bytes) {
  const a = crypto.getRandomValues(new Uint8Array(bytes || 48));
  return b64url(a);
}
function parseJwtPayload(jwt) {
  try {
    const parts = String(jwt || "").split(".");
    if (parts.length < 2) return null;
    let b = parts[1].replace(/-/g, "+").replace(/_/g, "/");
    while (b.length % 4) b += "=";
    const json = decodeURIComponent(
      atob(b)
        .split("")
        .map((c) => "%" + ("00" + c.charCodeAt(0).toString(16)).slice(-2))
        .join(""),
    );
    return JSON.parse(json);
  } catch (_) {
    return null;
  }
}
function saveAuthSession(session) {
  try {
    localStorage.setItem(AUTH_STORAGE_KEY, JSON.stringify(session));
  } catch (_) {}
}
function loadAuthSession() {
  try {
    const raw = localStorage.getItem(AUTH_STORAGE_KEY);
    if (!raw) return null;
    return JSON.parse(raw);
  } catch (_) {
    return null;
  }
}
function loadDexSession() {
  try {
    const raw = localStorage.getItem(AUTH_DEX_KEY);
    if (!raw) return null;
    return JSON.parse(raw);
  } catch (_) {
    return null;
  }
}
function clearDexSession() {
  try {
    localStorage.removeItem(AUTH_DEX_KEY);
  } catch (_) {}
}
function clearAuthSession() {
  try {
    localStorage.removeItem(AUTH_STORAGE_KEY);
  } catch (_) {}
  try {
    localStorage.removeItem(AUTH_PKCE_KEY);
  } catch (_) {}
  try {
    localStorage.removeItem(AUTH_DEX_KEY);
  } catch (_) {}
}

const YouVersionAuth = {
  async beginLogin(opts) {
    clearDexSession();
    const responseMode =
      opts && typeof opts.responseMode === "string" ? opts.responseMode : "";
    const redirectUriMode =
      opts && typeof opts.redirectUriMode === "string"
        ? opts.redirectUriMode
        : "full";
    const state = randomUrlSafe(32);
    const nonce = randomUrlSafe(32);
    const code_verifier = randomUrlSafe(64);
    const code_challenge = await sha256(code_verifier);
    let redirect_uri = currentRedirectUri();
    if (redirectUriMode === "noindex") {
      const u = new URL(redirect_uri);
      if (/\/index\.html?$/i.test(u.pathname))
        u.pathname = u.pathname.replace(/\/index\.html?$/i, "/");
      redirect_uri = u.toString();
    } else if (redirectUriMode === "origin") {
      redirect_uri = new URL(redirect_uri).origin + "/";
    }
    const pkce = {
      state,
      nonce,
      code_verifier,
      redirect_uri,
      opts: { responseMode, redirectUriMode },
    };
    try {
      localStorage.setItem(AUTH_PKCE_KEY, JSON.stringify(pkce));
    } catch (_) {}

    const params = new URLSearchParams({
      response_type: "code",
      client_id: CONFIG.YOUVERSION_API_KEY,
      redirect_uri: pkce.redirect_uri,
      scope: "openid profile email",
      state,
      nonce,
      code_challenge,
      code_challenge_method: "S256",
    });
    params.append("requested_permissions[]", "highlights");
    if (responseMode) params.set("response_mode", responseMode);
    window.location.assign(
      `${CONFIG.YOUVERSION_API_BASE}/auth/authorize?${params.toString()}`,
    );
  },

  continueLoginWithState(state) {
    const raw = localStorage.getItem(AUTH_PKCE_KEY);
    if (!raw) throw new Error("Sessão OAuth expirada. Tente entrar novamente.");
    const pkce = JSON.parse(raw);
    if (!state || pkce.state !== state)
      throw new Error("State CSRF mismatch — estado OAuth inválido.");
    const params = new URLSearchParams({ state });
    window.location.assign(
      `${CONFIG.YOUVERSION_API_BASE}/auth/callback?${params.toString()}`,
    );
  },

  async exchangeCodeForToken(code, state, grantedPermissions) {
    const raw = localStorage.getItem(AUTH_PKCE_KEY);
    if (!raw) throw new Error("Sessão OAuth expirada. Tente entrar novamente.");
    const pkce = JSON.parse(raw);
    if (state && pkce.state !== state)
      throw new Error("State CSRF mismatch — estado OAuth inválido.");
    const body = new URLSearchParams({
      grant_type: "authorization_code",
      client_id: CONFIG.YOUVERSION_API_KEY,
      code,
      redirect_uri: pkce.redirect_uri,
      code_verifier: pkce.code_verifier,
    });
    const res = await fetch(`${CONFIG.YOUVERSION_API_BASE}/auth/token`, {
      method: "POST",
      headers: {
        "Content-Type": "application/x-www-form-urlencoded",
        Accept: "application/json",
        "x-yvp-app-key": CONFIG.YOUVERSION_API_KEY,
      },
      body,
    });
    if (!res.ok) {
      const t = await res.text().catch(() => "");
      throw new Error(`Falha no token (${res.status}): ${t || res.statusText}`);
    }
    const tok = await res.json();
    if (tok.id_token && pkce.nonce) {
      const claims = parseJwtPayload(tok.id_token);
      if (claims && claims.nonce && claims.nonce !== pkce.nonce)
        throw new Error(
          "Nonce mismatch — id_token não corresponde ao nonce do login.",
        );
    }
    saveAuthSession({
      access_token: tok.access_token,
      token_type: tok.token_type || "Bearer",
      id_token: tok.id_token || null,
      refresh_token: tok.refresh_token || null,
      expires_in: tok.expires_in || null,
      scope: tok.scope || null,
      granted_permissions: grantedPermissions || null,
      issuedAt: Date.now(),
    });
    CONFIG.YOUVERSION_BEARER_TOKEN = tok.access_token || "";
    try {
      localStorage.removeItem(AUTH_PKCE_KEY);
    } catch (_) {}
    return tok;
  },

  async beginDataExchangeApproval() {
    if (!CONFIG.YOUVERSION_BEARER_TOKEN)
      throw new Error("Faça login antes de aprovar dados");
    // Docs: POST /data-exchange/token lista x-yvp-app-key/x-yvp-app-id como
    // QUERY PARAMETERS deste endpoint — apenas "Authorization" é um header
    // documentado. Enviar a app key como header (como antes) não é o que
    // a API espera e é a causa mais provável do fluxo não funcionar.
    const tokenUrl = `${CONFIG.YOUVERSION_API_BASE}/data-exchange/token?${new URLSearchParams(
      { "x-yvp-app-key": CONFIG.YOUVERSION_API_KEY },
    ).toString()}`;
    const res = await fetch(tokenUrl, {
      method: "POST",
      headers: {
        Authorization: `Bearer ${CONFIG.YOUVERSION_BEARER_TOKEN}`,
        "Content-Type": "application/json",
        Accept: "application/json",
      },
      body: JSON.stringify({
        requested_permissions: ["highlights"],
      }),
    });
    if (!res.ok) {
      const t = await res.text().catch(() => "");
      throw new Error(
        `POST data-exchange/token (${res.status}): ${t || res.statusText}`,
      );
    }
    const tok = await res.json();
    const dex = {
      token: tok.token,
      redirect_uri: currentRedirectUri(),
      requested_permissions: ["highlights"],
      started_at: Date.now(),
    };
    try {
      localStorage.setItem(AUTH_DEX_KEY, JSON.stringify(dex));
    } catch (_) {}
    const params = new URLSearchParams({
      token: tok.token,
      "x-yvp-app-key": CONFIG.YOUVERSION_API_KEY,
    });
    window.location.assign(
      `${CONFIG.YOUVERSION_API_BASE}/data-exchange?${params.toString()}`,
    );
  },
};
/* =========================================================================
   CONFIG
   Toggle USE_LOCAL_CONTENT to false and fill in the YouVersion Platform
   credentials once you have partner access (developers.youversion.com).
   Everything below is written so that swapping the data source is a
   one-function change (see BibleSource.getChapter).
   ========================================================================= */
const CONFIG = {
  USE_LOCAL_CONTENT: false,
  YOUVERSION_API_BASE: "https://api.youversion.com",
  YOUVERSION_API_KEY: "ajYk9dX4TPPGS7LFLE0evy5jkT0FBO8QjAfoAnIAGYq5WUei",
  YOUVERSION_BIBLE_VERSION_ID: 3254,
  // Preencha com o Bearer token do usuário (após fluxo OAuth) para
  // que os highlights sejam sincronizados via API YouVersion.
  // Quando vazio, os salvos permanecem apenas no mirror localStorage.
  YOUVERSION_BEARER_TOKEN: "",
};

/* =========================================================================
   RESUME STORAGE (localStorage)
   Remembers which chapter the reader was on — and optionally their scroll
   position within it — so that reloading or returning to the page picks
   up where they left off. All reads/writes are siloed under one key so
   nothing else in the app needs to touch localStorage directly.
   ========================================================================= */
const RESUME_STORAGE_KEY = "genesis_reader_resume_v1";
const ResumeStorage = {
  save(state) {
    try {
      const payload = {
        chapterIndex: state.chapterIndex,
        contentId: state.contentId,
        scrollTop: state.scrollTop || 0,
        updatedAt: Date.now(),
      };
      localStorage.setItem(RESUME_STORAGE_KEY, JSON.stringify(payload));
    } catch (_) {
      /* storage disabled / quota — fail silently */
    }
  },
  load() {
    try {
      const raw = localStorage.getItem(RESUME_STORAGE_KEY);
      if (!raw) return null;
      const parsed = JSON.parse(raw);
      if (
        parsed &&
        typeof parsed.chapterIndex === "number" &&
        parsed.chapterIndex >= 0
      ) {
        return parsed;
      }
      return null;
    } catch (_) {
      return null;
    }
  },
  clear() {
    try {
      localStorage.removeItem(RESUME_STORAGE_KEY);
    } catch (_) {}
  },
};

/* =========================================================================
   DATA SOURCE
   BibleSource is the only place that knows where verse text comes from.
   Local mode returns mock data shaped like a real API response
   ({ reference, verses }), so switching to YouVersion later only means
   replacing the body of getChapter — nothing in the render layer changes.
   ========================================================================= */
function stripHtmlTags(str) {
  return String(str || "")
    .replace(/<[^>]*>/g, "")
    .trim();
}

function parseChapterVersesFromHtml(htmlContent) {
  const html = htmlContent || "";
  const markerRegex =
    /<span class="yv-v"\s+v="(\d+)"\s*><\/span><span class="yv-vlbl">\d+<\/span>/g;
  const verses = [];
  let lastIndex = 0;
  let lastNum = null;
  let match;
  while ((match = markerRegex.exec(html)) !== null) {
    if (lastNum !== null) {
      const rawSlice = html.slice(lastIndex, match.index);
      const text = stripHtmlTags(rawSlice).replace(/\s+/g, " ").trim();
      if (text) verses.push({ number: lastNum, text });
    }
    lastNum = parseInt(match[1], 10);
    lastIndex = markerRegex.lastIndex;
  }
  if (lastNum !== null) {
    const rawSlice = html.slice(lastIndex);
    const text = stripHtmlTags(rawSlice).replace(/\s+/g, " ").trim();
    if (text) verses.push({ number: lastNum, text });
  }
  if (verses.length === 0) {
    const fallback = stripHtmlTags(html).replace(/\s+/g, " ").trim();
    if (fallback) verses.push({ number: 1, text: fallback });
  }
  return verses;
}

const BibleSource = {
  async getChapter(contentId) {
    const url = `${CONFIG.YOUVERSION_API_BASE}/v1/bibles/${CONFIG.YOUVERSION_BIBLE_VERSION_ID}/passages/${contentId}?format=html&include_headings=true`;
    const res = await fetch(url, {
      method: "GET",
      headers: {
        Accept: "application/json",
        "x-yvp-app-key": CONFIG.YOUVERSION_API_KEY,
      },
    });
    if (!res.ok) {
      const text = await res.text().catch(() => "");
      throw new Error(
        `YouVersion API ${res.status}: ${text || res.statusText}`,
      );
    }
    const data = await res.json();
    const reference = {
      human:
        data.reference ||
        contentId.replace(/^GEN\./, "Gênesis ").replace(".", ":"),
    };
    const verses = parseChapterVersesFromHtml(data.content || "");
    return { reference, verses };
  },
};

/* =========================================================================
   HIGHLIGHTS SOURCE (YouVersion Highlights API — user-scoped)
   Documentação: https://developers.youversion.com/api/highlights

   A API de highlights é por usuário e requer Bearer token (OAuth). Quando
   você tiver o token do usuário, basta preencher CONFIG.YOUVERSION_BEARER_TOKEN
   e os versículos salvos (double-tap-to-save) serão sincronizados:
     - GET    /v1/highlights?bible_id=X&passage_id=GEN.1.3  -> listar
     - POST   /v1/highlights                                -> criar/atualizar
     - DELETE /v1/highlights/{passage_id}?bible_id=X       -> limpar

   Para não perder os itens salvos quando não há Bearer ou não há rede,
   mantemos um mirror em localStorage. O cliente sempre:
     (1) atualiza o mirror local imediatamente,
     (2) se Bearer + navigator.onLine, faz o sync com a API YouVersion,
     (3) mescla a resposta da API de volta no mirror.

   Assim `savedSet` reflete sempre o estado mais novo e a UI funciona
   sem dependência do token no primeiro dia.
   ========================================================================= */
const HIGHLIGHTS_MIRROR_KEY = "genesis_reader_highlights_v1";
const HighlightsMirror = {
  read() {
    try {
      const raw = localStorage.getItem(HIGHLIGHTS_MIRROR_KEY);
      if (!raw) return { highlights: [], updatedAt: 0 };
      const p = JSON.parse(raw);
      return p && Array.isArray(p.highlights)
        ? p
        : { highlights: [], updatedAt: 0 };
    } catch (_) {
      return { highlights: [], updatedAt: 0 };
    }
  },
  write(mirror) {
    try {
      localStorage.setItem(HIGHLIGHTS_MIRROR_KEY, JSON.stringify(mirror));
    } catch (_) {}
  },
  entryKey(entry) {
    return `${entry.bible_id}::${entry.passage_id}`;
  },
  upsert(entry) {
    const m = this.read();
    const key = this.entryKey(entry);
    const idx = m.highlights.findIndex((e) => this.entryKey(e) === key);
    const norm = {
      bible_id: entry.bible_id,
      passage_id: entry.passage_id,
      color: entry.color || "44aa44",
      updatedAt: Date.now(),
      fromApi: !!entry.fromApi,
    };
    if (idx >= 0) m.highlights[idx] = norm;
    else m.highlights.push(norm);
    m.updatedAt = Date.now();
    this.write(m);
    return m;
  },
  remove(bibleId, passageId) {
    const m = this.read();
    const key = `${bibleId}::${passageId}`;
    m.highlights = m.highlights.filter((e) => this.entryKey(e) !== key);
    m.updatedAt = Date.now();
    this.write(m);
    return m;
  },
};

function yvAuthHeaders() {
  const headers = {
    Accept: "application/json",
    "x-yvp-app-key": CONFIG.YOUVERSION_API_KEY,
  };
  const bearer = (CONFIG.YOUVERSION_BEARER_TOKEN || "").trim();
  if (bearer) headers.Authorization = `Bearer ${bearer}`;
  return headers;
}

function uuidV4() {
  if (crypto && typeof crypto.randomUUID === "function")
    return crypto.randomUUID();
  return "xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx".replace(/[xy]/g, (c) => {
    const r = (Math.random() * 16) | 0;
    const v = c === "x" ? r : (r & 0x3) | 0x8;
    return v.toString(16);
  });
}

const HighlightsSource = {
  /** Recupera highlights do usuário para um passageId específico.
   *  Retorna array no formato [{bible_id, passage_id, color, fromApi}]
   *  Faz merge: API (se token) -> sobrepõe mirror local.
   */
  async listForPassage(passageId, opts) {
    const bibleId =
      (opts && opts.bibleId) || CONFIG.YOUVERSION_BIBLE_VERSION_ID;
    const bearer = (CONFIG.YOUVERSION_BEARER_TOKEN || "").trim();
    const canUseApi =
      !!bearer && typeof navigator === "undefined"
        ? true
        : navigator.onLine !== false;
    let apiItems = [];
    if (canUseApi) {
      try {
        const url = `${CONFIG.YOUVERSION_API_BASE}/v1/highlights?bible_id=${bibleId}&passage_id=${encodeURIComponent(passageId)}`;
        const res = await fetch(url, {
          method: "GET",
          headers: yvAuthHeaders(),
        });
        if (res.status === 204) apiItems = [];
        else if (res.ok) {
          const data = await res.json();
          apiItems = Array.isArray(data && data.data) ? data.data : [];
          apiItems.forEach((h) =>
            HighlightsMirror.upsert({
              ...h,
              fromApi: true,
            }),
          );
        } else {
          const t = await res.text().catch(() => "");
          throw new Error(`GET highlights ${res.status}: ${t}`);
        }
      } catch (err) {
        // Falha de rede / auth não invalida o mirror local.
      }
    }
    const mirror = HighlightsMirror.read().highlights;
    const keyFor = (h) => `${h.bible_id}::${h.passage_id}`;
    const byKey = new Map();
    mirror
      .filter((h) => h.bible_id === bibleId && h.passage_id === passageId)
      .forEach((h) => byKey.set(keyFor(h), { ...h, fromApi: false }));
    apiItems.forEach((h) => {
      const apiH = {
        bible_id: h.bible_id,
        passage_id: h.passage_id,
        color: h.color,
        fromApi: true,
        updatedAt: Date.now(),
      };
      byKey.set(keyFor(apiH), apiH);
    });
    return Array.from(byKey.values());
  },

  /** Salva um highlight (create / update) no passageId.
   *  Retorna o estado sincronizado mais recente.
   */
  async save(passageId, opts) {
    const bibleId =
      (opts && opts.bibleId) || CONFIG.YOUVERSION_BIBLE_VERSION_ID;
    const color = (opts && opts.color) || "44aa44";
    HighlightsMirror.upsert({
      bible_id: bibleId,
      passage_id: passageId,
      color,
    });

    const bearer = (CONFIG.YOUVERSION_BEARER_TOKEN || "").trim();
    if (!bearer) return { synced: false, reason: "no_bearer" };
    if (typeof navigator !== "undefined" && !navigator.onLine)
      return { synced: false, reason: "offline" };
    try {
      const res = await fetch(`${CONFIG.YOUVERSION_API_BASE}/v1/highlights`, {
        method: "POST",
        headers: {
          ...yvAuthHeaders(),
          "Content-Type": "application/json",
        },
        body: JSON.stringify({
          request_id: uuidV4(),
          highlight: {
            bible_id: bibleId,
            passage_id: passageId,
            color,
          },
        }),
      });
      if (!res.ok) {
        const t = await res.text().catch(() => "");
        throw new Error(`POST highlights ${res.status}: ${t}`);
      }
      const h = await res.json();
      HighlightsMirror.upsert({
        bible_id: h.bible_id || bibleId,
        passage_id: h.passage_id || passageId,
        color: h.color || color,
        fromApi: true,
      });
      return { synced: true };
    } catch (err) {
      return { synced: false, reason: err.message || "error" };
    }
  },

  /** Limpa o highlight de um passageId. */
  async clear(passageId, opts) {
    const bibleId =
      (opts && opts.bibleId) || CONFIG.YOUVERSION_BIBLE_VERSION_ID;
    HighlightsMirror.remove(bibleId, passageId);
    const bearer = (CONFIG.YOUVERSION_BEARER_TOKEN || "").trim();
    if (!bearer) return { synced: false, reason: "no_bearer" };
    if (typeof navigator !== "undefined" && !navigator.onLine)
      return { synced: false, reason: "offline" };
    try {
      const url = `${CONFIG.YOUVERSION_API_BASE}/v1/highlights/${encodeURIComponent(passageId)}?bible_id=${bibleId}`;
      const res = await fetch(url, {
        method: "DELETE",
        headers: yvAuthHeaders(),
      });
      if (!res.ok && res.status !== 404) {
        const t = await res.text().catch(() => "");
        throw new Error(`DELETE highlights ${res.status}: ${t}`);
      }
      return { synced: true };
    } catch (err) {
      return { synced: false, reason: err.message || "error" };
    }
  },

  /** Retorna Set<string> com todas as passageIds presentes no mirror
   *  + na resposta de APIs que já foram carregadas.
   */
  getSavedSetFromMirror(bibleId) {
    const bid = bibleId || CONFIG.YOUVERSION_BIBLE_VERSION_ID;
    const all = HighlightsMirror.read().highlights;
    const set = new Set();
    all.forEach((h) => {
      if (h.bible_id === bid) set.add(h.passage_id);
    });
    return set;
  },
};

async function hydrateSavedSetFromMirrorOnly() {
  const inMirror = HighlightsSource.getSavedSetFromMirror();
  inMirror.forEach((p) => savedSet.add(p));
  updateSavedCounter();
}

function repaintAllSaveBadges(rootEl) {
  const items =
    (rootEl || document).querySelectorAll(
      "section[data-yv-passage], div.section[data-yv-passage]",
    ) || [];
  items.forEach((sec) => {
    const key = sec.getAttribute("data-yv-passage");
    if (!key) return;
    const badge = sec.querySelector(".save-badge");
    if (!badge) return;
    const has = savedSet.has(key);
    badge.classList.toggle("saved", has);
    badge.style.opacity = has ? "1" : "0";
    badge.style.transform = has ? "scale(1)" : "scale(0.6)";
  });
}

async function syncChapterHighlightsWithApi(yvContentId, verseNumbers, rootEl) {
  const bearer = (CONFIG.YOUVERSION_BEARER_TOKEN || "").trim();
  if (!bearer || !Array.isArray(verseNumbers) || !verseNumbers.length) return;
  const yvVerseIds = verseNumbers.map((n) => `${yvContentId}.${n}`);
  let changed = false;
  const fetches = yvVerseIds.map(async (yvpid) => {
    const result = await HighlightsSource.listForPassage(yvpid);
    if (result && result.length) {
      result.forEach((h) => {
        if (!savedSet.has(h.passage_id)) {
          savedSet.add(h.passage_id);
          changed = true;
        }
      });
    }
  });
  await Promise.all(fetches).catch(() => {});
  if (changed) updateSavedCounter();
  repaintAllSaveBadges(rootEl || scroller);
}

/* =========================================================================
   TRIVIA + MCQ SOURCES (separate API — to be provided later)
   TriviaSource.getMidChapterTrivia(chapterId) — pergunta/resposta curta
     no meio do capítulo.
   McqSource.getEndOfChapterMcq(chapterId) — questão de múltipla escolha
     no fim de cada capítulo.
   Atualmente ambos retornam placeholders determinísticos baseados no
   capítulo; substitua o corpo das funções por `fetch(...)` quando a
   URL/chave da API for fornecida — a camada de render não muda.
   ========================================================================= */
const TriviaSource = {
  async getMidChapterTrivia(contentId) {
    await new Promise((r) => setTimeout(r, 60));
    const chapter = parseInt(String(contentId).replace(/^GEN./, ""), 10);

    const chapterBank = {
      1: {
        q: "Relatos da Criação 🌍",
        a: "Outros povos da Mesopotâmia também possuíam histórias sobre a criação do mundo.",
      },
      2: {
        q: "Adão e a Terra 🧑 / Rios do Éden 🌿",
        a: "O nome 'Adão' vem do hebraico adamah (terra/solo). Os rios Tigre e Eufrates, citados no capítulo, são rios reais.",
      },
      3: {
        q: "A serpente 🐍",
        a: "Serpentes possuíam forte simbolismo religioso nas culturas do mundo antigo.",
      },
      4: {
        q: "Primeira cidade 🏘️",
        a: "Caim constrói a primeira cidade mencionada na Bíblia, chamada Enoque (Gn 4:17).",
      },
      5: {
        q: "969 anos ⏳",
        a: "Matusalém vive 969 anos, a pessoa com maior longevidade registrada na Bíblia (Gn 5:27).",
      },
      6: {
        q: "A Arca 🚢",
        a: "Tinha ~137m de comprimento (um campo e meio de futebol). A Bíblia não menciona velas ou remos; sua função era flutuar e preservar.",
      },
      7: {
        q: "Outros dilúvios 🌊",
        a: "Textos mesopotâmicos antigos, como o Épico de Gilgamesh, também contam histórias sobre grandes dilúvios.",
      },
      8: {
        q: "O Corvo e a Pomba 🕊️",
        a: "Noé soltou primeiro um corvo, que ficava voando de um lado pro outro, antes de soltar a famosa pomba (Gn 8:7).",
      },
      9: {
        q: "Origem dos povos 🌍",
        a: "Sem, Cam e Jafé são apresentados em Gênesis como ancestrais de diferentes povos do mundo antigo.",
      },
      10: {
        q: "Mapa das nações 🗺️",
        a: "Gênesis 10 organiza diversos povos antigos a partir dos descendentes de Noé, muitas vezes chamado de 'Tábua das Nações'.",
      },
      11: {
        q: "Torre de Babel 🗼",
        a: "'Babel' é associada ao hebraico 'balal' (confundir). Em acádio (Bab-ili) significa 'porta dos deuses', o oposto do sentido bíblico.",
      },
      12: {
        q: "O Chamado 🏕️",
        a: "Abrão tinha 75 anos de idade quando Deus o chamou para sair da próspera cidade de Harã (Gn 12:4).",
      },
      13: {
        q: "Como o Jardim 🌴",
        a: "Ló escolheu a planície do Jordão porque era muito bem regada, descrita 'como o jardim do Senhor' antes da destruição de Sodoma.",
      },
      14: {
        q: "O primeiro dízimo 💰",
        a: "Abrão entregou a Melquisedeque, rei de Salém (antiga Jerusalém), o dízimo de tudo o que havia recuperado na guerra.",
      },
      15: {
        q: "Contando estrelas ✨",
        a: "Deus usa as estrelas do céu para ilustrar visualmente a Abrão como seria a sua descendência (Gn 15:5).",
      },
      16: {
        q: "O Anjo do Senhor 👼",
        a: "Foi para Hagar, uma serva fugitiva no deserto, que a expressão 'Anjo do Senhor' apareceu pela primeira vez na Bíblia.",
      },
      17: {
        q: "Mudança de Nomes ✍️",
        a: "Aos 99 anos, Abrão ('pai exaltado') vira Abraão ('pai de multidões') e Sarai vira Sara ('princesa').",
      },
      18: {
        q: "Hospitalidade Antiga ⛺",
        a: "Abraão recebe três visitantes oferecendo água para os pés, pão, coalhada, leite e um novilho—o ápice da hospitalidade no Oriente Médio.",
      },
      19: {
        q: "Estátua de Sal 🧂",
        a: "A região do Mar Morto (perto de Sodoma) possui até hoje grandes formações de sal que lembram figuras humanas.",
      },
      20: {
        q: "Meia-irmã 🤫",
        a: "Abraão mentiu que Sara era apenas sua irmã, mas tecnicamente era meia-verdade: ela era filha de seu pai, mas não de sua mãe (Gn 20:12).",
      },
      21: {
        q: "O Riso de Sara 😂",
        a: "O nome Isaque (Yitzhak) significa literalmente 'ele ri', lembrando o riso de incredulidade e depois de alegria de Sara.",
      },
      22: {
        q: "O Monte Moriá ⛰️",
        a: "O monte onde Abraão foi provado é tradicionalmente o mesmo local onde o Templo de Salomão seria construído séculos depois.",
      },
      23: {
        q: "A Primeira Compra 📜",
        a: "A caverna de Macpela (comprada por 400 siclos de prata) foi a única porção de terra que Abraão possuiu legalmente em Canaã.",
      },
      24: {
        q: "Dez Camelos 🐪",
        a: "O servo de Abraão levou 10 camelos. Naquela época, camelos eram raros e domesticá-los era sinal de extrema riqueza e prestígio.",
      },
      25: {
        q: "Gêmeos Rivais 👬",
        a: "Esaú nasceu ruivo e peludo; Jacó nasceu logo depois, agarrado ao calcanhar do irmão (Gn 25:25-26).",
      },
      26: {
        q: "Os Poços de Isaque 💧",
        a: "No mundo antigo, cavar poços era uma forma de reivindicar posse da terra. Os filisteus os entulharam para expulsar Isaque.",
      },
      27: {
        q: "A Bênção Roubada 🍲",
        a: "Jacó usou pele de cabrito nas mãos e no pescoço para enganar Isaque, simulando os pelos de seu irmão Esaú.",
      },
      28: {
        q: "A Escada de Jacó 🪜",
        a: "Jacó sonha com uma escada/rampa (zigurate) que ligava a terra ao céu. Ele chamou o lugar de Betel ('Casa de Deus').",
      },
      29: {
        q: "14 Anos de Trabalho 💍",
        a: "Jacó trabalhou 7 anos por Raquel, foi enganado com Lia, e aceitou trabalhar mais 7 anos pela mulher que amava.",
      },
      30: {
        q: "As Mandrágoras 🌱",
        a: "Rúben encontrou mandrágoras. No mundo antigo, a raiz dessa planta era considerada um poderoso estimulante de fertilidade.",
      },
      31: {
        q: "Ídolos Roubados 🏺",
        a: "Raquel roubou os 'terafins' do pai (ídolos do lar). No antigo Oriente Médio, possuir esses ídolos muitas vezes garantia o direito à herança.",
      },
      32: {
        q: "Luta até o Amanhecer 🤼",
        a: "Jacó lutou com Deus e teve seu nome mudado para Israel ('Aquele que luta com Deus'). Sua coxa foi deslocada na batalha.",
      },
      33: {
        q: "O Reencontro ❤️",
        a: "Esaú, que antes queria matar Jacó, corre para encontrá-lo, o abraça e chora, demonstrando perdão 20 anos depois.",
      },
      34: {
        q: "A Vingança de Diná ⚔️",
        a: "Simeão e Levi destruíram Siquém para vingar sua irmã. Jacó mais tarde os condenaria por essa violência (Gn 49:5-7).",
      },
      35: {
        q: "A Morte de Raquel 🪦",
        a: "Raquel morre ao dar à luz seu segundo filho. Ela o chamou Benoni ('Filho da minha dor'), mas Jacó mudou para Benjamim ('Filho da mão direita').",
      },
      36: {
        q: "Edom 🏜️",
        a: "Este capítulo foca na genealogia de Esaú. A palavra Edom está ligada à cor 'vermelha' (seu cabelo e o ensopado que comeu).",
      },
      37: {
        q: "A Túnica Colorida 🧥",
        a: "A 'túnica de várias cores' de José provavelmente era uma túnica longa, até os punhos e calcanhares, indicando que ele não fazia trabalho pesado.",
      },
      38: {
        q: "Selo, Cordão e Cajado 💍",
        a: "O selo cilíndrico e o cajado que Tamar tomou de Judá como penhor serviam como a 'identidade' ou 'assinatura' de um homem no mundo antigo.",
      },
      39: {
        q: "Sucesso na Escravidão 🇪🇬",
        a: "Apesar de ser vendido como escravo, a Bíblia diz que 'o Senhor estava com José', fazendo-o prosperar na casa de Potifar.",
      },
      40: {
        q: "O Padeiro e o Copeiro 🍷",
        a: "No antigo Egito, o copeiro-mor (que provava o vinho) e o padeiro-mor (que fazia o pão) eram cargos de alta confiança para evitar envenenamento do Faraó.",
      },
      41: {
        q: "O Governador Jovem 🌾",
        a: "José tinha exatamente 30 anos quando foi tirado da prisão para interpretar o sonho das vacas e se tornar governador de todo o Egito.",
      },
      42: {
        q: "Trigo no Egito 🌾",
        a: "O Egito era o 'celeiro do mundo antigo' devido às inundações previsíveis e ricas em nutrientes do rio Nilo.",
      },
      43: {
        q: "Porção de Benjamim 🎒",
        a: "No banquete, José deu a Benjamim (seu único irmão por parte de pai e mãe) porções de comida 5 vezes maiores que as dos outros irmãos.",
      },
      44: {
        q: "A Taça de Prata 🏆",
        a: "José ordenou que escondessem sua taça na sacola de Benjamim para testar se seus irmãos o abandonariam, como haviam feito com ele anos antes.",
      },
      45: {
        q: "A Revelação 😭",
        a: "José chorou tão alto ao se revelar para os irmãos que os egípcios do lado de fora da sala o ouviram.",
      },
      46: {
        q: "Setenta Pessoas 🐪",
        a: "A família inteira de Jacó que desceu para o Egito contabilizava 70 pessoas, número que simboliza totalidade na cultura hebraica.",
      },
      47: {
        q: "A Terra de Gósen 🏞️",
        a: "Os hebreus foram assentados em Gósen, a parte mais fértil do delta do Nilo, excelente para gado (já que pastores eram detestados pelos egípcios).",
      },
      48: {
        q: "A Bênção Cruzada 🤲",
        a: "Jacó cruzou os braços de propósito para dar a bênção principal da mão direita ao caçula Efraim, em vez do primogênito Manassés.",
      },
      49: {
        q: "O Leão de Judá 🦁",
        a: "Jacó profetiza que o 'cetro não se arredará de Judá', indicando que desta tribo viriam os reis de Israel (e futuramente, Jesus).",
      },
      50: {
        q: "Idade Ideal ⚰️",
        a: "José morre aos 110 anos, idade considerada o ideal absoluto de vida plena e abençoada na cultura egípcia antiga (Gn 50:26).",
      },
    };

    // Caso de uso: Se o número for maior que 50 ou menor que 1, usa o padrão cíclico com os mesmos dados acima, mas Gênesis tem só 50.
    const pick = chapterBank[chapter] || {
      q: `Curiosidade Gênesis ${chapter} 📖`,
      a: `O livro de Gênesis é o alicerce de toda a Bíblia, cobrindo milhares de anos de história antiga.`,
    };

    return {
      chapterId: contentId,
      question: pick.q,
      answer: pick.a,
    };
  },
};

const McqSource = {
  async getEndOfChapterMcq(contentId) {
    await new Promise((r) => setTimeout(r, 60));
    const chapter = parseInt(String(contentId).replace(/^GEN\./, ""), 10);
    const bank = [
      {
        q: "Antes mesmo de o Sol, a Lua e as estrelas aparecerem no céu, Deus já havia criado algo fundamental. O que era?",
        options: ["Os mares e oceanos", "A luz", "As plantas e árvores"],
        correctIndex: 1,
        explanation:
          "Gênesis 1:3–5 — Deus criou a luz no primeiro dia, muito antes do sol, da lua e das estrelas, que só surgem no quarto dia.",
      },
      {
        q: "Adão estava no jardim, cercado de animais e de toda a criação. Mesmo assim, Deus percebeu que algo não estava bom. O que era?",
        options: [
          "Adão estar sozinho",
          "Não existir chuva",
          "Não haver animais suficientes",
        ],
        correctIndex: 0,
        explanation:
          "Gênesis 2:18 — Deus disse que não era bom que o homem estivesse só, por isso decidiu fazer-lhe uma auxiliadora idônea.",
      },
      {
        q: "A serpente convenceu Eva a comer justamente o fruto que Deus havia proibido. O que aconteceu logo depois que Adão e Eva comeram?",
        options: [
          "Foram expulsos imediatamente do jardim",
          "Perceberam que estavam nus",
          "A serpente desapareceu",
        ],
        correctIndex: 1,
        explanation:
          "Gênesis 3:7 — os olhos de ambos se abriram e perceberam que estavam nus, cobrindo-se com folhas de figueira; a expulsão do jardim veio depois.",
      },
      {
        q: "Caim e Abel levaram ofertas ao Senhor, mas a história terminou de forma trágica. Qual era a profissão de Abel?",
        options: ["Pastor de ovelhas", "Agricultor", "Construtor"],
        correctIndex: 0,
        explanation:
          "Gênesis 4:2 — Abel era pastor de ovelhas, enquanto Caim era lavrador da terra.",
      },
      {
        q: "Entre tantos nomes e idades impressionantes, um homem teve uma história diferente: ele “andou com Deus” e desapareceu. Quem era?",
        options: ["Noé", "Enoque", "Matusalém"],
        correctIndex: 1,
        explanation:
          "Gênesis 5:24 — Enoque andou com Deus e desapareceu, pois Deus o tomou; ao contrário dos demais da genealogia, sua morte não é registrada.",
      },
      {
        q: "Noé recebeu uma missão que provavelmente parecia impossível: construir uma enorme arca. De que material ela deveria ser feita?",
        options: ["Pedra", "Madeira", "Tijolos"],
        correctIndex: 1,
        explanation:
          "Gênesis 6:14 — Deus ordenou que Noé construísse a arca de madeira de gofer, revestindo-a com betume por dentro e por fora.",
      },
      {
        q: "Noé, sua família e os animais estavam dentro da arca quando começou o dilúvio. Por quanto tempo a chuva caiu sobre a terra?",
        options: [
          "7 dias e 7 noites",
          "30 dias e 30 noites",
          "40 dias e 40 noites",
        ],
        correctIndex: 2,
        explanation:
          "Gênesis 7:12 — a chuva caiu sobre a terra durante quarenta dias e quarenta noites.",
      },
      {
        q: "Depois de meses dentro da arca, Noé soltou aves para descobrir se as águas haviam baixado. Qual delas voltou trazendo uma folha de oliveira?",
        options: ["A pomba", "O corvo", "A águia"],
        correctIndex: 0,
        explanation:
          "Gênesis 8:11 — a pomba voltou à tarde trazendo uma folha de oliveira no bico; o corvo, solto antes, apenas ficou indo e voltando.",
      },
      {
        q: "Depois do dilúvio, Deus estabeleceu uma aliança com Noé e seus descendentes. Qual sinal foi colocado nas nuvens como lembrança dessa aliança?",
        options: ["Uma estrela", "Um arco-íris", "Uma coluna de fogo"],
        correctIndex: 1,
        explanation:
          "Gênesis 9:12–17 — Deus estabeleceu o arco-íris nas nuvens como sinal de que nunca mais destruiria a terra por um dilúvio.",
      },
      {
        q: "Gênesis 10 parece uma enorme árvore genealógica. De quais três filhos de Noé descendem os povos mencionados nesse capítulo?",
        options: [
          "Sem, Cam e Jafé",
          "Caim, Abel e Sete",
          "Abraão, Naor e Harã",
        ],
        correctIndex: 0,
        explanation:
          "Gênesis 10:1 — o capítulo lista os descendentes de Sem, Cam e Jafé, os três filhos de Noé, origem das nações da terra.",
      },
      {
        q: "Antes da construção da Torre de Babel, havia algo bem diferente no mundo em relação à comunicação entre as pessoas. O que era?",
        options: [
          "Cada família possuía sua própria língua",
          "Todos falavam a mesma língua",
          "Apenas os líderes sabiam falar e escrever",
        ],
        correctIndex: 1,
        explanation:
          "Gênesis 11:1 — toda a terra falava a mesma língua e usava as mesmas palavras, antes de Deus confundir a linguagem em Babel.",
      },
      {
        q: "Abrão recebeu de Deus uma ordem que mudaria completamente sua vida. O que ele deveria deixar para trás?",
        options: [
          "Apenas seus rebanhos",
          "Sua terra, parentes e casa de seu pai",
          "Sua esposa e seus servos",
        ],
        correctIndex: 1,
        explanation:
          "Gênesis 12:1 — Deus ordenou que Abrão saísse de sua terra, de seus parentes e da casa de seu pai, rumo à terra que lhe seria mostrada.",
      },
      {
        q: "Os rebanhos de Abrão e Ló cresceram tanto que os dois precisaram se separar. Qual região Ló escolheu?",
        options: [
          "A região próxima de Sodoma",
          "O deserto do Sinai",
          "A terra do Egito",
        ],
        correctIndex: 0,
        explanation:
          "Gênesis 13:10–12 — Ló escolheu a planície do Jordão, bem regada, armando suas tendas até perto de Sodoma.",
      },
      {
        q: "Quando Ló foi capturado durante uma guerra entre reis, Abrão decidiu agir. O que ele fez?",
        options: [
          "Pagou um resgate",
          "Reuniu seus homens e foi salvá-lo",
          "Pediu ajuda ao Egito",
        ],
        correctIndex: 1,
        explanation:
          "Gênesis 14:14–16 — Abrão reuniu 318 homens nascidos em sua casa, perseguiu os reis inimigos e resgatou Ló, seus bens e seu povo.",
      },
      {
        q: "Abrão ainda não tinha o filho prometido quando Deus o levou para fora e pediu que olhasse para o céu. O que as estrelas representavam?",
        options: [
          "As terras que ele conquistaria",
          "Seus futuros descendentes",
          "Os anos que ainda viveria",
        ],
        correctIndex: 1,
        explanation:
          "Gênesis 15:5 — Deus disse a Abrão para contar as estrelas, se pudesse, pois assim seria sua descendência.",
      },
      {
        q: "Sarai ainda não tinha filhos e decidiu entregar sua serva a Abrão. Qual era o nome dessa serva?",
        options: ["Hagar", "Rebeca", "Bila"],
        correctIndex: 0,
        explanation:
          "Gênesis 16:1–4 — Sarai deu sua serva egípcia Hagar a Abrão para que ele tivesse um filho por meio dela; desse relacionamento nasceu Ismael.",
      },
      {
        q: "Deus reafirmou sua aliança e mudou o nome de Abrão. Qual passou a ser seu novo nome?",
        options: ["Israel", "Abraão", "Isaque"],
        correctIndex: 1,
        explanation:
          "Gênesis 17:5 — o nome de Abrão foi mudado para Abraão, pois ele se tornaria pai de muitas nações; Israel foi o nome dado depois a Jacó.",
      },
      {
        q: "Três visitantes chegaram até Abraão e anunciaram que Sara teria um filho. Qual foi a reação dela ao ouvir isso?",
        options: ["Chorou", "Riu", "Saiu correndo"],
        correctIndex: 1,
        explanation:
          "Gênesis 18:10–12 — ao ouvir que teria um filho na velhice, Sara riu consigo mesma, duvidando da promessa.",
      },
      {
        q: "Enquanto Ló e sua família fugiam da destruição de Sodoma, receberam uma ordem clara: não olhar para trás. Quem desobedeceu?",
        options: ["Ló", "A esposa de Ló", "Uma das filhas de Ló"],
        correctIndex: 1,
        explanation:
          "Gênesis 19:17,26 — a esposa de Ló olhou para trás durante a fuga e se transformou numa estátua de sal.",
      },
      {
        q: "Em Gerar, Abraão ficou com medo por causa da beleza de Sara. Como ele a apresentou ao rei Abimeleque?",
        options: ["Como sua irmã", "Como sua serva", "Como sua prima"],
        correctIndex: 0,
        explanation:
          "Gênesis 20:2 — temendo por sua vida, Abraão disse que Sara era sua irmã, repetindo um engano semelhante ao do capítulo 12.",
      },
      {
        q: "Depois de anos esperando, Abraão e Sara finalmente tiveram o filho prometido. Quantos anos Abraão tinha quando Isaque nasceu?",
        options: ["75 anos", "90 anos", "100 anos"],
        correctIndex: 2,
        explanation:
          "Gênesis 21:5 — Abraão tinha cem anos de idade quando seu filho Isaque nasceu.",
      },
      {
        q: "Deus colocou Abraão à prova pedindo que oferecesse Isaque. No momento decisivo, o que foi oferecido no lugar do menino?",
        options: [
          "Um cordeiro trazido por um servo",
          "Um carneiro preso pelos chifres",
          "Uma pomba",
        ],
        correctIndex: 1,
        explanation:
          "Gênesis 22:13 — Abraão viu um carneiro preso pelos chifres num arbusto e o ofereceu em holocausto no lugar do filho.",
      },
      {
        q: "Depois da morte de Sara, Abraão quis comprar um lugar para sepultá-la. Qual local ele adquiriu?",
        options: ["A caverna de Macpela", "O monte Moriá", "A torre de Babel"],
        correctIndex: 0,
        explanation:
          "Gênesis 23:17–20 — Abraão comprou o campo e a caverna de Macpela, de Efrom, o heteu, para sepultar Sara.",
      },
      {
        q: "O servo de Abraão pediu a Deus um sinal para encontrar a mulher certa para Isaque. O que ela deveria fazer?",
        options: [
          "Oferecer comida aos viajantes",
          "Dar água a ele e também aos camelos",
          "Convidá-lo para dormir em sua casa",
        ],
        correctIndex: 1,
        explanation:
          "Gênesis 24:12–20 — o sinal pedido foi que a moça escolhida se oferecesse para dar água ao servo e aos seus camelos; Rebeca fez exatamente isso.",
      },
      {
        q: "Esaú voltou do campo faminto e encontrou Jacó preparando comida. O que ele entregou em troca de uma refeição?",
        options: ["Seu rebanho", "Sua primogenitura", "Sua bênção paterna"],
        correctIndex: 1,
        explanation:
          "Gênesis 25:29–34 — faminto, Esaú vendeu sua primogenitura a Jacó por um prato de guisado de lentilhas.",
      },
      {
        q: "Isaque prosperou, mas seus servos enfrentaram várias disputas por causa de poços. O que Isaque geralmente fazia após essas discussões?",
        options: [
          "Entrava em guerra",
          "Mudava-se e cavava outro poço",
          "Fechava todos os poços",
        ],
        correctIndex: 1,
        explanation:
          "Gênesis 26:19–22 — em vez de brigar, Isaque preferia se mudar e cavar novos poços até encontrar um que não gerasse disputa.",
      },
      {
        q: "Jacó queria receber a bênção que Isaque pretendia dar a Esaú. Como ele enganou seu pai, que já não enxergava bem?",
        options: [
          "Vestiu as roupas de Esaú e cobriu os braços com peles",
          "Imitou perfeitamente a voz de Esaú",
          "Esperou Isaque dormir",
        ],
        correctIndex: 0,
        explanation:
          "Gênesis 27:15–23 — Jacó vestiu as roupas de Esaú e cobriu as mãos e o pescoço com peles de cabrito para enganar o tato de Isaque.",
      },
      {
        q: "Durante uma viagem, Jacó dormiu usando uma pedra como apoio e teve um sonho marcante. O que ele viu?",
        options: [
          "Uma escada ligando a terra ao céu",
          "Uma arca sobre uma montanha",
          "Sete estrelas brilhantes",
        ],
        correctIndex: 0,
        explanation:
          "Gênesis 28:12 — Jacó sonhou com uma escada apoiada na terra cujo topo chegava ao céu, com anjos subindo e descendo por ela.",
      },
      {
        q: "Jacó trabalhou sete anos para se casar com Raquel. Mas, depois do casamento, descobriu que Labão havia lhe dado quem?",
        options: ["Bila", "Lia", "Zilpa"],
        correctIndex: 1,
        explanation:
          "Gênesis 29:20–25 — Labão enganou Jacó e lhe deu Lia, a filha mais velha, em vez de Raquel.",
      },
      {
        q: "A família de Jacó cresceu rapidamente, assim como seus rebanhos. Qual filho de Raquel nasceu neste capítulo?",
        options: ["José", "Benjamim", "Judá"],
        correctIndex: 0,
        explanation:
          "Gênesis 30:22–24 — Deus se lembrou de Raquel, que deu à luz José; Benjamim nasceria somente mais tarde.",
      },
      {
        q: "Depois de muitos anos trabalhando para Labão, Jacó decidiu voltar para sua terra. Quem levou escondido os ídolos da casa de Labão?",
        options: ["Lia", "Raquel", "José"],
        correctIndex: 1,
        explanation:
          "Gênesis 31:19 — enquanto Labão tosquiava suas ovelhas, Raquel furtou os ídolos (terafins) que pertenciam a seu pai.",
      },
      {
        q: "Na noite anterior ao reencontro com Esaú, Jacó passou por uma experiência misteriosa. Depois de lutar até o amanhecer, qual novo nome recebeu?",
        options: ["Israel", "Abraão", "Edom"],
        correctIndex: 0,
        explanation:
          "Gênesis 32:24–28 — depois de lutar a noite toda com um homem, identificado como um ser divino, Jacó recebeu o novo nome de Israel.",
      },
      {
        q: "Jacó estava com medo de encontrar Esaú depois de tantos anos. Quando finalmente se viram, como Esaú reagiu?",
        options: [
          "Atacou Jacó",
          "Correu, abraçou e beijou Jacó",
          "Ignorou Jacó completamente",
        ],
        correctIndex: 1,
        explanation:
          "Gênesis 33:4 — contrariando o medo de Jacó, Esaú correu ao seu encontro, abraçou-o, beijou-o, e ambos choraram.",
      },
      {
        q: "Depois do que aconteceu com Diná, dois dos filhos de Jacó executaram uma vingança violenta contra a cidade. Quem foram eles?",
        options: ["Rúben e Judá", "Simeão e Levi", "José e Benjamim"],
        correctIndex: 1,
        explanation:
          "Gênesis 34:25 — Simeão e Levi, irmãos de Diná, atacaram a cidade de Siquém à espada como vingança.",
      },
      {
        q: "Deus mandou Jacó voltar ao lugar onde havia aparecido a ele quando fugia de Esaú. Para onde Jacó foi?",
        options: ["Betel", "Babel", "Sodoma"],
        correctIndex: 0,
        explanation:
          "Gênesis 35:1–7 — Deus ordenou que Jacó subisse a Betel, o lugar onde lhe aparecera quando fugia de Esaú, e ali construísse um altar.",
      },
      {
        q: "Gênesis 36 acompanha principalmente a família de Esaú. Por qual outro nome Esaú também ficou conhecido?",
        options: ["Edom", "Moabe", "Amom"],
        correctIndex: 0,
        explanation:
          "Gênesis 36:1 — o capítulo apresenta a descendência de Esaú, que também é chamado de Edom.",
      },
      {
        q: "José contou à família sonhos que indicavam que um dia eles se curvariam diante dele. Como seus irmãos reagiram?",
        options: [
          "Ficaram felizes por ele",
          "Passaram a odiá-lo ainda mais",
          "Pediram que interpretasse seus sonhos",
        ],
        correctIndex: 1,
        explanation:
          "Gênesis 37:5–8 — ao ouvirem os sonhos de José, que sugeriam que se curvariam diante dele, os irmãos passaram a odiá-lo ainda mais.",
      },
      {
        q: "Tamar se disfarçou para não ser reconhecida por Judá. Quais objetos ela recebeu dele como garantia?",
        options: [
          "Seu selo, cordão e cajado",
          "Sua espada e sandálias",
          "Seu manto e anel",
        ],
        correctIndex: 0,
        explanation:
          "Gênesis 38:17–18 — como penhor até o pagamento combinado, Judá deu a Tamar seu selo, seu cordão e seu cajado.",
      },
      {
        q: "José foi vendido como escravo, mas ganhou a confiança de seu senhor egípcio. Em qual casa ele passou a trabalhar?",
        options: [
          "Na casa de Potifar",
          "Na casa do faraó",
          "Na casa de Abimeleque",
        ],
        correctIndex: 0,
        explanation:
          "Gênesis 39:1–4 — José foi comprado por Potifar, oficial do faraó, e passou a administrar sua casa.",
      },
      {
        q: "Na prisão, José encontrou dois oficiais do faraó que tiveram sonhos misteriosos. Quem eram eles?",
        options: [
          "O copeiro e o padeiro",
          "O general e o sacerdote",
          "O escriba e o cozinheiro",
        ],
        correctIndex: 0,
        explanation:
          "Gênesis 40:1–5 — o copeiro-mor e o padeiro-mor do faraó, presos junto com José, tiveram cada um um sonho na mesma noite.",
      },
      {
        q: "O faraó sonhou com sete vacas gordas sendo devoradas por sete vacas magras. O que José disse que isso representava?",
        options: [
          "Sete guerras seguidas de paz",
          "Sete anos de fartura seguidos por sete anos de fome",
          "Sete novos reis do Egito",
        ],
        correctIndex: 1,
        explanation:
          "Gênesis 41:25–30 — José interpretou o sonho como sete anos de grande fartura no Egito, seguidos por sete anos de fome severa.",
      },
      {
        q: "Durante a fome, os irmãos de José foram ao Egito comprar alimentos. Eles reconheceram José quando ficaram diante dele?",
        options: [
          "Sim, imediatamente",
          "Não, mas José os reconheceu",
          "Apenas Benjamim o reconheceu",
        ],
        correctIndex: 1,
        explanation:
          "Gênesis 42:6–8 — José reconheceu seus irmãos assim que os viu, mas eles não o reconheceram.",
      },
      {
        q: "Os irmãos precisavam voltar ao Egito, mas havia uma condição estabelecida por José. Quem precisava ir com eles?",
        options: ["Jacó", "Benjamim", "Simeão"],
        correctIndex: 1,
        explanation:
          "Gênesis 43:3–5 — José havia exigido que os irmãos só voltassem à sua presença se trouxessem Benjamim com eles.",
      },
      {
        q: "José mandou esconder um objeto na bagagem de Benjamim para testar seus irmãos. Que objeto era?",
        options: ["Um anel de ouro", "Uma taça de prata", "Um pequeno ídolo"],
        correctIndex: 1,
        explanation:
          "Gênesis 44:1–2 — José ordenou que sua taça de prata fosse colocada na saca de Benjamim, como um teste para seus irmãos.",
      },
      {
        q: "Depois de anos separado de sua família, José finalmente revelou sua identidade aos irmãos. Como eles reagiram inicialmente?",
        options: [
          "Ficaram sem conseguir responder",
          "Começaram a comemorar imediatamente",
          "Não acreditaram nele e foram embora",
        ],
        correctIndex: 0,
        explanation:
          "Gênesis 45:1–3 — ao se revelar, José deixou seus irmãos tão perturbados que eles não conseguiram lhe responder.",
      },
      {
        q: "Jacó descobriu que José estava vivo e decidiu partir para o Egito. Antes de continuar a viagem, onde ele ofereceu sacrifícios a Deus?",
        options: ["Berseba", "Betel", "Hebrom"],
        correctIndex: 0,
        explanation:
          "Gênesis 46:1–4 — a caminho do Egito, Jacó parou em Berseba e ali ofereceu sacrifícios ao Deus de seu pai Isaque.",
      },
      {
        q: "José apresentou sua família ao faraó, e eles receberam uma região para viver. Qual era essa região?",
        options: ["Gósen", "Canaã", "Edom"],
        correctIndex: 0,
        explanation:
          "Gênesis 47:5–6 — o faraó concedeu à família de José a melhor parte da terra, a região de Gósen, para que ali habitassem.",
      },
      {
        q: "Quando Jacó foi abençoar os filhos de José, ele cruzou as mãos propositalmente. Quem recebeu a bênção principal, apesar de ser o mais novo?",
        options: ["Manassés", "Efraim", "Benjamim"],
        correctIndex: 1,
        explanation:
          "Gênesis 48:13–20 — Jacó cruzou os braços de propósito para colocar a mão direita sobre Efraim, o mais novo, dando-lhe a bênção maior em vez de a Manassés.",
      },
      {
        q: "Antes de morrer, Jacó reuniu seus filhos e falou sobre o futuro deles. Qual filho foi comparado a um leão?",
        options: ["Judá", "José", "Levi"],
        correctIndex: 0,
        explanation:
          "Gênesis 49:8–9 — Jacó comparou Judá a um leãozinho, descrevendo sua força e liderança entre os irmãos.",
      },
      {
        q: "Depois da morte de Jacó, os irmãos de José ficaram com medo de que ele finalmente se vingasse. Como José reagiu?",
        options: [
          "Expulsou os irmãos do Egito",
          "Mandou prendê-los",
          "Perdoou e tranquilizou seus irmãos",
        ],
        correctIndex: 2,
        explanation:
          "Gênesis 50:15–21 — José tranquilizou seus irmãos, perdoando-os e afirmando que Deus havia transformado o mal em bem.",
      },
    ];
    const pick =
      bank[(((chapter - 1) % bank.length) + bank.length) % bank.length];
    console.log(pick);
    return {
      chapterId: contentId,
      question: pick.q,
      options: pick.options,
      correctIndex: pick.correctIndex,
      explanation: pick.explanation,
    };
  },
};

/* =========================================================================
   READING_PLAN
   The order the app reads chapters in. One chapter per "page" in the
   scroller (the scroller resets and scrolls back to zero between chapters)
   — the storyId just groups references visually, there's no transition
   screen between chapters anymore when storyId stays the same.
   ========================================================================= */
const GENESIS_SUBTITLES = [
  "A criação dos céus e da terra",
  "O jardim do Éden",
  "A queda do homem",
  "Caim e Abel",
  "As gerações de Adão",
  "A corrupção da terra",
  "A instrução para a arca",
  "Noé entra na arca",
  "O dilúvio e a aliança do arco-íris",
  "As famílias dos filhos de Noé",
  "A torre de Babel",
  "O chamado de Abraão",
  "Abraão vai ao Egito",
  "Ló e Abraão se separam",
  "Abraão resgata Ló",
  "A aliança da circuncisão",
  "A promessa de Isaque",
  "Sodoma e Gomorra",
  "Ló foge das cidades",
  "O nascimento de Isaque",
  "Ismael é expulso",
  "O sacrifício de Isaque",
  "A morte de Sara",
  "Isaque recebe Rebeca",
  "A morte de Abraão",
  "Esaú e Jacó nascem",
  "Jacó compra a primogenitura",
  "A bênção de Isaque para Jacó",
  "Jacó foge para Labão",
  "A visão da escada",
  "Jacó serve a Labão por Raquel",
  "Os filhos de Jacó",
  "Jacó foge de Labão",
  "Jacó encontra Esaú",
  "Diné e Siquém",
  "Jacó volta a Betel",
  "A morte de Rebeca e Isaque",
  "Esaú e Jacó se separam",
  "José e os irmãos",
  "José vende aos ismaelitas",
  "José na casa de Potifar",
  "O cárcere e o copeiro",
  "Faraó sonha com sete vacas",
  "José governa o Egito",
  "Os irmãos vão ao Egito",
  "O segundo encontro no Egito",
  "A taça no saco de Benjamim",
  "José se revela aos irmãos",
  "Jacó desce ao Egito",
  "Israel no Egito e a bênção final",
];

const READING_PLAN = Array.from({ length: 50 }, (_, i) => {
  const chapter = i + 1;
  const entry = {
    storyId: "genesis",
    storyTitle: i === 0 ? "Gênesis" : undefined,
    storySubtitle: i === 0 ? "O começo de tudo" : undefined,
    contentId: `GEN.${chapter}`,
    subtitle: GENESIS_SUBTITLES[i] || `Capítulo ${chapter}`,
  };
  if (chapter === 6) {
    entry.funFactAfterVerse = 14;
    entry.funFact = {
      stat: "300 × 50 × 30",
      unit: "côvados — comprimento × largura × altura",
      body: "Gênesis 6:15 descreve a arca com 300 côvados de comprimento. Usando um côvado de cerca de 45,7 cm, isso equivale a mais de um campo de futebol de comprimento e à altura de um prédio de quatro andares.",
      bars: [
        { label: "Arca de Noé — 137 m", target: 100 },
        { label: "Campo de futebol — ~105 m", target: 77 },
      ],
    };
  }
  if (chapter === 22) {
    entry.quiz = {
      question: "Qual lugar Abraão ia oferecer Isaque, segundo a narrativa?",
      options: [
        "Uma montanha em Moriah",
        "O deserto de Berseba",
        "Ao lado dos carvalhos de Manre",
      ],
      correctIndex: 0,
      explanation:
        "Gênesis 22:2 diz que Deus pediu para Abraão ir à terra de Moriah e oferecer Isaque em uma das montanhas que lhe seria mostrada.",
    };
  }
  if (chapter === 50) {
    entry.quiz = {
      question: "Quantos anos viveu José no Egito, conforme o fim de Gênesis?",
      options: ["90 anos", "110 anos", "147 anos"],
      correctIndex: 1,
      explanation:
        "Gênesis 50:26 diz que José morreu com 110 anos de idade, depois de ver os filhos de Efraim até a terceira geração.",
    };
  }
  return entry;
});

/* =========================================================================
   VIDEO ANNOTATIONS (JSON-style config)
   Cada entrada: { afterVerse, src, autoScrollAfterEnded, playsInline,
               onEnterAutoPlay, onEnterScrollTo }

   - afterVerse: versículo que dispara a inserção ("GEN.CAP.VERSO" — ex. "GEN.1.3")
   - src: caminho local, tipicamente ./videos/<arquivo>
   - autoScrollAfterEnded: se true, após o vídeo terminar a página rolagem continua descendo 1 tela
   - onEnterScrollTo: se true, a tela scrolla smooth para o vídeo quando ele entra na viewport
   - playFromStartOnReEnter: se true (padrão), voltar o scroll e revisita o vídeo sempre reinicia do 0
   - playsInline: true (padrão — evita fullscreen em iOS Safari)
   - autoplayMuted: se true, tenta tocar muted com autoplay
   ========================================================================= */
const VIDEO_ANNOTATIONS = [
  {
    afterVerse: "GEN.1.3",
    src: "./videos/genesis1-3.mp4",
    autoScrollAfterEnded: true,
    onEnterScrollTo: true,
    playFromStartOnReEnter: true,
    playsInline: true,
    autoplayMuted: false,
  },
  {
    afterVerse: "GEN.1.12",
    src: "./videos/112.mp4",
    autoScrollAfterEnded: true,
    onEnterScrollTo: true,
    playFromStartOnReEnter: true,
    playsInline: true,
    autoplayMuted: false,
  },
  {
    afterVerse: "GEN.1.25",
    src: "./videos/125.mp4",
    autoScrollAfterEnded: true,
    onEnterScrollTo: true,
    playFromStartOnReEnter: true,
    playsInline: true,
    autoplayMuted: false,
  },
  {
    afterVerse: "GEN.2.10",
    src: "./videos/210.mp4",
    autoScrollAfterEnded: true,
    onEnterScrollTo: true,
    playFromStartOnReEnter: true,
    playsInline: true,
    autoplayMuted: false,
  },
  {
    afterVerse: "GEN.3.1",
    src: "./videos/ElevenLabs_video_gemini-omni-flash_A vibrant red f_2026-08-30T05_02_48.mp4",
    autoScrollAfterEnded: true,
    onEnterScrollTo: true,
    playFromStartOnReEnter: true,
    playsInline: true,
    autoplayMuted: false,
  },
  {
    afterVerse: "GEN.3.10",
    src: "./videos/adameve.mp4",
    autoScrollAfterEnded: true,
    onEnterScrollTo: true,
    playFromStartOnReEnter: true,
    playsInline: true,
    autoplayMuted: false,
  },
  {
    afterVerse: "GEN.3.14",
    src: "./videos/snake.mp4",
    autoScrollAfterEnded: true,
    onEnterScrollTo: true,
    playFromStartOnReEnter: true,
    playsInline: true,
    autoplayMuted: false,
  },
  {
    afterVerse: "GEN.7.11",
    src: "./videos/noahsark.mp4",
    autoScrollAfterEnded: true,
    onEnterScrollTo: true,
    playFromStartOnReEnter: true,
    playsInline: true,
    autoplayMuted: false,
  },
];

function getVideosForChapter(contentId) {
  const prefix = contentId + "."; // GEN.1.3  -> prefix=GEN.1.
  return VIDEO_ANNOTATIONS.filter((a) => a.afterVerse.startsWith(prefix));
}

function findVideosInsertAfterVerseNumber(annotations, afterVerse) {
  return annotations.filter((a) => a.afterVerse === afterVerse);
}

const TRANSITION_ICON = `<svg viewBox="0 0 48 48" fill="none" xmlns="http://www.w3.org/2000/svg">
    <path d="M6 25 Q24 34 42 25 L36 34 Q24 40 12 34 Z" stroke="currentColor" stroke-width="2" stroke-linejoin="round"/>
    <rect x="17" y="13" width="14" height="11" rx="1.5" stroke="currentColor" stroke-width="2"/>
    <line x1="21" y1="13" x2="21" y2="24" stroke="currentColor" stroke-width="1.4"/>
    <line x1="27" y1="13" x2="27" y2="24" stroke="currentColor" stroke-width="1.4"/>
    <path d="M3 29c4 3 8 3 12 0s8-3 12 0 8 3 12 0 8-3 8-3" stroke="currentColor" stroke-width="1.3" stroke-linecap="round"/>
  </svg>`;

/* =========================================================================
   SHARED CHROME (created once): saved counter, toast, focus vignette
   ========================================================================= */
const scroller = document.getElementById("scroller");
const savedSet = new Set();
let hintTaught = false;

const savedCounter = document.createElement("div");
savedCounter.className = "saved-counter show"; // <-- "show" is required
savedCounter.innerHTML = `<span class="save-badgs saved pop" aria-hidden="true"></span>`;
savedCounter.setAttribute("role", "button");
savedCounter.setAttribute("tabindex", "0");
savedCounter.setAttribute("aria-label", "Abrir versículos salvos");
document.body.appendChild(savedCounter);

const toast = document.createElement("div");
toast.className = "toast";
toast.innerHTML = `<span class="tbookmark"></span><span class="ttext"></span>`;
document.body.appendChild(toast);

const vignette = document.createElement("div");
vignette.className = "focus-vignette";
document.body.appendChild(vignette);

const aiSheetBackdrop = document.createElement("div");
aiSheetBackdrop.className = "ai-sheet-backdrop";
aiSheetBackdrop.setAttribute("aria-hidden", "true");
document.body.appendChild(aiSheetBackdrop);

const savedSheetBackdrop = document.createElement("div");
savedSheetBackdrop.className = "saved-sheet-backdrop";
savedSheetBackdrop.setAttribute("aria-hidden", "true");
document.body.appendChild(savedSheetBackdrop);

const aiSheet = document.createElement("section");
aiSheet.className = "ai-sheet";
aiSheet.setAttribute("role", "dialog");
aiSheet.setAttribute("aria-modal", "true");
aiSheet.setAttribute("aria-hidden", "true");
aiSheet.setAttribute("aria-label", "Explicação do versículo");
document.body.appendChild(aiSheet);

const savedSheet = document.createElement("section");
savedSheet.className = "saved-sheet";
savedSheet.setAttribute("role", "dialog");
savedSheet.setAttribute("aria-modal", "true");
savedSheet.setAttribute("aria-hidden", "true");
savedSheet.setAttribute("aria-label", "Versículos salvos");
document.body.appendChild(savedSheet);

let toastTimer = null;
let pendingReaderDeepLink = parseReaderDeepLink();
function showToast(message) {
  clearTimeout(toastTimer);
  toast.querySelector(".ttext").textContent = message;
  toast.classList.add("show");
  toastTimer = setTimeout(() => toast.classList.remove("show"), 2200);
}

function updateSavedCounter() {
  savedSheetState.listCache = null;
  savedCounter.classList.toggle("show", savedSet.size > 0);
  savedCounter.setAttribute(
    "aria-label",
    savedSet.size > 0 ? "Abrir versículos salvos" : "Nenhum versículo salvo",
  );
  void refreshSavedSheetIfOpen();
}

function hideAllHints() {
  hintTaught = true;
  document
    .querySelectorAll(".swipe-hint")
    .forEach((h) => (h.style.opacity = "0"));
}

function preview(text) {
  return text.length > 46 ? text.slice(0, 46).trim() + "…" : text;
}

const AI_QUESTION_ICON = `<svg xmlns="http://www.w3.org/2000/svg" width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" class="lucide lucide-message-circle-question-mark-icon lucide-message-circle-question-mark"><path d="M2.992 16.342a2 2 0 0 1 .094 1.167l-1.065 3.29a1 1 0 0 0 1.236 1.168l3.413-.998a2 2 0 0 1 1.099.092 10 10 0 1 0-4.777-4.719"/><path d="M9.09 9a3 3 0 0 1 5.83 1c0 2-3 3-3 3"/><path d="M12 17h.01"/></svg>`;
const AI_REPLY_ICON = `<svg xmlns="http://www.w3.org/2000/svg" width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" class="lucide lucide-message-circle-reply-icon lucide-message-circle-reply"><path d="M2.992 16.342a2 2 0 0 1 .094 1.167l-1.065 3.29a1 1 0 0 0 1.236 1.168l3.413-.998a2 2 0 0 1 1.099.092 10 10 0 1 0-4.777-4.719"/><path d="m10 15-3-3 3-3"/><path d="M7 12h8a2 2 0 0 1 2 2v1"/></svg>`;
const AI_REWORD_CACHE = new Map();
const AI_SHEET_PEEK = 272;
const SAVED_SHEET_PEEK = 332;
const aiSheetState = {
  activeButton: null,
  activeKey: "",
  requestId: 0,
  open: false,
  dragging: false,
  collapsedOffset: 0,
  currentOffset: 0,
  startY: 0,
  startOffset: 0,
};
const savedSheetState = {
  requestId: 0,
  open: false,
  dragging: false,
  collapsedOffset: 0,
  currentOffset: 0,
  startY: 0,
  startOffset: 0,
  listCache: null,
  chapterCache: new Map(),
};

aiSheet.innerHTML = `
  <div class="ai-sheet-dragger" aria-hidden="true">
    <span class="ai-sheet-grip"></span>
  </div>
  <div class="ai-sheet-head">
    <div class="ai-sheet-kicker">Português simples</div>
    <button class="ai-sheet-close" type="button" aria-label="Fechar explicação" title="Fechar explicação">${AI_REPLY_ICON}</button>
  </div>
  <div class="ai-sheet-body">
    <p class="ai-sheet-ref"></p>
    <p class="ai-sheet-original"></p>
    <div class="ai-sheet-copy is-loading">Preparando uma explicação mais clara…</div>
  </div>
`;

savedSheet.innerHTML = `
  <div class="saved-sheet-dragger" aria-hidden="true">
    <span class="saved-sheet-grip"></span>
  </div>
  <div class="saved-sheet-head">
    <div class="saved-sheet-title-wrap">
      <p class="saved-sheet-kicker">Seus salvos</p>
      <h2 class="saved-sheet-title">Versículos salvos</h2>
    </div>
    <button class="saved-sheet-close" type="button" aria-label="Fechar salvos" title="Fechar salvos">${AI_REPLY_ICON}</button>
  </div>
  <div class="saved-sheet-body">
    <div class="saved-sheet-list is-loading">Carregando seus versículos salvos…</div>
  </div>
`;

function prefersReducedMotion() {
  return (
    typeof window !== "undefined" &&
    window.matchMedia &&
    window.matchMedia("(prefers-reduced-motion: reduce)").matches
  );
}

function makeAiCacheKey(chapterData, verse) {
  return `${chapterData.reference.human}::${verse.number}::${verse.text}`;
}

function buildChapterContext(chapterData) {
  return chapterData.verses
    .map((v) => `${v.number}. ${String(v.text || "").trim()}`)
    .join("\n");
}

function setAiButtonState(btn, active, loading) {
  if (!btn) return;
  btn.classList.toggle("is-active", !!active);
  btn.classList.toggle("is-loading", !!loading);
  btn.disabled = !!loading;
  btn.innerHTML = active ? AI_REPLY_ICON : AI_QUESTION_ICON;
  btn.setAttribute(
    "aria-label",
    active ? "Fechar explicação" : "Abrir explicação em português simples",
  );
  btn.setAttribute(
    "title",
    active ? "Fechar explicação" : "Abrir explicação em português simples",
  );
}

async function fetchSimplifiedVerse(chapterData, verse) {
  const cacheKey = makeAiCacheKey(chapterData, verse);
  if (AI_REWORD_CACHE.has(cacheKey)) return AI_REWORD_CACHE.get(cacheKey);

  const chapterContext = buildChapterContext(chapterData);
  const res = await fetch("https://api.openai.com/v1/chat/completions", {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      Authorization: `Bearer ${CHAT_GPT_TOKEN}`,
    },
    body: JSON.stringify({
      model: "gpt-4o",
      temperature: 0.3,
      max_tokens: 1000,
      response_format: { type: "json_object" },
      messages: [
        {
          role: "system",
          content: `Você é um assistente teológico que explica versículos bíblicos dentro de um aplicativo. Você deve ler o versículo dentro do contexto do capítulo e do livro inteiro.

GUARDA-ROUPAS BÍBLICOS OBRIGATÓRIOS:
1. A Bíblia é a fonte primária. Não apresente tradição, especulação ou comentário cultural como texto explícito.
2. Nunca invente versículos ou referências. Se houver incerteza, declare-a.
3. Distinga claramente texto bíblico, interpretação e aplicação.
4. Evite prova-textual (proof-texting). Interprete considerando contexto imediato, histórico, cultural e gênero literário.
5. Reconheça a diversidade teológica quando houver divergência entre tradições cristãs fiéis.
6. Nunca afirme falar por Deus, alegue nova revelação ou declare certeza sobre motivos ocultos de Deus.
7. Nunca atribua sofrimento a punição divina sem base bíblica explícita. A orientação bíblica não substitui aconselhamento profissional.

FORMATO DE SAÍDA:
Você deve retornar ESTRITAMENTE um objeto JSON contendo as seguintes chaves, mapeadas para a interface do aplicativo:
{
  "theme_title": "Um título curto para o tema central (ex: 'A videira').",
  "theme_intro": "Um parágrafo curto explicando a centralidade literária ou simbólica do tema no texto.",
  "historical": "Contexto histórico relevante para entender o versículo (momento histórico, autor, público original). Se não houver, retorne '-'.",
  "cultural": "Contexto cultural ou costumes da época relevantes ao versículo. Se não houver, retorne '-'.",
  "people": "Quem está envolvido na narrativa do versículo (quem fala, para quem, quem está presente). Se não houver, retorne '-'.",
  "explanation": "A explicação detalhada do versículo em si, considerando todo o contexto acima.",
  "disclaimer": "- Essa explicação foi gerada por inteligência artificial e pode apresentar erros. Recomendamos a consulta da palavra original."
}
Responda em português, de forma clara, direta e acessível a um leitor leigo, sem jargões desnecessários.`,
        },
        {
          role: "user",
          content: `Referência: ${chapterData.reference.human}\n\nContexto do Capítulo Inteiro:\n${chapterContext}\n\nVersículo Alvo: ${verse.number}\nTexto do Versículo: ${verse.text}\n\nGere a explicação em JSON estruturado.`,
        },
      ],
    }),
  });
  if (!res.ok) {
    const errorText = await res.json().catch(() => "");
    throw new Error(errorText || `OpenAI ${res.status}`);
  }
  const data = await res.json();
  const content = String(data?.choices?.[0]?.message?.content || "")
    .replace(/\s+/g, " ")
    .trim();
  if (!content) throw new Error("A IA não retornou texto.");
  AI_REWORD_CACHE.set(cacheKey, content);
  return content;
}

function getAiSheetClosedOffset() {
  return aiSheet.offsetHeight + 28;
}

function getAiSheetCollapsedOffset() {
  const height = aiSheet.offsetHeight || 0;
  const visible = Math.min(
    Math.max(window.innerHeight * 0.34, 220),
    AI_SHEET_PEEK,
  );
  return Math.max(height - visible, 0);
}

function applyAiSheetOffset(offset, immediate) {
  aiSheetState.currentOffset = Math.max(0, offset);
  aiSheet.style.transition = immediate || aiSheetState.dragging ? "none" : "";
  aiSheet.style.transform = `translateY(${aiSheetState.currentOffset}px)`;
}

function clearActiveAiButton() {
  if (!aiSheetState.activeButton) return;
  setAiButtonState(aiSheetState.activeButton, false, false);
  aiSheetState.activeButton = null;
  aiSheetState.activeKey = "";
}

function normalizeAiSheetPayload(copy) {
  if (copy && typeof copy === "object") return copy;
  const raw = String(copy || "").trim();
  if (!raw) throw new Error("A IA não retornou conteúdo.");
  return JSON.parse(raw);
}

function appendAiSheetSection(container, label, text, featured) {
  const content = String(text || "").trim();
  if (!content || content === "-") return;
  const section = document.createElement("section");
  section.className = featured
    ? "ai-sheet-section ai-sheet-section-featured"
    : "ai-sheet-section";

  const title = document.createElement("h3");
  title.className = "ai-sheet-section-label";
  title.textContent = label;

  const body = document.createElement("p");
  body.className = featured
    ? "ai-sheet-section-copy ai-sheet-section-copy-featured"
    : "ai-sheet-section-copy";
  body.textContent = content;

  section.appendChild(title);
  section.appendChild(body);
  container.appendChild(section);
}

function fillAiSheetCopy(copy, isError) {
  const copyEl = aiSheet.querySelector(".ai-sheet-copy");
  copyEl.replaceChildren();
  copyEl.className = isError ? "ai-sheet-copy is-error" : "ai-sheet-copy";

  if (isError) {
    copyEl.textContent = String(copy || "");
    return;
  }

  let payload = null;
  try {
    payload = normalizeAiSheetPayload(copy);
  } catch (_) {
    copyEl.textContent = String(copy || "");
    return;
  }

  const title = document.createElement("h2");
  title.className = "ai-sheet-theme-title";
  title.textContent = String(payload.theme_title || "Tema central").trim();
  copyEl.appendChild(title);

  appendAiSheetSection(copyEl, "Introdução", payload.theme_intro, true);
  appendAiSheetSection(copyEl, "Explicação", payload.explanation, true);
  appendAiSheetSection(copyEl, "Contexto histórico", payload.historical);
  appendAiSheetSection(copyEl, "Contexto cultural", payload.cultural);
  appendAiSheetSection(copyEl, "Pessoas", payload.people);
  appendAiSheetSection(copyEl, "Nota", payload.disclaimer);
}

function closeAiSheet() {
  aiSheetState.requestId += 1;
  aiSheetState.open = false;
  aiSheetState.dragging = false;
  aiSheet.classList.remove("show", "is-dragging");
  aiSheetBackdrop.classList.remove("show");
  document.body.classList.remove("ai-sheet-open");
  aiSheet.setAttribute("aria-hidden", "true");
  applyAiSheetOffset(getAiSheetClosedOffset(), true);
  clearActiveAiButton();
}

function openAiSheetShell(btn, ref, original, key) {
  if (aiSheetState.activeButton && aiSheetState.activeButton !== btn) {
    setAiButtonState(aiSheetState.activeButton, false, false);
  }
  aiSheetState.activeButton = btn;
  aiSheetState.activeKey = key;
  aiSheetState.open = true;
  aiSheetState.dragging = false;
  aiSheet.classList.add("show");
  aiSheetBackdrop.classList.add("show");
  document.body.classList.add("ai-sheet-open");
  aiSheet.setAttribute("aria-hidden", "false");
  aiSheet.querySelector(".ai-sheet-ref").textContent = ref;
  aiSheet.querySelector(".ai-sheet-original").textContent = original;
  fillAiSheetCopy("Preparando uma explicação mais clara…", false);
  aiSheet.querySelector(".ai-sheet-copy").classList.add("is-loading");
  setAiButtonState(btn, true, true);
  requestAnimationFrame(() => {
    aiSheetState.collapsedOffset = getAiSheetCollapsedOffset();
    applyAiSheetOffset(aiSheetState.collapsedOffset, prefersReducedMotion());
  });
}

function snapAiSheet(offset) {
  const collapsedOffset = getAiSheetCollapsedOffset();
  aiSheetState.collapsedOffset = collapsedOffset;
  if (offset > collapsedOffset + 96) {
    closeAiSheet();
    return;
  }
  const nextOffset =
    Math.abs(offset) < Math.abs(offset - collapsedOffset) ? 0 : collapsedOffset;
  applyAiSheetOffset(nextOffset, prefersReducedMotion());
}

function beginAiSheetDrag(e) {
  if (!aiSheetState.open) return;
  aiSheetState.dragging = true;
  aiSheetState.startY = e.clientY;
  aiSheetState.startOffset = aiSheetState.currentOffset;
  aiSheet.classList.add("is-dragging");
  aiSheet.setPointerCapture(e.pointerId);
}

function moveAiSheetDrag(e) {
  if (!aiSheetState.dragging) return;
  const nextOffset = Math.max(
    0,
    Math.min(
      getAiSheetClosedOffset(),
      aiSheetState.startOffset + (e.clientY - aiSheetState.startY),
    ),
  );
  applyAiSheetOffset(nextOffset, true);
}

function endAiSheetDrag(e) {
  if (!aiSheetState.dragging) return;
  aiSheetState.dragging = false;
  aiSheet.classList.remove("is-dragging");
  if (aiSheet.hasPointerCapture(e.pointerId)) {
    aiSheet.releasePointerCapture(e.pointerId);
  }
  snapAiSheet(aiSheetState.currentOffset);
}

function makeAiRewordable(sectionEl, chapterData, verse) {
  const btn = sectionEl.querySelector(".ai-btn");
  const key = makeAiCacheKey(chapterData, verse);
  const ref = `${chapterData.reference.human} · ${verse.number}`;
  const originalText = String(verse.text || "");

  setAiButtonState(btn, false, false);

  btn.addEventListener("click", async () => {
    if (aiSheetState.open && aiSheetState.activeKey === key) {
      closeAiSheet();
      return;
    }

    const requestId = aiSheetState.requestId + 1;
    aiSheetState.requestId = requestId;
    openAiSheetShell(btn, ref, originalText, key);

    try {
      const simplifiedText = await fetchSimplifiedVerse(chapterData, verse);
      if (
        aiSheetState.requestId !== requestId ||
        aiSheetState.activeKey !== key
      ) {
        return;
      }
      fillAiSheetCopy(simplifiedText, false);
      setAiButtonState(btn, true, false);
    } catch (e) {
      if (
        aiSheetState.requestId !== requestId ||
        aiSheetState.activeKey !== key
      ) {
        return;
      }
      fillAiSheetCopy(
        `Não foi possível simplificar agora: ${
          e && e.message ? e.message : "erro inesperado"
        }`,
        true,
      );
      setAiButtonState(btn, true, false);
    }
  });
}

aiSheetBackdrop.addEventListener("click", closeAiSheet);
aiSheet
  .querySelector(".ai-sheet-close")
  .addEventListener("click", closeAiSheet);
aiSheet
  .querySelector(".ai-sheet-dragger")
  .addEventListener("pointerdown", beginAiSheetDrag);
aiSheet.addEventListener("pointermove", moveAiSheetDrag);
aiSheet.addEventListener("pointerup", endAiSheetDrag);
aiSheet.addEventListener("pointercancel", endAiSheetDrag);
window.addEventListener("keydown", (e) => {
  if (e.key === "Escape" && aiSheetState.open) closeAiSheet();
});
window.addEventListener("resize", () => {
  if (!aiSheetState.open || aiSheetState.dragging) return;
  const collapsedOffset = getAiSheetCollapsedOffset();
  aiSheetState.collapsedOffset = collapsedOffset;
  const nextOffset =
    aiSheetState.currentOffset <= collapsedOffset / 2 ? 0 : collapsedOffset;
  applyAiSheetOffset(nextOffset, true);
});

function parseSavedPassageId(passageId) {
  const match = /^GEN\.(\d+)\.(\d+)$/i.exec(String(passageId || ""));
  if (!match) return null;
  return {
    chapter: parseInt(match[1], 10),
    verse: parseInt(match[2], 10),
    passageId,
  };
}

function getSavedSheetListEl() {
  return savedSheet.querySelector(".saved-sheet-list");
}

function setSavedSheetStateText(text, stateClass) {
  const listEl = getSavedSheetListEl();
  listEl.replaceChildren();
  listEl.className = stateClass
    ? `saved-sheet-list ${stateClass}`
    : "saved-sheet-list";
  listEl.textContent = text;
}

async function getSavedSheetChapter(chapter) {
  if (savedSheetState.chapterCache.has(chapter)) {
    return savedSheetState.chapterCache.get(chapter);
  }
  const promise = BibleSource.getChapter(`GEN.${chapter}`);
  savedSheetState.chapterCache.set(chapter, promise);
  return promise;
}

async function loadSavedSheetItems() {
  if (savedSheetState.listCache) return savedSheetState.listCache;
  const parsed = HighlightsMirror.read()
    .highlights.map((item) => parseSavedPassageId(item.passage_id))
    .filter(Boolean);
  if (!parsed.length) {
    savedSheetState.listCache = [];
    return [];
  }

  const chapters = [...new Set(parsed.map((item) => item.chapter))];
  const chapterVerseMap = new Map();
  await Promise.all(
    chapters.map(async (chapter) => {
      try {
        const chapterData = await getSavedSheetChapter(chapter);
        chapterVerseMap.set(chapter, chapterData.verses || []);
      } catch (_) {
        chapterVerseMap.set(chapter, []);
      }
    }),
  );

  const items = parsed
    .map((item) => {
      const verses = chapterVerseMap.get(item.chapter) || [];
      const found = verses.find((verse) => verse.number === item.verse);
      return {
        ...item,
        ref: `Gênesis ${item.chapter}:${item.verse}`,
        text: found ? found.text : "Abrir versículo no leitor",
      };
    })
    .sort((a, b) => a.chapter - b.chapter || a.verse - b.verse);

  savedSheetState.listCache = items;
  return items;
}

async function refreshSavedSheetIfOpen() {
  if (!savedSheetState.open) return;
  const requestId = savedSheetState.requestId + 1;
  savedSheetState.requestId = requestId;
  try {
    const items = await loadSavedSheetItems();
    if (!savedSheetState.open || savedSheetState.requestId !== requestId)
      return;
    renderSavedSheetList(items);
    requestAnimationFrame(() => {
      if (!savedSheetState.open || savedSheetState.dragging) return;
      savedSheetState.collapsedOffset = getSavedSheetCollapsedOffset();
      const nextOffset =
        savedSheetState.currentOffset <= savedSheetState.collapsedOffset / 2
          ? 0
          : savedSheetState.collapsedOffset;
      applySavedSheetOffset(nextOffset, true);
    });
  } catch (_) {
    if (!savedSheetState.open || savedSheetState.requestId !== requestId)
      return;
    setSavedSheetStateText(
      "Não foi possível carregar seus versículos salvos agora.",
      "is-empty",
    );
  }
}

function openSavedPassage(item) {
  pendingReaderDeepLink = {
    chapterIndex: item.chapter - 1,
    verseNumber: item.verse,
    passageId: item.passageId,
  };
  closeSavedSheet();
  jumpToGenesisChapter(item.chapter);
}

function renderSavedSheetList(items) {
  const listEl = getSavedSheetListEl();
  listEl.replaceChildren();
  listEl.className = "saved-sheet-list";

  if (!items.length) {
    listEl.classList.add("is-empty");
    listEl.textContent = "Salve algum versículo no leitor e ele aparece aqui.";
    return;
  }

  const grouped = new Map();
  items.forEach((item) => {
    const arr = grouped.get(item.chapter) || [];
    arr.push(item);
    grouped.set(item.chapter, arr);
  });

  Array.from(grouped.entries()).forEach(([chapter, chapterItems]) => {
    const group = document.createElement("section");
    group.className = "saved-sheet-group";

    const heading = document.createElement("h3");
    heading.className = "saved-sheet-group-title";
    heading.textContent = `Gênesis ${chapter}`;
    group.appendChild(heading);

    const stack = document.createElement("div");
    stack.className = "saved-sheet-group-list";
    chapterItems.forEach((item) => {
      const btn = document.createElement("button");
      btn.className = "saved-sheet-item";
      btn.type = "button";
      btn.addEventListener("click", () => openSavedPassage(item));

      const ref = document.createElement("span");
      ref.className = "saved-sheet-item-ref";
      ref.textContent = item.ref;

      const text = document.createElement("span");
      text.className = "saved-sheet-item-text";
      text.textContent = item.text;

      btn.appendChild(ref);
      btn.appendChild(text);
      stack.appendChild(btn);
    });

    group.appendChild(stack);
    listEl.appendChild(group);
  });
}

function getSavedSheetClosedOffset() {
  return savedSheet.offsetHeight + 28;
}

function getSavedSheetCollapsedOffset() {
  const height = savedSheet.offsetHeight || 0;
  const visible = Math.min(
    Math.max(window.innerHeight * 0.42, 260),
    SAVED_SHEET_PEEK,
  );
  return Math.max(height - visible, 0);
}

function applySavedSheetOffset(offset, immediate) {
  savedSheetState.currentOffset = Math.max(0, offset);
  savedSheet.style.transition =
    immediate || savedSheetState.dragging ? "none" : "";
  savedSheet.style.transform = `translateY(${savedSheetState.currentOffset}px)`;
}

function closeSavedSheet() {
  savedSheetState.requestId += 1;
  savedSheetState.open = false;
  savedSheetState.dragging = false;
  savedSheet.classList.remove("show", "is-dragging");
  savedSheetBackdrop.classList.remove("show");
  savedSheet.setAttribute("aria-hidden", "true");
  applySavedSheetOffset(getSavedSheetClosedOffset(), true);
}

async function openSavedSheet() {
  if (savedSheetState.open) {
    closeSavedSheet();
    return;
  }
  if (aiSheetState.open) closeAiSheet();

  const requestId = savedSheetState.requestId + 1;
  savedSheetState.requestId = requestId;
  savedSheetState.open = true;
  savedSheetState.dragging = false;
  savedSheet.classList.add("show");
  savedSheetBackdrop.classList.add("show");
  savedSheet.setAttribute("aria-hidden", "false");
  setSavedSheetStateText("Carregando seus versículos salvos…", "is-loading");
  requestAnimationFrame(() => {
    savedSheetState.collapsedOffset = getSavedSheetCollapsedOffset();
    applySavedSheetOffset(
      savedSheetState.collapsedOffset,
      prefersReducedMotion(),
    );
  });

  try {
    const items = await loadSavedSheetItems();
    if (savedSheetState.requestId !== requestId) return;
    renderSavedSheetList(items);
    requestAnimationFrame(() => {
      if (!savedSheetState.open || savedSheetState.dragging) return;
      savedSheetState.collapsedOffset = getSavedSheetCollapsedOffset();
      applySavedSheetOffset(savedSheetState.collapsedOffset, true);
    });
  } catch (_) {
    if (savedSheetState.requestId !== requestId) return;
    setSavedSheetStateText(
      "Não foi possível carregar seus versículos salvos agora.",
      "is-empty",
    );
    requestAnimationFrame(() => {
      if (!savedSheetState.open || savedSheetState.dragging) return;
      savedSheetState.collapsedOffset = getSavedSheetCollapsedOffset();
      applySavedSheetOffset(savedSheetState.collapsedOffset, true);
    });
  }
}

function snapSavedSheet(offset) {
  const collapsedOffset = getSavedSheetCollapsedOffset();
  savedSheetState.collapsedOffset = collapsedOffset;
  if (offset > collapsedOffset + 96) {
    closeSavedSheet();
    return;
  }
  const nextOffset =
    Math.abs(offset) < Math.abs(offset - collapsedOffset) ? 0 : collapsedOffset;
  applySavedSheetOffset(nextOffset, prefersReducedMotion());
}

function beginSavedSheetDrag(e) {
  if (!savedSheetState.open) return;
  savedSheetState.dragging = true;
  savedSheetState.startY = e.clientY;
  savedSheetState.startOffset = savedSheetState.currentOffset;
  savedSheet.classList.add("is-dragging");
  savedSheet.setPointerCapture(e.pointerId);
}

function moveSavedSheetDrag(e) {
  if (!savedSheetState.dragging) return;
  const nextOffset = Math.max(
    0,
    Math.min(
      getSavedSheetClosedOffset(),
      savedSheetState.startOffset + (e.clientY - savedSheetState.startY),
    ),
  );
  applySavedSheetOffset(nextOffset, true);
}

function endSavedSheetDrag(e) {
  if (!savedSheetState.dragging) return;
  savedSheetState.dragging = false;
  savedSheet.classList.remove("is-dragging");
  if (savedSheet.hasPointerCapture(e.pointerId)) {
    savedSheet.releasePointerCapture(e.pointerId);
  }
  snapSavedSheet(savedSheetState.currentOffset);
}

savedCounter.addEventListener("click", openSavedSheet);
savedCounter.addEventListener("keydown", (e) => {
  if (e.key !== "Enter" && e.key !== " ") return;
  e.preventDefault();
  openSavedSheet();
});
savedSheetBackdrop.addEventListener("click", closeSavedSheet);
savedSheet
  .querySelector(".saved-sheet-close")
  .addEventListener("click", closeSavedSheet);
savedSheet
  .querySelector(".saved-sheet-dragger")
  .addEventListener("pointerdown", beginSavedSheetDrag);
savedSheet.addEventListener("pointermove", moveSavedSheetDrag);
savedSheet.addEventListener("pointerup", endSavedSheetDrag);
savedSheet.addEventListener("pointercancel", endSavedSheetDrag);
window.addEventListener("keydown", (e) => {
  if (e.key === "Escape" && savedSheetState.open) closeSavedSheet();
});
window.addEventListener("resize", () => {
  if (!savedSheetState.open || savedSheetState.dragging) return;
  const collapsedOffset = getSavedSheetCollapsedOffset();
  savedSheetState.collapsedOffset = collapsedOffset;
  const nextOffset =
    savedSheetState.currentOffset <= collapsedOffset / 2 ? 0 : collapsedOffset;
  applySavedSheetOffset(nextOffset, true);
});

/* =========================================================================
   DOUBLE-TAP-TO-SAVE — sincronizado com a API de highlights YouVersion.
   (documentação: https://developers.youversion.com/api/highlights)

   Fluxo de cada save/unsave:
   1. toggle imediato de UI (savedSet + badge + toast) — resposta instantânea
   2. mirror localStorage é atualizado (estado autoritativo local)
   3. se CONFIG.YOUVERSION_BEARER_TOKEN estiver preenchido e online:
        save → POST /v1/highlights
        unsave → DELETE /v1/highlights/{passage_id}
   4. se o passo 3 falhar, toast informa, mas o salvamento local permanece
      e será sincronizado novamente quando o usuário salvar novamente
      (ou quando houver sincronismo futuro).
   ========================================================================= */
function triggerSave(key, text, badge, inner) {
  const wasSaved = savedSet.has(key);
  // 1) toggle UI + state imediato
  if (wasSaved) {
    savedSet.delete(key);
    badge.classList.remove("saved");
    showToast(`Removido "${preview(text)}" dos salvos`);
    HighlightsSource.clear(key).then((r) => {
      if (
        !r.synced &&
        r.reason &&
        r.reason !== "no_bearer" &&
        r.reason !== "offline"
      ) {
        showToast(`Não foi possível sincronizar a remoção: ${r.reason}`);
      }
    });
  } else {
    savedSet.add(key);
    badge.classList.add("saved");
    badge.classList.remove("pop");
    void badge.offsetWidth;
    badge.classList.add("pop");
    showToast(`Salvo "${preview(text)}"`);
    HighlightsSource.save(key).then((r) => {
      if (
        !r.synced &&
        r.reason &&
        r.reason !== "no_bearer" &&
        r.reason !== "offline"
      ) {
        showToast(`Não foi possível salvar no YouVersion: ${r.reason}`);
      }
    });
  }
  updateSavedCounter();
  inner.style.transition =
    "transform 0.28s cubic-bezier(.25,.8,.3,1.25), opacity 0.2s ease";
  inner.style.transform = "scale(0.985)";
  inner.style.opacity = "0.92";
  requestAnimationFrame(() => {
    inner.style.transform = "scale(1)";
    inner.style.opacity = "1";
  });
  setTimeout(() => {
    inner.style.transition = "";
  }, 300);
}

function makeDoubleTappable(sectionEl, key, text) {
  const inner = sectionEl.querySelector(".verse-inner");
  const badge = sectionEl.querySelector(".save-badge");
  const DOUBLE_TAP_MS = 320;
  const MOVE_TOLERANCE = 18;
  let lastTapAt = 0;
  let lastTapX = 0;
  let lastTapY = 0;
  let pointerDownX = 0;
  let pointerDownY = 0;

  function pulse() {
    inner.style.transition = "transform 0.16s ease, opacity 0.16s ease";
    inner.style.transform = "scale(0.99)";
    inner.style.opacity = "0.96";
    setTimeout(() => {
      inner.style.transform = "scale(1)";
      inner.style.opacity = "1";
    }, 16);
    setTimeout(() => {
      inner.style.transition = "";
    }, 180);
  }

  sectionEl.addEventListener("pointerdown", (e) => {
    if (e.pointerType === "mouse" && e.button !== 0) return;
    if (e.target && e.target.closest && e.target.closest(".ai-btn")) return;
    pointerDownX = e.clientX;
    pointerDownY = e.clientY;
  });

  sectionEl.addEventListener("pointerup", (e) => {
    if (e.pointerType === "mouse" && e.button !== 0) return;
    if (e.target && e.target.closest && e.target.closest(".ai-btn")) return;
    const dx = e.clientX - pointerDownX;
    const dy = e.clientY - pointerDownY;
    if (Math.abs(dx) > MOVE_TOLERANCE || Math.abs(dy) > MOVE_TOLERANCE) return;

    hideAllHints();
    const now = Date.now();
    const nearLastTap =
      Math.abs(e.clientX - lastTapX) <= MOVE_TOLERANCE &&
      Math.abs(e.clientY - lastTapY) <= MOVE_TOLERANCE;

    if (now - lastTapAt <= DOUBLE_TAP_MS && nearLastTap) {
      e.preventDefault();
      lastTapAt = 0;
      triggerSave(key, text, badge, inner);
      return;
    }

    lastTapAt = now;
    lastTapX = e.clientX;
    lastTapY = e.clientY;
    pulse();
  });

  sectionEl.addEventListener("pointercancel", () => {
    lastTapAt = 0;
  });

  sectionEl.addEventListener("dblclick", (e) => {
    e.preventDefault();
  });
}

/* =========================================================================
   SECTION BUILDERS (pure render functions — no data fetching in here)
   ========================================================================= */
function buildTransitionSection(entry) {
  const sec = document.createElement("div");
  sec.className = "section transition-section";
  sec.setAttribute("data-ref", `Próxima: ${entry.storyTitle}`);
  sec.innerHTML = `
      <p class="eyebrow">Próxima história</p>
      <div class="transition-icon">${TRANSITION_ICON}</div>
      <p class="transition-title">Agora: ${entry.storyTitle}</p>
      <p class="transition-sub">${entry.storySubtitle}</p>
      <p class="transition-cue">Continue rolando <span class="arrow">↓</span></p>
    `;
  return sec;
}

function buildDividerSection(chapterData, entry) {
  const sec = document.createElement("div");
  sec.className = "section divider";
  sec.setAttribute("data-ref", chapterData.reference.human);
  sec.innerHTML = `
      <div class="divider-inner">
        <div style="display: flex;">
        <p class="dropcap">${chapterData.reference.human.charAt(0)}</p>
        <p class="divider-title">${chapterData.reference.human.slice(1)}</p>
        </div>
        <div class="divider-rule"></div>
        <p class="divider-sub">${entry.subtitle || ""}</p>
      </div>
    `;
  return sec;
}

function buildVerseSection(chapterData, verse, isFirstEver, yvContentId) {
  const sec = document.createElement("div");
  sec.className = "section swipeable";
  const humanRef = `${chapterData.reference.human} · ${verse.number}`;
  const yvPassageId = yvContentId ? `${yvContentId}.${verse.number}` : null; // ex. GEN.1.3
  const key = yvPassageId || humanRef;
  sec.setAttribute("data-ref", humanRef);
  sec.setAttribute("data-yv-passage", yvPassageId || "");
  const isSaved = savedSet.has(key);
  sec.innerHTML = `
      <div class="verse-inner">
        <p class="verse-num">${chapterData.reference.human} · ${verse.number}</p>
        <p class="verse-text">${verse.text}</p>
        <button class="ai-btn" type="button" aria-label="Abrir explicação em português simples" title="Abrir explicação em português simples">${AI_QUESTION_ICON}</button>
        ${isFirstEver ? '<p class="swipe-hint"><span class="harrow">••</span> Toque duas vezes para salvar</p>' : ""}
      </div>
      <span class="save-badge ${isSaved ? "saved" : ""}" aria-hidden="true"></span>
    `;
  if (isSaved) {
    const badge = sec.querySelector(".save-badge");
    badge.style.opacity = "1";
    badge.style.transform = "scale(1)";
  }
  makeDoubleTappable(sec, key, verse.text);
  makeAiRewordable(sec, chapterData, verse);
  return sec;
}

function buildFactSection(fact) {
  const sec = document.createElement("div");
  sec.className = "section fact-section";
  sec.setAttribute("data-ref", "Você sabia?");
  sec.innerHTML = `
      <p class="eyebrow">Você sabia?</p>
      <p class="fact-stat">${fact.stat}</p>
      <p class="fact-unit">${fact.unit}</p>
      <p class="fact-body">${fact.body}</p>
      <div class="fact-bars">
        ${fact.bars
          .map(
            (b) => `
          <div class="fact-bar-row">
            <span class="fact-bar-label">${b.label}</span>
            <div class="fact-bar-track"><div class="fact-bar-fill" data-target="${b.target}"></div></div>
          </div>
        `,
          )
          .join("")}
      </div>
    `;
  return sec;
}

function buildQuizSection(quiz, onContinue) {
  const sec = document.createElement("div");
  sec.className = "section";
  sec.setAttribute("data-ref", "Pergunta");
  sec.innerHTML = `
      <p class="eyebrow">Compreensão</p>
      <p class="quiz-q">${quiz?.question}</p>
      <div class="options"></div>
      <p class="feedback"></p>
      <button class="continue-btn" type="button">Continuar <span>↓</span></button>
    `;
  const optionsWrap = sec.querySelector(".options");
  const fb = sec.querySelector(".feedback");
  const continueBtn = sec.querySelector(".continue-btn");

  quiz.options.forEach((opt, i) => {
    const btn = document.createElement("button");
    btn.className = "opt";
    btn.type = "button";
    btn.textContent = opt;
    btn.addEventListener("click", () => {
      optionsWrap.querySelectorAll(".opt").forEach((b) => (b.disabled = true));
      if (i === quiz.correctIndex) {
        btn.classList.add("correct");
      } else {
        btn.classList.add("incorrect");
        optionsWrap.children[quiz.correctIndex].classList.add("correct");
      }
      fb.innerHTML =
        (i === quiz.correctIndex
          ? "<strong>Correto.</strong> "
          : "<strong>Quase.</strong> ") + quiz.explanation;
      fb.classList.add("show");
      continueBtn.classList.add("show");
    });
    optionsWrap.appendChild(btn);
  });

  continueBtn.addEventListener("click", onContinue);
  return sec;
}

function buildReflectSection(onDone) {
  const sec = document.createElement("div");
  sec.className = "section";
  sec.setAttribute("data-ref", "Reflexão");
  sec.innerHTML = `
      <p class="eyebrow">Reflexão</p>
      <p class="reflect-prompt">Alguma coisa dessa leitura vale a pena anotar?</p>
      <textarea placeholder="Escreva uma breve reflexão…"></textarea>
      <div class="reflect-actions">
        <button class="btn-primary" type="button">Publicar reflexão</button>
        <button class="btn-text" type="button">Pular por enquanto</button>
      </div>
    `;
  const textarea = sec.querySelector("textarea");
  sec
    .querySelector(".btn-primary")
    .addEventListener("click", () => onDone(textarea.value.trim()));
  sec.querySelector(".btn-text").addEventListener("click", () => onDone(null));
  return sec;
}

function buildCommentsSection(commentsArray) {
  const sec = document.createElement("div");
  sec.className = "section";
  sec.setAttribute("data-ref", "Comentários");
  sec.innerHTML = `
      <p class="eyebrow">De outros leitores</p>
      <div class="comments-wrap"><div class="comments-list"></div></div>
    `;
  const list = sec.querySelector(".comments-list");
  function render() {
    list.innerHTML = commentsArray
      .map(
        (c) => `
        <div class="comment ${c.name === "Você" ? "you" : ""}">
          <div class="comment-head">
            <span class="comment-name">${c.name}</span>
            <span class="comment-time">${c.time}</span>
          </div>
          <p class="comment-text">${c.text}</p>
        </div>
      `,
      )
      .join("");
  }
  render();
  sec.refresh = render;
  return sec;
}

/* =========================================================================
   TRIVIA (mid-chapter) + MCQ (end-of-chapter) section builders
   Both TriviaSource and McqSource are API placeholders above — swap in
   `fetch()` calls once the other API URL + key are provided.
   ========================================================================= */
function buildTriviaSection(trivia) {
  const sec = document.createElement("div");
  sec.className = "section fact-section";
  sec.setAttribute("data-ref", "Pergunta do capítulo");
  sec.innerHTML = `
      <p class="eyebrow">Pergunta — meio do capítulo</p>
      <p class="quiz-q" style="margin-bottom: 26px;">${trivia.question}</p>
      <button class="btn-primary" id="revealTrivia" type="button" style="margin-bottom: 28px;">
        Revelar resposta
      </button>
      <p class="fact-body" id="triviaAnswer" style="opacity:0; transform: translateY(8px); transition: opacity 0.4s ease, transform 0.4s ease;">
        ${trivia.answer}
      </p>
    `;
  sec.querySelector("#revealTrivia").addEventListener("click", () => {
    const ans = sec.querySelector("#triviaAnswer");
    ans.style.opacity = "1";
    ans.style.transform = "translateY(0)";
    sec.querySelector("#revealTrivia").style.display = "none";
  });
  return sec;
}

/* =========================================================================
   VIDEO SECTION BUILDER + VIEWPORT TRACKING BEHAVIORS
   Behaviors per VIDEO_ANNOTATIONS entry:
   - onEnterScrollTo (true): scrolls smooth to the video when it enters viewport
   - playFromStartOnReEnter (true): always rewind & play-from-0 when it re-enters viewport
   - autoScrollAfterEnded (true): once ended event fires, advance the scroller by 1 viewport
   ========================================================================= */
const VIDEO_WRAP_STYLE = [
  "width: 100%;",
  "align-self: center;",
  "background: #000;",
  "overflow: hidden;",
  "box-shadow: 0 18px 40px -16px rgba(17, 24, 39, 0.5);",
  "position: relative;",
].join("");
const VIDEO_EL_STYLE = [
  "width: 100%;",
  "height: auto;",
  "display: block;",
  "background: #000;",
].join("");

function buildVideoSection(annotation) {
  const sec = document.createElement("div");
  sec.className = "section video-section";
  sec.setAttribute(
    "data-ref",
    "Vídeo · " + annotation.afterVerse.split(".").slice(-2).join(":"),
  );
  sec.dataset.videoAfter = annotation.afterVerse;
  sec.style.marginTop = "20px";
  sec.style.marginBottom = "10px";
  sec.style.display = "flex";
  sec.style.justifyContent = "center";

  const wrap = document.createElement("div");
  wrap.style.cssText = VIDEO_WRAP_STYLE;
  wrap.className = "video-wrap";

  const video = document.createElement("video");
  video.className = "annot-video";
  video.src = annotation.src;
  video.controls = true;
  video.preload = "auto";
  if (annotation.playsInline !== false) {
    video.setAttribute("playsinline", "");
    video.setAttribute("webkit-playsinline", "");
  }
  if (annotation.autoplayMuted) {
    video.muted = true;
    video.autoplay = true;
  }
  video.style.cssText = VIDEO_EL_STYLE;
  video.dataset.autoScrollAfterEnded = annotation.autoScrollAfterEnded
    ? "1"
    : "";
  video.dataset.playFromStartOnReEnter =
    annotation.playFromStartOnReEnter !== false ? "1" : "";
  video.dataset.onEnterScrollTo = annotation.onEnterScrollTo ? "1" : "";

  wrap.appendChild(video);
  sec.appendChild(wrap);

  return sec;
}

function attachVideoBehaviors(scrollerEl) {
  const videos = scrollerEl.querySelectorAll("video.annot-video");
  if (!("IntersectionObserver" in window)) return;
  videos.forEach((video) => {
    if (video.dataset.behaviorsAttached === "1") return;
    video.dataset.behaviorsAttached = "1";
    let lastVisible = false;
    let didInitialScrollTo = false; // scroll-to-video só na primeira entrada
    const io = new IntersectionObserver(
      (entries) => {
        entries.forEach((e) => {
          const visible = e.isIntersecting && e.intersectionRatio > 0.66;
          if (visible && !lastVisible) {
            if (video.dataset.playFromStartOnReEnter === "1") {
              try {
                video.pause();
                video.currentTime = 0;
              } catch (_) {}
            }
            if (video.dataset.onEnterScrollTo === "1" && !didInitialScrollTo) {
              didInitialScrollTo = true;
              const vSec = video.closest(".video-section");
              if (vSec) {
                vSec.scrollIntoView({
                  behavior: "smooth",
                  block: "start",
                });
              }
            }
            const playP = video.play();
            if (playP && typeof playP.catch === "function") {
              playP.catch(() => {
                video.muted = true;
                const p2 = video.play();
                if (p2 && typeof p2.catch === "function") p2.catch(() => {});
              });
            }
          } else if (!visible && lastVisible) {
            try {
              video.pause();
            } catch (_) {}
          }
          lastVisible = visible;
        });
      },
      { root: scrollerEl, threshold: [0.33, 0.66] },
    );
    io.observe(video);

    video.addEventListener("ended", () => {
      if (video.dataset.autoScrollAfterEnded === "1") {
        const oneScreen = Math.max(400, scrollerEl.clientHeight * 0.85);
        scrollerEl.scrollTo({
          top: scrollerEl.scrollTop + oneScreen,
          left: 0,
          behavior: "smooth",
        });
      }
    });
  });
}

function buildEndOfChapterMcqSection(mcq, onContinue) {
  const sec = document.createElement("div");
  sec.className = "section quiz-section";
  sec.setAttribute("data-ref", "Quiz");
  sec.innerHTML = `
      <p class="eyebrow"></p>
      <p class="quiz-q">${mcq.question}</p>
      <div class="options"></div>
      <p class="feedback"></p>
      <button class="continue-btn" type="button">Próximo capítulo <span>↓</span></button>
    `;
  const optionsWrap = sec.querySelector(".options");
  const fb = sec.querySelector(".feedback");
  const continueBtn = sec.querySelector(".continue-btn");

  mcq.options.forEach((opt, i) => {
    const btn = document.createElement("button");
    btn.className = "opt";
    btn.type = "button";
    btn.textContent = opt;
    btn.addEventListener("click", () => {
      optionsWrap.querySelectorAll(".opt").forEach((b) => (b.disabled = true));
      if (i === mcq.correctIndex) {
        btn.classList.add("correct");
      } else {
        btn.classList.add("incorrect");
        optionsWrap.children[mcq.correctIndex].classList.add("correct");
      }
      fb.innerHTML =
        (i === mcq.correctIndex
          ? "<strong>Correto.</strong> "
          : "<strong>Quase.</strong> ") + mcq.explanation;
      fb.classList.add("show");
      continueBtn.classList.add("show");
    });
    optionsWrap.appendChild(btn);
  });

  continueBtn.addEventListener("click", onContinue);
  return sec;
}

/* =========================================================================
   CHAPTER-BY-CHAPTER CONTROLLER
   One chapter at a time inside #scroller. When the user nears the end of
   the current chapter, the next chapter's Bible text + trivia + MCQ are
   prefetched in the background. When the user scrolls PAST the last
   section of the chapter (past the MCQ, if present), the end-of-chapter
   sentinel fires advanceToNextChapter automatically — no button click
   required. The "Próximo capítulo" button inside the MCQ is kept as a
   shortcut for users who don't want to scroll past the quiz.

   On every chapter transition:
     1. every child of #scroller is removed
     2. scrollTop resets to 0
     3. the prefetched next chapter renders into the empty scroller

   Resume + jump-to-chapter:
   - ResumeStorage saves (chapterIndex, contentId, scrollTop) to localStorage
     every time the chapter changes, periodically on scroll, and on page
     unload. On reload we render the remembered chapter + scrollTop.
   - `window.jumpToGenesisChapter(n)` jumps directly to capítulo n (1..50).
   - The "Ir para capítulo" button opens a grid with all 50 capítulos.
   ========================================================================= */
let planCursor = 0;
let previousStoryId = null;
let sectionObserver = null;
let prefetchObserver = null;
let advanceObserver = null;
let currentSentinelPrefetch = null;
let currentSentinelAdvance = null;
let isLoadingNext = false;
let hasStarted = false;
let prefetchCache = null;
let currentChapterIndex = -1;
let pendingResumeScrollTop = 0;
let resumeSaveTimer = null;

function currentContentId() {
  if (currentChapterIndex < 0) return null;
  const entry = READING_PLAN[currentChapterIndex % READING_PLAN.length];
  return entry ? entry.contentId : null;
}

function saveResumePosition(forceScrollTop) {
  if (currentChapterIndex < 0) return;
  ResumeStorage.save({
    chapterIndex: currentChapterIndex,
    contentId: currentContentId(),
    scrollTop:
      typeof forceScrollTop === "number"
        ? forceScrollTop
        : scroller.scrollTop || 0,
  });
  refreshJumpPanelCurrentMarker();
}

function observeSection(el) {
  if (sectionObserver) sectionObserver.observe(el);
}

function attachPrefetchSentinel() {
  if (currentSentinelPrefetch && prefetchObserver)
    prefetchObserver.unobserve(currentSentinelPrefetch);
  const s = document.createElement("div");
  s.className = "sentinel";
  scroller.appendChild(s);
  currentSentinelPrefetch = s;
  if (prefetchObserver) prefetchObserver.observe(s);
}

function attachAdvanceSentinel() {
  if (currentSentinelAdvance && advanceObserver)
    advanceObserver.unobserve(currentSentinelAdvance);
  const s = document.createElement("div");
  s.className = "sentinel";
  scroller.appendChild(s);
  currentSentinelAdvance = s;
  if (advanceObserver) advanceObserver.observe(s);
}

async function prefetchChapterBundle(index) {
  const safeIndex = Math.max(
    0,
    Math.min(READING_PLAN.length - 1, index % READING_PLAN.length),
  );
  const entry = READING_PLAN[safeIndex];
  try {
    const [chapterData, trivia, mcq] = await Promise.all([
      BibleSource.getChapter(entry.contentId),
      TriviaSource.getMidChapterTrivia(entry.contentId),
      McqSource.getEndOfChapterMcq(entry.contentId),
    ]);
    return {
      index: safeIndex,
      entry,
      chapterData,
      trivia,
      mcq,
      ok: true,
    };
  } catch (err) {
    return { index: safeIndex, entry, error: err, ok: false };
  }
}

function clearScroller() {
  while (scroller.firstChild) {
    scroller.removeChild(scroller.firstChild);
  }
  scroller.scrollTop = 0;
  const pFill = document.getElementById("progressFill");
  if (pFill) pFill.style.width = "0%";
}

function renderChapter(bundle, opts) {
  const { entry, chapterData, trivia, mcq, error, ok } = bundle;
  clearScroller();

  pendingResumeScrollTop = (opts && opts.scrollTop) || 0;

  if (!ok) {
    const errSec = document.createElement("div");
    errSec.className = "section";
    errSec.setAttribute("data-ref", "Erro");
    errSec.innerHTML = `
            <p class="eyebrow">Erro ao carregar</p>
            <p class="verse-text" style="max-width: 520px">
              Não foi possível carregar ${entry.contentId}. Verifique se a chave da API e a versão da Bíblia estão corretas, ou se o navegador está bloqueando a requisição (CORS).
            </p>
            <p class="divider-sub" style="margin-top: 20px; text-align: center;">${error.message}</p>
            <button class="btn-primary" type="button" data-retry="1" style="margin-top: 32px;">Tentar próximo capítulo</button>
          `;
    scroller.appendChild(errSec);
    observeSection(errSec);
    errSec.querySelector("[data-retry]").addEventListener("click", () => {
      requestAnimationFrame(() => advanceToNextChapter(true));
    });
    return;
  }

  const divider = buildDividerSection(chapterData, entry);
  scroller.appendChild(divider);
  observeSection(divider);

  const chapterVideos = getVideosForChapter(entry.contentId); // filtra anotações do capítulo atual
  const totalVerses = chapterData.verses.length;
  const midIndex = totalVerses > 1 ? Math.floor(totalVerses / 2) : -1;
  chapterData.verses.forEach((verse, vi) => {
    const isFirstEver = !hasStarted && vi === 0 && pendingResumeScrollTop < 20;
    const verseSection = buildVerseSection(
      chapterData,
      verse,
      isFirstEver,
      entry.contentId,
    );
    scroller.appendChild(verseSection);
    observeSection(verseSection);

    if (entry.funFactAfterVerse === vi && entry.funFact) {
      const factSection = buildFactSection(entry.funFact);
      scroller.appendChild(factSection);
      observeSection(factSection);
    }

    if (vi === midIndex && trivia) {
      const triviaSection = buildTriviaSection(trivia);
      scroller.appendChild(triviaSection);
      observeSection(triviaSection);
    }

    // Insere vídeos marcados para "depois deste versículo" (ex. GEN.1.3)
    const afterVerseId = `${entry.contentId}.${verse.number}`;
    const videosHere = chapterVideos.filter(
      (a) => a.afterVerse === afterVerseId,
    );
    videosHere.forEach((a) => {
      const vs = buildVideoSection(a);
      scroller.appendChild(vs);
      observeSection(vs);
    });
  });

  if (entry.quiz) {
    let reflectSectionRef, commentsSectionRef;
    const quizSection = buildQuizSection(entry.quiz, () => {
      reflectSectionRef &&
        reflectSectionRef.scrollIntoView({ behavior: "smooth" });
    });
    scroller.appendChild(quizSection);
    observeSection(quizSection);

    reflectSectionRef = buildReflectSection((value) => {
      if (value) {
        if (!entry.comments) entry.comments = [];
        entry.comments.unshift({
          name: "Você",
          time: "agora mesmo",
          text: value,
        });
        if (commentsSectionRef && commentsSectionRef.refresh) {
          commentsSectionRef.refresh();
        }
      }
      if (commentsSectionRef) {
        commentsSectionRef.scrollIntoView({ behavior: "smooth" });
      }
    });
    scroller.appendChild(reflectSectionRef);
    observeSection(reflectSectionRef);

    commentsSectionRef = buildCommentsSection(entry.comments || []);
    scroller.appendChild(commentsSectionRef);
    observeSection(commentsSectionRef);
  }

  if (mcq) {
    const mcqSection = buildEndOfChapterMcqSection(mcq, () => {
      advanceToNextChapter(false);
    });
    scroller.appendChild(mcqSection);
    observeSection(mcqSection);
  }

  attachVideoBehaviors(scroller);
  attachPrefetchSentinel();
  attachAdvanceSentinel();

  // Busca o estado de highlights desse capítulo na API YouVersion,
  // mescla com o mirror e re-pinta os badges se houver novidade.
  // (fire-and-forget — a API retorna rápido, mas a UI já está pronta
  // com o estado do mirror)
  const verseNumbers = chapterData.verses
    ? chapterData.verses.map((v) => v.number)
    : [];
  syncChapterHighlightsWithApi(entry.contentId, verseNumbers, scroller);

  previousStoryId = entry.storyId;
  hasStarted = true;

  if (pendingResumeScrollTop > 0) {
    requestAnimationFrame(() => {
      scroller.scrollTop = pendingResumeScrollTop;
      pendingResumeScrollTop = 0;
    });
  }

  if (
    pendingReaderDeepLink &&
    pendingReaderDeepLink.chapterIndex === currentChapterIndex
  ) {
    requestAnimationFrame(() => {
      const targetEl = scroller.querySelector(
        `[data-yv-passage="${pendingReaderDeepLink.passageId}"]`,
      );
      if (!targetEl) return;
      targetEl.scrollIntoView({
        behavior: prefersReducedMotion() ? "auto" : "smooth",
        block: "center",
      });
      setTimeout(
        () => {
          saveResumePosition(scroller.scrollTop);
        },
        prefersReducedMotion() ? 0 : 420,
      );
      pendingReaderDeepLink = null;
      clearReaderDeepLink();
    });
  }

  saveResumePosition(pendingResumeScrollTop || 0);
}

async function advanceToNextChapter(forceSkipCache) {
  if (isLoadingNext) return;
  isLoadingNext = true;
  try {
    const nextIndex = currentChapterIndex + 1;
    if (nextIndex >= READING_PLAN.length) {
      // Fim de Gênesis.
      isLoadingNext = false;
      return;
    }
    let bundle = forceSkipCache ? null : prefetchCache;
    if (!bundle || bundle.index !== nextIndex) {
      prefetchCache = null;
      const fresh = await prefetchChapterBundle(nextIndex);
      bundle = fresh;
    }
    currentChapterIndex = nextIndex;
    planCursor = nextIndex + 1;
    renderChapter(bundle);
    prefetchCache = null;
    schedulePrefetch(currentChapterIndex + 1);
  } finally {
    isLoadingNext = false;
  }
}

async function goToChapterIndex(targetIndex, scrollTopVal) {
  const safeIndex = Math.max(0, Math.min(READING_PLAN.length - 1, targetIndex));
  if (safeIndex === currentChapterIndex && !scrollTopVal) return;
  if (isLoadingNext) return;
  isLoadingNext = true;
  try {
    let bundle =
      prefetchCache && prefetchCache.index === safeIndex ? prefetchCache : null;
    if (!bundle) {
      prefetchCache = null;
      bundle = await prefetchChapterBundle(safeIndex);
    }
    currentChapterIndex = safeIndex;
    planCursor = safeIndex + 1;
    renderChapter(bundle, { scrollTop: scrollTopVal || 0 });
    prefetchCache = null;
    schedulePrefetch(currentChapterIndex + 1);
  } finally {
    isLoadingNext = false;
  }
}

/**
 * Pula para qualquer capítulo de Gênesis.
 * Uso: `jumpToGenesisChapter(3)` ou `jumpToGenesisChapter('22')`.
 * Também disponível em `window.jumpToGenesisChapter(n)`.
 */
function jumpToGenesisChapter(chapterNumber) {
  const n = parseInt(String(chapterNumber).trim(), 10);
  if (!Number.isFinite(n) || n < 1 || n > READING_PLAN.length) {
    throw new RangeError(
      `Capítulo inválido: use um número entre 1 e ${READING_PLAN.length}.`,
    );
  }
  closeJumpPanel();
  goToChapterIndex(n - 1, 0);
}
window.jumpToGenesisChapter = jumpToGenesisChapter;

async function schedulePrefetch(targetIndex) {
  if (targetIndex < 0 || targetIndex >= READING_PLAN.length) return;
  if (prefetchCache && prefetchCache.index === targetIndex) return;
  const fresh = await prefetchChapterBundle(targetIndex);
  prefetchCache = fresh;
}

async function loadFirstChapter() {
  if (isLoadingNext) return;
  isLoadingNext = true;
  try {
    const saved = ResumeStorage.load();
    const startIndex = pendingReaderDeepLink
      ? pendingReaderDeepLink.chapterIndex
      : saved &&
          saved.chapterIndex >= 0 &&
          saved.chapterIndex < READING_PLAN.length
        ? saved.chapterIndex
        : 0;
    const firstBundle = await prefetchChapterBundle(startIndex);
    currentChapterIndex = startIndex;
    planCursor = startIndex + 1;
    renderChapter(firstBundle, {
      scrollTop:
        !pendingReaderDeepLink && saved && saved.chapterIndex === startIndex
          ? saved.scrollTop
          : 0,
    });
    schedulePrefetch(startIndex + 1);
  } finally {
    isLoadingNext = false;
  }
}

function initChapterController() {
  const marker = document.getElementById("markerRef");

  hydrateSavedSetFromMirrorOnly();

  sectionObserver = new IntersectionObserver(
    (entries) => {
      entries.forEach((entry) => {
        if (entry.isIntersecting && entry.intersectionRatio > 0.55) {
          marker.textContent = entry.target.getAttribute("data-ref");
          if (!entry.target.dataset.factDone) {
            const fills = entry.target.querySelectorAll(".fact-bar-fill");
            if (fills.length) {
              fills.forEach((f) => {
                f.style.width = f.dataset.target + "%";
              });
              entry.target.dataset.factDone = "1";
            }
          }
        }
      });
    },
    { root: scroller, threshold: [0.55] },
  );

  prefetchObserver = new IntersectionObserver(
    (entries) => {
      entries.forEach((entry) => {
        if (entry.isIntersecting) {
          schedulePrefetch(currentChapterIndex + 1);
        }
      });
    },
    { root: scroller, rootMargin: "900px 0px 900px 0px" },
  );

  advanceObserver = new IntersectionObserver(
    (entries) => {
      entries.forEach((entry) => {
        if (entry.isIntersecting) {
          advanceToNextChapter(false);
        }
      });
    },
    { root: scroller, rootMargin: "120px 0px 0px 0px" },
  );

  initJumpPanelUI();
  loadFirstChapter();
}

/* =========================================================================
   JUMP PANEL UI — grade com capítulos 1..50 + atalho para retomar
   ========================================================================= */
let jumpPanelInited = false;

function openJumpPanel() {
  if (!jumpPanelInited) return;
  const panel = document.getElementById("jumpPanel");
  const backdrop = document.getElementById("jumpBackdrop");
  const markerBtn = document.getElementById("marker");
  backdrop.hidden = false;
  panel.hidden = false;
  if (markerBtn) markerBtn.setAttribute("aria-expanded", "true");
  refreshJumpPanelCurrentMarker();
  const saved = ResumeStorage.load();
  const foot = document.getElementById("jumpFromStorage");
  const btn = document.getElementById("jumpResumeBtn");
  if (saved && typeof saved.chapterIndex === "number") {
    const ch = saved.chapterIndex + 1;
    btn.textContent = ch.toString();
    foot.hidden = false;
  } else {
    foot.hidden = true;
  }
}

function closeJumpPanel() {
  const panel = document.getElementById("jumpPanel");
  const backdrop = document.getElementById("jumpBackdrop");
  const markerBtn = document.getElementById("marker");
  backdrop.hidden = true;
  panel.hidden = true;
  if (markerBtn) markerBtn.setAttribute("aria-expanded", "false");
}

function refreshJumpPanelCurrentMarker() {
  const grid = document.getElementById("jumpGrid");
  if (!grid || !grid.children.length) return;
  Array.from(grid.children).forEach((cell, i) => {
    const chIndex = i; // grid is 1..50, array index 0 = cap 1
    cell.classList.toggle(
      "current",
      currentChapterIndex >= 0 && chIndex === currentChapterIndex,
    );
  });
}

function initJumpPanelUI() {
  if (jumpPanelInited) return;
  jumpPanelInited = true;

  const grid = document.getElementById("jumpGrid");
  const markerBtn = document.getElementById("marker");
  for (let ch = 1; ch <= READING_PLAN.length; ch++) {
    const cell = document.createElement("button");
    cell.className = "jump-cell";
    cell.type = "button";
    cell.textContent = ch.toString();
    cell.addEventListener("click", () => jumpToGenesisChapter(ch));
    grid.appendChild(cell);
  }

  markerBtn.addEventListener("click", openJumpPanel);
  document
    .getElementById("jumpClose")
    .addEventListener("click", closeJumpPanel);
  document
    .getElementById("jumpBackdrop")
    .addEventListener("click", closeJumpPanel);
  document.getElementById("jumpResumeBtn").addEventListener("click", () => {
    const saved = ResumeStorage.load();
    if (saved) jumpToGenesisChapter(saved.chapterIndex + 1);
  });

  document.addEventListener("keydown", (e) => {
    if (e.key === "Escape") {
      closeJumpPanel();
    } else if ((e.metaKey || e.ctrlKey) && e.key.toLowerCase() === "k") {
      e.preventDefault();
      openJumpPanel();
    }
  });

  // Painel começa fechado.
  closeJumpPanel();
}

/* =========================================================================
   AUTH/APP BOOTSTRAP — decide: tela de login / callback handler / leitor
   Ordem:
   1. Hydrate CONFIG.YOUVERSION_BEARER_TOKEN do localStorage, se houver.
   2. URL contém ?code -> callback OAuth -> exchange -> dex approval.
   3. URL contém ?data_exchange_status=granted/cancelled/error -> dex final.
   4. URL ?error (access_denied do OAuth) -> tela de erro.
   5. else: Bearer presente? -> inicializa leitor. Caso contrário, tela login.
   ========================================================================= */
const loginShell = document.getElementById("loginShell");
const loginCard = document.getElementById("loginCard");
const loadingCard = document.getElementById("loadingCard");
const errorCard = document.getElementById("errorCard");
const logoutBtn = document.getElementById("logoutBtn");

function showCard(which) {
  loginCard.hidden = which !== "login";
  loadingCard.hidden = which !== "loading";
  errorCard.hidden = which !== "error";
}
function hideLoginShell() {
  loginShell.style.display = "none";
}
function setLoading(title, sub) {
  document.getElementById("loadingTitle").textContent =
    title || "Conectando com YouVersion…";
  document.getElementById("loadingSub").textContent =
    sub || "Por favor, aguarde.";
  showCard("loading");
}
function showError(title, body, onRetry, extra) {
  document.getElementById("errTitle").textContent =
    title || "Não foi possível entrar";
  document.getElementById("errBody").innerHTML =
    body || "Tente novamente ou continue sem conta YouVersion.";
  const debug = document.getElementById("loginDebug");
  const debugBox = document.getElementById("loginDebugBox");
  const extraBox = document.getElementById("errExtraActions");
  extraBox.innerHTML = "";
  const info = (extra && extra.debugInfo) || null;
  if (info && typeof info === "object") {
    debug.hidden = false;
    try {
      debugBox.textContent = JSON.stringify(info, null, 2);
    } catch (_) {
      debugBox.textContent = String(info);
    }
  } else {
    debug.hidden = true;
    debugBox.textContent = "";
  }
  const actions = (extra && extra.extraActions) || [];
  actions.forEach((act) => {
    const b = document.createElement("button");
    b.type = "button";
    b.className = "login-alt-retry";
    b.textContent = act.label;
    b.addEventListener("click", () => {
      showCard("loading");
      Promise.resolve()
        .then(() => act.onClick && act.onClick())
        .catch((e) =>
          showError(
            null,
            `${e && e.message ? e.message : String(e)}`,
            onRetry,
            extra,
          ),
        );
    });
    extraBox.appendChild(b);
  });
  document.getElementById("errRetry").onclick = () => {
    showCard("loading");
    (onRetry && onRetry()).catch((e) =>
      showError(
        null,
        `${e && e.message ? e.message : String(e)}`,
        onRetry,
        extra,
      ),
    );
  };
  showCard("error");
}

function hydrateBearerFromStorage() {
  const sess = loadAuthSession();
  if (sess && sess.access_token) {
    CONFIG.YOUVERSION_BEARER_TOKEN = sess.access_token;
    return sess;
  }
  return null;
}

function initReaderAndHooks() {
  loginShell && (loginShell.style.display = "none");
  logoutBtn.hidden = !CONFIG.YOUVERSION_BEARER_TOKEN;

  initChapterController();

  scroller.addEventListener("scroll", () => {
    const max = scroller.scrollHeight - scroller.clientHeight;
    const pct = max > 0 ? (scroller.scrollTop / max) * 100 : 0;
    document.getElementById("progressFill").style.width = pct + "%";
    document.getElementById("scrollHint").style.opacity =
      scroller.scrollTop > 40 ? "0" : "0.7";
    clearTimeout(resumeSaveTimer);
    resumeSaveTimer = setTimeout(
      () => saveResumePosition(scroller.scrollTop),
      350,
    );
  });
  window.addEventListener("beforeunload", () =>
    saveResumePosition(scroller.scrollTop),
  );
  document.addEventListener("visibilitychange", () => {
    if (document.visibilityState === "hidden") {
      saveResumePosition(scroller.scrollTop);
    }
  });
}

function wireLoginButtons() {
  document.getElementById("loginBtn").addEventListener("click", () => {
    setLoading(
      "Redirecionando para aprovação YouVersion",
      "Você vai sair para a página oficial YouVersion e voltar quando aprovar.",
    );
    YouVersionAuth.beginLogin().catch((e) => {
      showError(
        "Não foi possível iniciar login",
        `${e && e.message ? e.message : String(e)}<br><small>Verifique se a chave YouVersion está ativa para OAuth.</small>`,
        () => YouVersionAuth.beginLogin(),
      );
    });
  });

  const skipFn = () => {
    hideLoginShell();
    initReaderAndHooks();
  };
  document.getElementById("loginSkipBtn").addEventListener("click", skipFn);
  document.getElementById("errSkip").addEventListener("click", skipFn);

  logoutBtn.addEventListener("click", () => {
    clearAuthSession();
    CONFIG.YOUVERSION_BEARER_TOKEN = "";
    window.location.reload();
  });
}

async function handleRedirect() {
  const qParams = new URLSearchParams(window.location.search);
  const hParams = new URLSearchParams(
    window.location.hash ? window.location.hash.slice(1) : "",
  );
  const getP = (k) =>
    qParams.get(k) !== null && qParams.get(k) !== ""
      ? qParams.get(k)
      : hParams.get(k);
  const qsCode = getP("code");
  const qsState = getP("state");
  const qsError = getP("error");
  const qsErrorDesc = getP("error_description");
  const dexStatus = getP("data_exchange_status");
  const grantedPermissions = getP("granted_permissions");
  const deniedPermissions = getP("denied_permissions");
  const qsAccessToken = getP("access_token");
  const qsIdToken = getP("id_token");
  const qsTokenType = getP("token_type");
  const qsExpiresIn = getP("expires_in");
  const qsScope = getP("scope");
  const pendingDex = loadDexSession();

  const hasDexMarkers =
    !!pendingDex &&
    (!!dexStatus ||
      !!grantedPermissions ||
      !!deniedPermissions ||
      (!!pendingDex && !!qsError));
  const hasOauthMarkers = !!qsCode || !!qsAccessToken || !!qsIdToken;

  const anyRedirectParam =
    hasOauthMarkers ||
    qsError ||
    hasDexMarkers ||
    qParams.get("error_code") ||
    qsState;

  if (!anyRedirectParam) {
    // Não há callback — decide: login screen ou leitor direto.
    const sess = hydrateBearerFromStorage();
    wireLoginButtons();
    if (sess && sess.access_token) {
      hideLoginShell();
      initReaderAndHooks();
      return;
    }
    showCard("login");
    return;
  }

  // Limpa query params do final do fluxo (evita reload re-aplicar callback).
  function finishAndClearSearch() {
    try {
      const u = new URL(window.location.href);
      u.search = "";
      u.hash = "";
      window.history.replaceState({}, document.title, u.toString());
    } catch (_) {}
  }

  function finishDataExchange(message) {
    wireLoginButtons();
    hydrateBearerFromStorage();
    finishAndClearSearch();
    initReaderAndHooks();
    if (message) showToast(message);
    clearDexSession();
  }

  // Data Exchange callback deve ser interpretado antes de qualquer fallback
  // de OAuth. A doc oficial retorna `data_exchange_status` e permissões,
  // não um novo `code` OAuth.
  const effectiveDexStatus = dexStatus
    ? dexStatus
    : grantedPermissions
      ? "granted"
      : deniedPermissions || qsError === "access_denied"
        ? "cancelled"
        : pendingDex && qsError
          ? "error"
          : "";

  if (effectiveDexStatus === "granted") {
    const permCount = grantedPermissions
      ? grantedPermissions.split(",").filter(Boolean).length
      : 0;
    finishDataExchange(
      `Pronto! ${permCount} permissão(ões) YouVersion concedida(s). Destaques sincronizados ativos.`,
    );
    return;
  }

  if (effectiveDexStatus === "cancelled") {
    finishDataExchange(
      "Permissões YouVersion canceladas. Login permanece ativo; destaques serão locais.",
    );
    return;
  }

  if (effectiveDexStatus === "error") {
    finishDataExchange(
      `Aprovação YouVersion com erro (${qsError || "desconhecido"}). Destaques locais ativos.`,
    );
    return;
  }

  // Se existe um fluxo de Data Exchange pendente e a volta não trouxe os
  // campos esperados, não devemos cair no diagnóstico de OAuth.
  if (pendingDex && !hasOauthMarkers) {
    finishDataExchange(
      "A aprovação YouVersion retornou sem status reconhecido. Login mantido; destaques locais continuam ativos.",
    );
    return;
  }

  // (1) Primeiro redirect do OAuth moderno: apenas ?state=...
  if (qsState && !qsCode && !qsAccessToken && !qsIdToken && !qsError) {
    wireLoginButtons();
    try {
      setLoading(
        "Finalizando login YouVersion",
        "Confirmando retorno da YouVersion…",
      );
      YouVersionAuth.continueLoginWithState(qsState);
      return;
    } catch (e) {
      finishAndClearSearch();
      showError(
        "Erro ao confirmar login YouVersion",
        `${e && e.message ? e.message : String(e)}<br><small>A YouVersion agora retorna primeiro apenas o <code>state</code>; a app precisa reenviá-lo para <code>/auth/callback</code>.</small>`,
        () => YouVersionAuth.beginLogin(),
      );
      return;
    }
  }

  // (2) Segundo callback OAuth com ?code (ou #code=... no fragment).
  if (qsCode) {
    wireLoginButtons();
    setLoading(
      "Finalizando login YouVersion",
      "Trocando código de autorização por token de acesso…",
    );
    try {
      await YouVersionAuth.exchangeCodeForToken(
        qsCode,
        qsState,
        grantedPermissions,
      );
      finishAndClearSearch();
      initReaderAndHooks();
      const permCount = grantedPermissions
        ? grantedPermissions.split(",").filter(Boolean).length
        : 0;
      showToast(
        permCount
          ? `Login realizado. ${permCount} permissão(ões) concedida(s) pela YouVersion.`
          : "Login realizado com sucesso.",
      );
      return;
    } catch (e) {
      finishAndClearSearch();
      wireLoginButtons();
      showError(
        "Erro ao finalizar login",
        `${e && e.message ? e.message : String(e)}<br><small>Você pode tentar novamente ou continuar sem conta (destaques salvos apenas neste dispositivo).</small>`,
        () => YouVersionAuth.beginLogin(),
      );
      return;
    }
  }

  // (1b) Implicit / hybrid flow: access_token ou id_token retornados DIRETO
  // no #fragment — salva sessão direto sem precisar trocar code.
  if (qsAccessToken) {
    wireLoginButtons();
    setLoading("Finalizando login YouVersion", "Recebendo token de acesso…");
    try {
      const exp = qsExpiresIn ? parseInt(qsExpiresIn, 10) : null;
      if (qsIdToken) {
        const raw = localStorage.getItem(AUTH_PKCE_KEY);
        if (raw) {
          try {
            const pkce = JSON.parse(raw);
            if (pkce && pkce.nonce) {
              const claims = parseJwtPayload(qsIdToken);
              if (claims && claims.nonce && claims.nonce !== pkce.nonce)
                throw new Error("Nonce mismatch — id_token não corresponde.");
            }
          } catch (_) {}
        }
      }
      saveAuthSession({
        access_token: qsAccessToken,
        token_type: qsTokenType || "Bearer",
        id_token: qsIdToken || null,
        refresh_token: null,
        expires_in: exp,
        scope: qsScope || null,
        granted_permissions: grantedPermissions || null,
        issuedAt: Date.now(),
      });
      CONFIG.YOUVERSION_BEARER_TOKEN = qsAccessToken;
      try {
        localStorage.removeItem(AUTH_PKCE_KEY);
      } catch (_) {}
      finishAndClearSearch();
      initReaderAndHooks();
      showToast("Login realizado com sucesso.");
      return;
    } catch (e) {
      finishAndClearSearch();
      wireLoginButtons();
      showError(
        "Erro ao finalizar login (token implícito)",
        `${e && e.message ? e.message : String(e)}<br><small>Você pode tentar novamente ou continuar sem conta.</small>`,
        () => YouVersionAuth.beginLogin(),
      );
      return;
    }
  }

  // (3) OAuth /callback ?error=access_denied etc.
  if (qsError) {
    wireLoginButtons();
    finishAndClearSearch();
    const isDenied = qsError === "access_denied" || qsError === "cancelled";
    showError(
      isDenied ? "Aprovação cancelada" : "Erro no login YouVersion",
      `${qsErrorDesc ? `${qsErrorDesc} · ` : ""}${qsError}<br><small>Você pode aprovar novamente ou continuar sem conta YouVersion (destaques salvos apenas neste dispositivo).</small>`,
      () => YouVersionAuth.beginLogin(),
    );
    return;
  }

  // Caso genérico: só carregar o leitor.
  wireLoginButtons();
  hydrateBearerFromStorage();
  finishAndClearSearch();
  initReaderAndHooks();
}

// Boot.
(async function boot() {
  try {
    await handleRedirect();
  } catch (e) {
    wireLoginButtons();
    showError(
      "Falha ao inicializar autenticação",
      `${e && e.message ? e.message : String(e)}<br><small>Tente novamente ou continue sem conta YouVersion.</small>`,
      () => YouVersionAuth.beginLogin(),
    );
  }
})();

/* =========================================================================
   FOCUS MODE — dims the interface and plays a soft rain-like ambience
   ========================================================================= */
let audioCtx = null,
  rain = null,
  focusOn = false,
  modInterval = null;

function startModulation() {
  clearInterval(modInterval);
  modInterval = setInterval(() => {
    if (!focusOn || !rain) return;
    const target = 500 + Math.random() * 900;
    rain.filter.frequency.cancelScheduledValues(audioCtx.currentTime);
    rain.filter.frequency.linearRampToValueAtTime(
      target,
      audioCtx.currentTime + 2.5,
    );
  }, 2500);
}

const focusBtn = document.getElementById("focusBtn");
const focusIcon = focusBtn.querySelector(".focus-icon");
const FOCUS_ICON_OFF = `<svg xmlns="http://www.w3.org/2000/svg" width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" class="lucide lucide-sun-icon lucide-sun"><circle cx="12" cy="12" r="4"/><path d="M12 2v2"/><path d="M12 20v2"/><path d="m4.93 4.93 1.41 1.41"/><path d="m17.66 17.66 1.41 1.41"/><path d="M2 12h2"/><path d="M20 12h2"/><path d="m6.34 17.66-1.41 1.41"/><path d="m19.07 4.93-1.41 1.41"/></svg>`;
const FOCUS_ICON_ON = `<svg xmlns="http://www.w3.org/2000/svg" width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" class="lucide lucide-cloud-sun-rain-icon lucide-cloud-sun-rain"><path d="M12 2v2"/><path d="m4.93 4.93 1.41 1.41"/><path d="M20 12h2"/><path d="m19.07 4.93-1.41 1.41"/><path d="M15.947 12.65a4 4 0 0 0-5.925-4.128"/><path d="M3 20a5 5 0 1 1 8.9-4H13a3 3 0 0 1 2 5.24"/><path d="M11 20v2"/><path d="M7 19v2"/></svg>`;
const soakingAudio = new Audio("soaking.mp3");
soakingAudio.loop = true;
soakingAudio.volume = 0; // começa em 0 pra fazer fade-in

function updateFocusButtonUi() {
  focusBtn.classList.toggle("active", focusOn);
  focusBtn.setAttribute("aria-pressed", String(focusOn));
  focusBtn.setAttribute(
    "aria-label",
    focusOn ? "Desativar modo foco" : "Ativar modo foco",
  );
  focusBtn.setAttribute(
    "title",
    focusOn ? "Desativar modo foco" : "Ativar modo foco",
  );
  focusIcon.innerHTML = focusOn ? FOCUS_ICON_ON : FOCUS_ICON_OFF;
}

updateFocusButtonUi();

function fadeAudio(el, target, duration = 900) {
  const start = el.volume;
  const startTime = performance.now();
  function step(now) {
    const t = Math.min((now - startTime) / duration, 1);
    el.volume = start + (target - start) * t;
    if (t < 1) requestAnimationFrame(step);
  }
  requestAnimationFrame(step);
}

focusBtn.addEventListener("click", async () => {
  focusOn = !focusOn;
  document.body.classList.toggle("focus-active", focusOn);
  updateFocusButtonUi();

  if (focusOn) {
    try {
      await soakingAudio.play();
      fadeAudio(soakingAudio, 1);
    } catch (err) {
      console.warn("Não consegui tocar o áudio:", err);
    }

    if (audioCtx && audioCtx.state === "suspended") await audioCtx.resume();
    showToast("Modo foco ativado — som suave ligado");
  } else {
    fadeAudio(soakingAudio, 0);
    setTimeout(() => soakingAudio.pause(), 950);

    if (rain) {
      rain.gain.gain.cancelScheduledValues(audioCtx.currentTime);
      rain.gain.gain.setValueAtTime(rain.gain.gain.value, audioCtx.currentTime);
      rain.gain.gain.linearRampToValueAtTime(0, audioCtx.currentTime + 0.9);
    }
    showToast("Modo foco desativado");
  }
});
