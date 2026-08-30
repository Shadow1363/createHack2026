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
const TOGETHER_INVITE_KEY = "together_pending_join_v1";

function isTogetherSessionId(value) {
  return /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i.test(
    String(value || ""),
  );
}

function stashTogetherInvite(sessionId) {
  if (!isTogetherSessionId(sessionId)) return;
  try {
    localStorage.setItem(
      TOGETHER_INVITE_KEY,
      JSON.stringify({ id: sessionId, at: Date.now() }),
    );
  } catch (_) {}
}

function peekTogetherInvite() {
  try {
    const raw = localStorage.getItem(TOGETHER_INVITE_KEY);
    if (!raw) return null;
    const v = JSON.parse(raw);
    if (!v || !isTogetherSessionId(v.id)) return null;
    if (Date.now() - (v.at || 0) > 48 * 3600 * 1000) return null;
    return v.id;
  } catch (_) {
    return null;
  }
}

function takeTogetherInvite() {
  const id = peekTogetherInvite();
  try {
    localStorage.removeItem(TOGETHER_INVITE_KEY);
  } catch (_) {}
  return id;
}

function stashAndStripTogetherInviteFromUrl() {
  try {
    const u = new URL(window.location.href);
    const id = u.searchParams.get("together") || u.searchParams.get("join");
    if (isTogetherSessionId(id)) {
      stashTogetherInvite(id);
      u.searchParams.delete("together");
      u.searchParams.delete("join");
      window.history.replaceState({}, document.title, u.toString());
    }
  } catch (_) {}
}

function consumePendingTogetherInvite() {
  const id = takeTogetherInvite();
  if (!id) return;
  const tryOpen = () => {
    if (window.Together && typeof window.Together.openInviteLink === "function") {
      window.Together.openInviteLink(id);
      return true;
    }
    return false;
  };
  if (!tryOpen()) {
    setTimeout(tryOpen, 0);
    window.addEventListener("load", tryOpen, { once: true });
  }
}

function currentRedirectUri() {
  const u = new URL(window.location.href);
  u.search = "";
  u.hash = "";
  return u.toString();
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
    const chapter = parseInt(String(contentId).replace(/^GEN\./, ""), 10);

    /*
Gn 2:7	
O nome "Adao" vem do hebraico adamah, que significa terra ou solo. E um jogo de palavras no original: o homem (adam) e formado do solo (adamah).
Gn 4:17	Caim constroi a primeira cidade mencionada na Biblia, chamada Enoque.
Gn 5:27	Matusalem vive 969 anos, a maior idade registrada na Biblia.
Gn 6:15	
A arca tinha aproximadamente 137m de comprimento por 23m de largura, usando o covado comum (~45cm). Pra efeito de comparacao, e proximo do comprimento de um campo e meio de futebol.
Gn 11:9	
"Babel" e associada ao hebraico balal, confundir. Curiosamente, em acadio a mesma palavra (Bab-ili) significa "porta dos deuses", o oposto do sentido biblico.
Gn 50:26	Jose morre aos 110 anos, idade considerada o ideal de vida plena na cultura egipcia antiga.
*/

    const bank = [
      {
        q: "Quantos dias de criação aparecem em Gênesis 1?",
        a: "Seis dias, com descanso no sétimo (Gênesis 2:1–3).",
      },
      {
        q: "De qual ribeiro Deus formou o homem, no jardim do Éden?",
        a: "Do pó da terra; soprou em seus narizes o fôlego da vida (Gênesis 2:7).",
      },
      {
        q: "Qual fruto Eva comeu primeiro, segundo o texto de Gênesis?",
        a: "O texto não cita a fruta; só diz que era do fruto da árvore proibida no meio do jardim (Gênesis 3:6).",
      },
      {
        q: "De quem é a linhagem registrada em Gênesis 5?",
        a: "De Adão a Noé, passando por Sete, Enos, Cainã, Maalaleel, Jerede, Enoque, Matusalém, Lameque e Noé.",
      },
      {
        q: "Por que Deus decidiu destruir a terra com dilúvio (Gênesis 6)?",
        a: "Porque a maldade do homem se multiplicara e toda imaginação dos pensamentos de seu coração era má continuamente.",
      },
    ];
    const pick = bank[chapter % bank.length];
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
        q: "No primeiro dia da criação, o que Deus fez primeiro?",
        options: [
          "Criou os luminares no céu",
          "Disse: Haja luz, e separou a luz das trevas",
          "Formou o homem do pó da terra",
        ],
        correctIndex: 1,
        explanation:
          "Gênesis 1:3–5 — a luz vem antes dos luminares do quarto dia; o homem é formado no capítulo 2.",
      },
      {
        q: "O rio que saía de Éden se dividia em quatro braços. Qual deles NÃO está listado em Gênesis 2?",
        options: ["Eufrates", "Tigre (Hiddequel)", "Nilo"],
        correctIndex: 2,
        explanation:
          "Os quatro rios são Pisom, Giom, Hiddequel (Tigre) e Eufrates (Gênesis 2:10–14). Nilo não aparece.",
      },
      {
        q: "Que maldição Deus pronunciou sobre a serpente em Gênesis 3?",
        options: [
          "Rastejar sobre o ventre e comer pó todos os dias da sua vida",
          "Ser expulsa do Éden junto com Adão",
          "Não poder provar do fruto das árvores do jardim",
        ],
        correctIndex: 0,
        explanation:
          "Gênesis 3:14 — a serpente rasteja sobre o ventre e come pó; a expulsão é sobre o casal humano.",
      },
      {
        q: "Caim matou Abel por ciúmes de quê?",
        options: [
          "Da beleza dos rebanhos de Abel",
          "Do favor de Deus sobre a oferta de Abel",
          "Da herança prometida a Abel",
        ],
        correctIndex: 1,
        explanation:
          "Gênesis 4:4–5 — Deus respeitou Abel e sua oferta, mas não a Caim; a ira de Caim resultou em fratricídio.",
      },
    ];
    const pick = bank[chapter % bank.length];
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
savedCounter.className = "saved-counter";
savedCounter.innerHTML = `<span class="cbookmark"></span><span id="savedCount">0</span> salvos`;
document.body.appendChild(savedCounter);

const toast = document.createElement("div");
toast.className = "toast";
toast.innerHTML = `<span class="tbookmark"></span><span class="ttext"></span>`;
document.body.appendChild(toast);

const vignette = document.createElement("div");
vignette.className = "focus-vignette";
document.body.appendChild(vignette);

let toastTimer = null;
function showToast(message) {
  clearTimeout(toastTimer);
  toast.querySelector(".ttext").textContent = message;
  toast.classList.add("show");
  toastTimer = setTimeout(() => toast.classList.remove("show"), 2200);
}

function updateSavedCounter() {
  document.getElementById("savedCount").textContent = savedSet.size;
  savedCounter.classList.toggle("show", savedSet.size > 0);
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
    pointerDownX = e.clientX;
    pointerDownY = e.clientY;
  });

  sectionEl.addEventListener("pointerup", (e) => {
    if (e.pointerType === "mouse" && e.button !== 0) return;
    const dx = e.clientX - pointerDownX;
    const dy = e.clientY - pointerDownY;
    if (Math.abs(dx) > MOVE_TOLERANCE || Math.abs(dy) > MOVE_TOLERANCE) return;

    hideAllHints();
    const now = Date.now();
    const nearLastTap =
      Math.abs(e.clientX - lastTapX) <= MOVE_TOLERANCE &&
      Math.abs(e.clientY - lastTapY) <= MOVE_TOLERANCE;

    if (now - lastTapAt <= DOUBLE_TAP_MS && nearLastTap) {
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
      <p class="quiz-q">${quiz.question}</p>
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
  sec.className = "section";
  sec.setAttribute("data-ref", "Quiz fim do capítulo");
  sec.innerHTML = `
      <p class="eyebrow">Final do capítulo — múltipla escolha</p>
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
    const startIndex =
      saved &&
      saved.chapterIndex >= 0 &&
      saved.chapterIndex < READING_PLAN.length
        ? saved.chapterIndex
        : 0;
    const firstBundle = await prefetchChapterBundle(startIndex);
    currentChapterIndex = startIndex;
    planCursor = startIndex + 1;
    renderChapter(firstBundle, {
      scrollTop:
        saved && saved.chapterIndex === startIndex ? saved.scrollTop : 0,
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
  backdrop.hidden = false;
  panel.hidden = false;
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
  backdrop.hidden = true;
  panel.hidden = true;
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
  for (let ch = 1; ch <= READING_PLAN.length; ch++) {
    const cell = document.createElement("button");
    cell.className = "jump-cell";
    cell.type = "button";
    cell.textContent = ch.toString();
    cell.addEventListener("click", () => jumpToGenesisChapter(ch));
    grid.appendChild(cell);
  }

  document.getElementById("jumpBtn").addEventListener("click", openJumpPanel);
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
  const inviteNote = document.getElementById("loginInviteNote");
  if (inviteNote) {
    const pending = peekTogetherInvite();
    inviteNote.hidden = which !== "login" || !pending;
  }
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

function syncTogetherProfileFromSession() {
  if (!window.TogetherDB) return;
  const sess = loadAuthSession();
  const claims = sess && sess.id_token ? parseJwtPayload(sess.id_token) : null;
  const task = claims
    ? window.TogetherDB.linkYouVersionProfile(claims)
    : window.TogetherDB.ensureSession();
  task.catch((e) =>
    console.warn("[Together] Falha ao sincronizar perfil Supabase:", e),
  );
}

function initReaderAndHooks() {
  loginShell && (loginShell.style.display = "none");
  logoutBtn.hidden = !CONFIG.YOUVERSION_BEARER_TOKEN;

  syncTogetherProfileFromSession();
  const tabbarEl = document.getElementById("tabbar");
  if (tabbarEl) tabbarEl.hidden = false;
  const tryInitTogether = () => {
    if (window.Together && typeof window.Together.init === "function") {
      window.Together.init();
      return true;
    }
    return false;
  };
  if (!tryInitTogether()) {
    setTimeout(tryInitTogether, 0);
    document.addEventListener("DOMContentLoaded", tryInitTogether, { once: true });
    window.addEventListener("load", tryInitTogether, { once: true });
  }

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

  consumePendingTogetherInvite();
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
  stashAndStripTogetherInviteFromUrl();
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

function buildRainNoise(ctx) {
  const bufferSize = 2 * ctx.sampleRate;
  const buffer = ctx.createBuffer(1, bufferSize, ctx.sampleRate);
  const data = buffer.getChannelData(0);
  let lastOut = 0;
  for (let i = 0; i < bufferSize; i++) {
    const white = Math.random() * 2 - 1;
    data[i] = (lastOut + 0.02 * white) / 1.02;
    lastOut = data[i];
    data[i] *= 3.2;
  }
  const source = ctx.createBufferSource();
  source.buffer = buffer;
  source.loop = true;
  const filter = ctx.createBiquadFilter();
  filter.type = "lowpass";
  filter.frequency.value = 900;
  const gain = ctx.createGain();
  gain.gain.value = 0;
  source.connect(filter).connect(gain).connect(ctx.destination);
  source.start(0);
  return { source, filter, gain };
}

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
const focusLabel = document.getElementById("focusLabel");

focusBtn.addEventListener("click", async () => {
  focusOn = !focusOn;
  document.body.classList.toggle("focus-active", focusOn);
  focusBtn.classList.toggle("active", focusOn);
  focusBtn.setAttribute("aria-pressed", String(focusOn));
  focusLabel.textContent = focusOn ? "Foco ativo" : "Modo foco";

  if (focusOn) {
    if (!audioCtx) {
      audioCtx = new (window.AudioContext || window.webkitAudioContext)();
      rain = buildRainNoise(audioCtx);
      startModulation();
    }
    if (audioCtx.state === "suspended") await audioCtx.resume();
    rain.gain.gain.cancelScheduledValues(audioCtx.currentTime);
    rain.gain.gain.setValueAtTime(rain.gain.gain.value, audioCtx.currentTime);
    rain.gain.gain.linearRampToValueAtTime(0.16, audioCtx.currentTime + 1.4);
    showToast("Modo foco ativado — som suave ligado");
  } else {
    if (rain) {
      rain.gain.gain.cancelScheduledValues(audioCtx.currentTime);
      rain.gain.gain.setValueAtTime(rain.gain.gain.value, audioCtx.currentTime);
      rain.gain.gain.linearRampToValueAtTime(0, audioCtx.currentTime + 0.9);
    }
    showToast("Modo foco desativado");
  }
});
