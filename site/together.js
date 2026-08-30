/* =========================================================================
   TOGETHER — leitura em grupo com gamificação (pontos + streak) + tela "You"
   Depende de: supabase-client.js (TogetherDB), script.js (BibleSource,
   CONFIG, GENESIS_SUBTITLES, showToast, parseJwtPayload).
   ========================================================================= */

const TOGETHER_BOOKS = [
  { usfm: "GEN", name: "Genesis", chapters: 50, enabled: true },
  { usfm: "PSA", name: "Psalms", chapters: 150, enabled: false },
  { usfm: "PRO", name: "Proverbs", chapters: 31, enabled: false },
  { usfm: "ISA", name: "Isaiah", chapters: 66, enabled: false },
  { usfm: "MAT", name: "Matthew", chapters: 28, enabled: false },
  { usfm: "LUK", name: "Luke", chapters: 24, enabled: false },
  { usfm: "JHN", name: "John", chapters: 21, enabled: false },
  { usfm: "ROM", name: "Romans", chapters: 16, enabled: false },
  { usfm: "PHP", name: "Philippians", chapters: 4, enabled: false },
  { usfm: "JAS", name: "James", chapters: 5, enabled: false },
];

function togetherEl(tag, className, html) {
  const el = document.createElement(tag);
  if (className) el.className = className;
  if (html !== undefined) el.innerHTML = html;
  return el;
}

function togetherInitials(name) {
  const clean = String(name || "?").trim();
  if (!clean) return "?";
  const parts = clean.split(/\s+/);
  return ((parts[0][0] || "") + (parts[1] ? parts[1][0] : "")).toUpperCase();
}

function togetherTimeAgo(iso) {
  if (!iso) return "";
  const diffMs = Date.now() - new Date(iso).getTime();
  const mins = Math.round(diffMs / 60000);
  if (mins < 1) return "agora";
  if (mins < 60) return `${mins} min atrás`;
  const hours = Math.round(mins / 60);
  if (hours < 24) return `${hours}h atrás`;
  const days = Math.round(hours / 24);
  return `${days}d atrás`;
}

const GENESIS_VERSE_COUNTS = [
  31, 25, 24, 26, 32, 22, 24, 22, 29, 32, 32, 20, 18, 24, 21, 16, 27, 33, 38,
  18, 34, 24, 20, 67, 34, 35, 46, 22, 35, 43, 55, 32, 20, 31, 29, 43, 36, 30,
  23, 23, 57, 38, 34, 34, 28, 34, 31, 22, 33, 26,
];

function togetherVerseCount(bookUsfm, chapter) {
  if (
    bookUsfm === "GEN" &&
    chapter >= 1 &&
    chapter <= GENESIS_VERSE_COUNTS.length
  ) {
    return GENESIS_VERSE_COUNTS[chapter - 1];
  }
  return 12;
}

function togetherShareText(title) {
  return title ? `Vem ler ${title} comigo` : "Vem ler comigo";
}

function togetherWhatsAppUrl(inviteUrl, title) {
  const text = `${togetherShareText(title)}\n${inviteUrl}`;
  return `https://wa.me/?text=${encodeURIComponent(text)}`;
}

function tryNativeShare(inviteUrl, title) {
  if (typeof navigator.share !== "function") return Promise.resolve(false);
  const data = {
    title: title || "Leitura em conjunto",
    text: togetherShareText(title),
    url: inviteUrl,
  };
  try {
    if (typeof navigator.canShare === "function" && !navigator.canShare(data)) {
      return Promise.resolve(false);
    }
  } catch (_) {}
  return navigator
    .share(data)
    .then(() => true)
    .catch((err) => {
      if (err && err.name === "AbortError") return true;
      return false;
    });
}

function closeTogetherShareSheet() {
  document.getElementById("tgShareSheet")?.remove();
}

function showTogetherShareSheet(inviteUrl, title) {
  closeTogetherShareSheet();
  const overlay = togetherEl("div", "tg-share-overlay");
  overlay.id = "tgShareSheet";
  overlay.innerHTML = `
    <div class="tg-share-sheet" role="dialog" aria-modal="true" aria-labelledby="tgShareTitle">
      <div class="tg-share-handle"></div>
      <p id="tgShareTitle" class="tg-share-title">Compartilhar</p>
      <p class="tg-share-sub">${title ? `Convite para ${title}` : "Link de convite"}</p>
      <button type="button" class="tg-share-row" id="tgShareNative"${typeof navigator.share === "function" ? "" : " hidden"}>
        Compartilhar…
      </button>
      <a class="tg-share-row" id="tgShareWa" href="${togetherWhatsAppUrl(inviteUrl, title)}" target="_blank" rel="noopener">
        WhatsApp
      </a>
      <button type="button" class="tg-share-row" id="tgShareCopy">Copiar link</button>
      <button type="button" class="tg-share-cancel" id="tgShareClose">Cancelar</button>
    </div>
  `;
  const close = () => closeTogetherShareSheet();
  overlay.addEventListener("click", (e) => {
    if (e.target === overlay) close();
  });
  overlay.querySelector("#tgShareClose").addEventListener("click", close);
  overlay.querySelector("#tgShareWa").addEventListener("click", close);
  const nativeBtn = overlay.querySelector("#tgShareNative");
  nativeBtn.addEventListener("click", async () => {
    const ok = await tryNativeShare(inviteUrl, title);
    if (ok) close();
  });
  overlay.querySelector("#tgShareCopy").addEventListener("click", async () => {
    try {
      await navigator.clipboard.writeText(inviteUrl);
      showToast("Link copiado");
      close();
    } catch (_) {
      showToast(inviteUrl);
    }
  });
  document.body.appendChild(overlay);
}

function shareTogetherInvite(inviteUrl, title) {
  if (typeof navigator.share !== "function") {
    showTogetherShareSheet(inviteUrl, title);
    return;
  }
  tryNativeShare(inviteUrl, title).then((shared) => {
    if (!shared) showTogetherShareSheet(inviteUrl, title);
  });
}

const Together = {
  _state: {
    view: "list",
    draft: {},
    unsubscribe: null,
    currentUserId: null,
    invitePoll: null,
  },

  init() {
    if (this._wired) return;
    this.viewRead = document.getElementById("scroller");
    this.viewTogether = document.getElementById("togetherView");
    this.viewYou = document.getElementById("youView");
    this.tabbar = document.getElementById("tabbar");
    if (!this.tabbar || !this.viewTogether || !this.viewYou) return;
    this._wired = true;

    // Clique das abas é ligado no HTML (listener no #tabbar), para não
    // depender da ordem de carregamento dos scripts após o login YouVersion.

    // Elementos do leitor que também precisam sumir fora da aba "Read".
    this.readOnlyEls = [
      document.getElementById("progressFill")?.parentElement,
      document.getElementById("marker"),
      document.getElementById("scrollHint"),
      document.getElementById("focusBtn"),
      document.getElementById("jumpBtn"),
    ].filter(Boolean);
  },

  switchTab(tab, opts) {
    if (!this._wired) this.init();
    const tabbar = this.tabbar || document.getElementById("tabbar");
    const viewRead = this.viewRead || document.getElementById("scroller");
    const viewTogether =
      this.viewTogether || document.getElementById("togetherView");
    const viewYou = this.viewYou || document.getElementById("youView");
    if (!tabbar || !viewTogether || !viewYou) return;

    tabbar.querySelectorAll(".tabbar-btn").forEach((btn) => {
      btn.classList.toggle("is-active", btn.dataset.tab === tab);
    });
    if (viewRead) viewRead.hidden = tab !== "read";
    viewTogether.hidden = tab !== "together";
    viewYou.hidden = tab !== "you";
    (this.readOnlyEls || []).forEach((el) => {
      el.style.display = tab === "read" ? "" : "none";
    });
    const logout = document.getElementById("logoutBtn");
    if (logout && !logout.hidden) {
      logout.style.display = tab === "read" ? "" : "none";
    }
    if (this._state.unsubscribe && tab !== "together") {
      this._state.unsubscribe();
      this._state.unsubscribe = null;
    }
    if (tab !== "together") this._stopInvitePoll();
    if (opts && opts.skipRender) return;
    if (tab === "together") this.renderHome();
    if (tab === "you") this.renderYou();
  },

  _stopInvitePoll() {
    if (this._state.invitePoll) {
      clearInterval(this._state.invitePoll);
      this._state.invitePoll = null;
    }
  },

  async renderHome() {
    this._state.view = "list";
    this._stopInvitePoll();
    const root = this.viewTogether;
    root.innerHTML = "";
    root.appendChild(
      togetherEl(
        "div",
        "tg-scroll",
        `
        <div class="tg-header">
          <h1 class="tg-title">Together</h1>
          <p class="tg-subtitle">Proponha um capítulo para ler com um(a) amigo(a). Deixem reflexões um para o outro. Cada um no seu ritmo.</p>
        </div>
        <p class="tg-eyebrow">Ativos</p>
        <div class="tg-session-list" id="tgSessionList"><div class="tg-loading">Carregando…</div></div>
        <button class="tg-new-btn" id="tgStartNew" type="button">
          <span class="tg-plus">+</span> Iniciar nova leitura
        </button>
        <div class="tg-howitworks">
          <p class="tg-how-title">Como funciona</p>
          <div class="tg-how-item"><span class="tg-how-num">1</span><p>Escolha um capítulo e proponha para um(a) amigo(a).</p></div>
          <div class="tg-how-item"><span class="tg-how-num">2</span><p>Cada um lê no seu ritmo, versículo por versículo.</p></div>
          <div class="tg-how-item"><span class="tg-how-num">3</span><p>Deixem reflexões pelo caminho — vocês veem a do outro quando chegam lá.</p></div>
        </div>
      `,
      ),
    );
    root.querySelector("#tgStartNew").addEventListener("click", () => {
      this._state.draft = {};
      this.renderNewSession();
    });

    try {
      const [sessions, me] = await Promise.all([
        window.TogetherDB.listMySessions(),
        window.TogetherDB.getMyProfile(),
      ]);
      this._state.currentUserId = me.id;
      const list = root.querySelector("#tgSessionList");
      if (!sessions.length) {
        list.innerHTML = `<p class="tg-empty">Nenhuma leitura em conjunto ainda. Comece uma abaixo ✨</p>`;
        return;
      }
      list.innerHTML = "";
      sessions.forEach((session) =>
        list.appendChild(this._sessionCard(session, me.id)),
      );
    } catch (e) {
      console.error(e);
      root.querySelector("#tgSessionList").innerHTML =
        '<p class="tg-empty">Não foi possível carregar suas leituras agora.</p>';
    }
  },

  _sessionCard(session, myId) {
    const participants = session.together_participants || [];
    const other = participants.find((p) => p.user_id !== myId);
    const mine = participants.find((p) => p.user_id === myId);
    const otherName = other?.profiles?.display_name || "Aguardando amigo(a)";
    const total = session.total_verses || 1;

    const card = togetherEl("div", "tg-card");
    card.innerHTML = `
      <div class="tg-card-head">
        <div class="tg-avatar">${togetherInitials(otherName)}</div>
        <div class="tg-card-head-text">
          <p class="tg-card-name">${otherName}</p>
          <p class="tg-card-meta">${session.created_by === myId ? "Proposto por você" : `Proposto por ${otherName}`} · ${togetherTimeAgo(session.created_at)}</p>
        </div>
        <div class="tg-card-ref">
          <p class="tg-card-ref-title">${session.title}</p>
          <p class="tg-card-ref-sub">${session.translation}</p>
        </div>
      </div>
      <div class="tg-progress-rows">
        ${this._progressRow("Você", mine?.current_verse || 0, total, "gold")}
        ${this._progressRow(otherName.split(" ")[0], other?.current_verse || 0, total, "green")}
      </div>
      <div class="tg-card-foot">
        <div>
          <p class="tg-card-foot-title">Continue de onde parou</p>
        </div>
        <span class="tg-continue">Continuar →</span>
      </div>
    `;
    card.addEventListener("click", () => this.renderSession(session.id));
    return card;
  },

  _progressRow(label, value, total, color) {
    const pct = Math.max(0, Math.min(1, total ? value / total : 0));
    const dots = Array.from({ length: 12 }, (_, i) => {
      const filled = i < Math.round(pct * 12);
      return `<span class="tg-dot ${filled ? `tg-dot-${color}` : ""}"></span>`;
    }).join("");
    return `
      <div class="tg-progress-row">
        <span class="tg-progress-label">${label}</span>
        <span class="tg-progress-dots">${dots}</span>
        <span class="tg-progress-count tg-count-${color}">${value}/${total}</span>
      </div>
    `;
  },

  // ------------------------------------------------------------------
  // Nova leitura: escolher livro + capítulo
  // ------------------------------------------------------------------
  renderNewSession() {
    this._state.view = "new-session";
    const root = this.viewTogether;
    const draft = this._state.draft;
    if (!draft.bookUsfm) draft.bookUsfm = "GEN";
    const selectedBook = draft.bookUsfm;
    const selectedChapter = draft.chapter || null;

    root.innerHTML = "";
    const wrap = togetherEl("div", "tg-scroll");
    wrap.innerHTML = `
      <button class="tg-back" id="tgBack" type="button">‹ Voltar</button>
      <p class="tg-eyebrow tg-eyebrow-gold">Nova leitura</p>
      <h2 class="tg-h2">O que vocês vão ler juntos?</h2>
      <p class="tg-label">Livro</p>
      <div class="tg-pill-grid" id="tgBookGrid"></div>
      <p class="tg-label" id="tgChapterLabel" ${selectedBook ? "" : "hidden"}>Capítulo</p>
      <div class="tg-chapter-grid" id="tgChapterGrid"></div>
      <div class="tg-selected-card" id="tgSelectedCard" hidden></div>
      <div class="tg-cta-bar">
        <button class="tg-cta" id="tgChooseFriend" disabled>Escolher amigo(a) →</button>
      </div>
    `;
    root.appendChild(wrap);

    root
      .querySelector("#tgBack")
      .addEventListener("click", () => this.renderHome());

    const bookGrid = root.querySelector("#tgBookGrid");
    TOGETHER_BOOKS.forEach((book) => {
      const btn = togetherEl(
        "button",
        `tg-pill ${book.usfm === selectedBook ? "is-selected" : ""} ${book.enabled ? "" : "is-disabled"}`,
        book.name,
      );
      btn.type = "button";
      btn.disabled = !book.enabled;
      btn.title = book.enabled ? "" : "Em breve";
      btn.addEventListener("click", () => {
        draft.bookUsfm = book.usfm;
        draft.chapter = null;
        this.renderNewSession();
      });
      bookGrid.appendChild(btn);
    });

    const book = TOGETHER_BOOKS.find((b) => b.usfm === selectedBook);
    const chapterGrid = root.querySelector("#tgChapterGrid");
    if (book) {
      Array.from({ length: book.chapters }, (_, i) => i + 1).forEach((n) => {
        const btn = togetherEl(
          "button",
          `tg-chapter-btn ${n === selectedChapter ? "is-selected" : ""}`,
          String(n),
        );
        btn.type = "button";
        btn.addEventListener("click", () => {
          draft.chapter = n;
          this.renderNewSession();
        });
        chapterGrid.appendChild(btn);
      });
    }

    const selectedCard = root.querySelector("#tgSelectedCard");
    const ctaBtn = root.querySelector("#tgChooseFriend");
    if (book && selectedChapter) {
      const subtitle =
        book.usfm === "GEN" ? GENESIS_SUBTITLES[selectedChapter - 1] : "";
      selectedCard.hidden = false;
      selectedCard.innerHTML = `
        <p class="tg-selected-title">${book.name} ${selectedChapter}</p>
        <p class="tg-selected-sub">${book.name} ${selectedChapter}${subtitle ? ` — ${subtitle}` : ""}</p>
      `;
      ctaBtn.disabled = false;
      ctaBtn.addEventListener("click", () => {
        this._prepareInviteSession();
        this.renderChooseFriend();
      });
    }
  },

  // ------------------------------------------------------------------
  // Escolher amigo(a)
  // ------------------------------------------------------------------
  async renderChooseFriend() {
    this._state.view = "choose-friend";
    this._prepareInviteSession();
    const root = this.viewTogether;
    root.innerHTML = "";
    const wrap = togetherEl("div", "tg-scroll");
    wrap.innerHTML = `
      <button class="tg-back" id="tgBack" type="button">‹ Voltar</button>
      <p class="tg-eyebrow tg-eyebrow-gold">Nova leitura</p>
      <h2 class="tg-h2">Com quem você vai ler?</h2>
      <div class="tg-friend-list" id="tgFriendList"><div class="tg-loading">Carregando amigos…</div></div>
      <div class="tg-cta-bar" id="tgCtaBar">
        <button class="tg-cta" id="tgShareInvite" type="button">Compartilhar</button>
        <button class="tg-cta" id="tgConfirm" disabled hidden>Iniciar leitura em conjunto →</button>
      </div>
    `;
    root.appendChild(wrap);
    root
      .querySelector("#tgBack")
      .addEventListener("click", () => this.renderNewSession());

    let selectedFriendId = null;
    const confirmBtn = root.querySelector("#tgConfirm");
    const shareBtn = root.querySelector("#tgShareInvite");
    confirmBtn.addEventListener("click", () =>
      this._createSessionAndOpen(selectedFriendId),
    );
    shareBtn.addEventListener("click", () => this._shareInviteAndOpen());

    try {
      const friends = await window.TogetherDB.listFriends();
      const list = root.querySelector("#tgFriendList");
      list.innerHTML = "";
      if (!friends.length) {
        list.innerHTML = `
          <div class="tg-invite-empty">
            <p class="tg-empty tg-empty-inline">Você ainda não tem amigos(as) adicionados. Envie um link de convite para lerem este capítulo juntos.</p>
          </div>`;
      } else {
        shareBtn.classList.add("tg-cta-secondary");
        shareBtn.textContent = "Ou compartilhar";
        friends.forEach((friend) => {
          const row = togetherEl(
            "button",
            "tg-friend-row",
            `<span class="tg-avatar tg-avatar-sm">${togetherInitials(friend.display_name)}</span>
             <span class="tg-friend-name">${friend.display_name}</span>
             <span class="tg-friend-check">✓</span>`,
          );
          row.type = "button";
          row.addEventListener("click", () => {
            selectedFriendId = friend.id;
            list
              .querySelectorAll(".tg-friend-row")
              .forEach((r) => r.classList.remove("is-selected"));
            row.classList.add("is-selected");
            confirmBtn.hidden = false;
            confirmBtn.disabled = false;
            shareBtn.classList.add("tg-cta-secondary");
            shareBtn.textContent = "Ou compartilhar";
          });
          list.appendChild(row);
        });
        const hint = togetherEl(
          "p",
          "tg-invite-hint",
          "Ou envie um link de convite se a pessoa ainda não está na sua lista.",
        );
        list.appendChild(hint);
      }
    } catch (e) {
      console.error(e);
      root.querySelector("#tgFriendList").innerHTML =
        '<p class="tg-empty">Não foi possível carregar seus amigos. Você ainda pode convidar por link.</p>';
    }
  },

  async _createSessionRecord(friendId) {
    const draft = this._state.draft;
    const book = TOGETHER_BOOKS.find((b) => b.usfm === draft.bookUsfm);
    if (!book || !draft.chapter) return null;
    const subtitle =
      book.usfm === "GEN" ? GENESIS_SUBTITLES[draft.chapter - 1] : "";
    return window.TogetherDB.createSession({
      bookUsfm: book.usfm,
      bookName: book.name,
      chapter: draft.chapter,
      title: `${book.name} ${draft.chapter}`,
      subtitle,
      translation: "NVI",
      totalVerses: togetherVerseCount(book.usfm, draft.chapter),
      friendId,
    });
  },

  async _createSessionAndOpen(friendId) {
    const confirmBtn = document.getElementById("tgConfirm");
    if (confirmBtn) {
      confirmBtn.disabled = true;
      confirmBtn.textContent = "Criando…";
    }
    try {
      const session = await this._createSessionRecord(friendId);
      if (!session) return;
      showToast(`Leitura de ${session.title} criada!`);
      this._state.draft = {};
      this.renderSession(session.id);
    } catch (e) {
      console.error(e);
      showToast("Não foi possível criar a leitura. Tente de novo.");
      if (confirmBtn) {
        confirmBtn.disabled = false;
        confirmBtn.textContent = "Iniciar leitura em conjunto →";
      }
    }
  },

  _prepareInviteSession() {
    const draft = this._state.draft;
    const key = `${draft.bookUsfm || ""}:${draft.chapter || ""}`;
    if (this._state.invitePrepKey === key && this._state.invitePrep) {
      return this._state.invitePrep;
    }
    this._state.invitePrepKey = key;
    this._state.pendingInvite = null;
    this._state.invitePrep = this._createSessionRecord(null)
      .then((session) => {
        this._state.pendingInvite = session;
        return session;
      })
      .catch((err) => {
        this._state.invitePrep = null;
        this._state.invitePrepKey = null;
        throw err;
      });
    return this._state.invitePrep;
  },

  async _shareInviteAndOpen() {
    const shareBtn = document.getElementById("tgShareInvite");
    const restoreShareLabel = () => {
      if (!shareBtn) return;
      shareBtn.disabled = false;
      shareBtn.textContent = shareBtn.classList.contains("tg-cta-secondary")
        ? "Ou compartilhar"
        : "Compartilhar";
    };
    try {
      let session = this._state.pendingInvite;
      if (!session) {
        if (shareBtn) {
          shareBtn.disabled = true;
          shareBtn.textContent = "Criando convite…";
        }
        session = await this._prepareInviteSession();
      }
      if (!session) {
        showToast("Escolha um capítulo primeiro.");
        restoreShareLabel();
        return;
      }
      const url = window.TogetherDB.inviteUrlForSession(session.id);
      shareTogetherInvite(url, session.title);
      this._state.draft = {};
      this._state.pendingInvite = session;
      this.renderSession(session.id);
    } catch (e) {
      console.error(e);
      showToast("Não foi possível criar o convite. Tente de novo.");
      restoreShareLabel();
    }
  },

  async openInviteLink(sessionId) {
    this.switchTab("together", { skipRender: true });
    const root = this.viewTogether || document.getElementById("togetherView");
    if (root) {
      root.innerHTML =
        '<div class="tg-loading tg-loading-full">Entrando na leitura…</div>';
    }
    try {
      const session = await window.TogetherDB.joinSession(sessionId);
      showToast("Vocês estão conectados! Bora ler ✨");
      this.renderSession(session.id);
    } catch (e) {
      console.error(e);
      showToast("Não foi possível entrar neste convite.");
      this.renderHome();
    }
  },

  // ------------------------------------------------------------------
  // Sessão de leitura em conjunto
  // ------------------------------------------------------------------
  async renderSession(sessionId) {
    this._state.view = "session";
    this._stopInvitePoll();
    if (this._state.unsubscribe) {
      this._state.unsubscribe();
      this._state.unsubscribe = null;
    }
    const root = this.viewTogether;
    root.innerHTML =
      '<div class="tg-loading tg-loading-full">Carregando leitura…</div>';

    let session, me, reflections;
    try {
      [session, me, reflections] = await Promise.all([
        window.TogetherDB.getSession(sessionId),
        window.TogetherDB.getMyProfile(),
        window.TogetherDB.listReflections(sessionId),
      ]);
    } catch (e) {
      console.error(e);
      root.innerHTML =
        '<p class="tg-empty tg-empty-full">Não foi possível carregar esta leitura.</p>';
      return;
    }

    const chapterData = await Promise.race([
      BibleSource.getChapter(`${session.book_usfm}.${session.chapter}`).catch(
        () => ({ verses: [] }),
      ),
      new Promise((resolve) => setTimeout(() => resolve({ verses: [] }), 2500)),
    ]);

    this._renderSessionBody(session, me, chapterData, reflections);

    this._state.unsubscribe = window.TogetherDB.subscribeToSession(
      sessionId,
      async () => {
        const [freshSession, freshReflections] = await Promise.all([
          window.TogetherDB.getSession(sessionId),
          window.TogetherDB.listReflections(sessionId),
        ]);
        this._renderSessionBody(
          freshSession,
          me,
          chapterData,
          freshReflections,
        );
      },
    );
    const waitingForInvitee = !(session.together_participants || []).some(
      (p) => p.user_id !== me.id,
    );
    if (waitingForInvitee) this._watchForInvitee(sessionId, me.id);
  },

  _renderSessionBody(session, me, chapterData, reflections) {
    const root = this.viewTogether;
    const participants = session.together_participants || [];
    const mine = participants.find((p) => p.user_id === me.id);
    const other = participants.find((p) => p.user_id !== me.id);
    const otherName =
      other?.profiles?.display_name || (other ? "amigo(a)" : "convidado(a)");
    const waiting = !other;
    const total = session.total_verses || chapterData.verses.length || 1;
    const currentVerseNum = Math.max(1, mine?.current_verse || 1);
    const verse = chapterData.verses.find(
      (v) => v.number === currentVerseNum,
    ) ||
      chapterData.verses[currentVerseNum - 1] || {
        number: currentVerseNum,
        text: "",
      };
    const verseReflections = reflections.filter(
      (r) => r.verse_number === currentVerseNum,
    );

    root.innerHTML = "";
    const wrap = togetherEl("div", "tg-scroll tg-session-scroll");
    wrap.innerHTML = `
      <button class="tg-back" id="tgBack" type="button">‹ Voltar</button>
      <div class="tg-session-head">
        <span class="tg-avatar tg-avatar-sm">${togetherInitials(waiting ? "?" : otherName)}</span>
        <h2 class="tg-session-title">${waiting ? session.title : `${session.title} com ${otherName.split(" ")[0]}`}</h2>
      </div>
      ${
        waiting
          ? `<p class="tg-invite-waiting">Aguardando alguém entrar pelo link de convite.</p>
        <button class="tg-cta tg-cta-session-share" id="tgSessionShare" type="button">Compartilhar</button>`
          : ""
      }
      <div class="tg-progress-rows tg-progress-rows-session">
        ${this._progressRow("Você", mine?.current_verse || 0, total, "gold")}
        ${this._progressRow(otherName.split(" ")[0], other?.current_verse || 0, total, "green")}
      </div>
      <div class="tg-verse-meta">
        <span>${session.book_name.toUpperCase()} • ${session.chapter}:${verse.number}</span>
        <span>${session.translation}</span>
      </div>
      <p class="tg-verse-text">${verse.text || (chapterData.verses && chapterData.verses.length ? "Fim do capítulo. Deixe uma reflexão para seu(sua) amigo(a) 🙌" : "O texto do capítulo aparece em instantes.")}</p>
      <div class="tg-verse-nav">
        <button class="tg-verse-btn" id="tgPrevVerse" ${currentVerseNum <= 1 ? "disabled" : ""}>← Anterior</button>
        <button class="tg-verse-btn tg-verse-btn-primary" id="tgNextVerse" ${currentVerseNum >= total ? "disabled" : ""}>Próximo →</button>
      </div>
      <div class="tg-reflections">
        <p class="tg-how-title">Reflexões · versículo ${verse.number}</p>
        <div class="tg-reflection-list" id="tgReflectionList"></div>
        <textarea class="tg-reflection-input" id="tgReflectionInput" placeholder="Deixe uma reflexão para ${otherName.split(" ")[0]} sobre este versículo…" maxlength="2000"></textarea>
        <button class="tg-reflection-submit" id="tgReflectionSubmit">Publicar reflexão</button>
      </div>
    `;
    root.appendChild(wrap);

    root
      .querySelector("#tgBack")
      .addEventListener("click", () => this.renderHome());
    const sessionShareBtn = root.querySelector("#tgSessionShare");
    if (sessionShareBtn) {
      sessionShareBtn.addEventListener("click", () => {
        const url = window.TogetherDB.inviteUrlForSession(session.id);
        shareTogetherInvite(url, session.title);
      });
    }

    const reflList = root.querySelector("#tgReflectionList");
    if (!verseReflections.length) {
      reflList.innerHTML =
        '<p class="tg-empty tg-empty-inline">Nenhuma reflexão ainda neste versículo.</p>';
    } else {
      verseReflections.forEach((r) => {
        const row = togetherEl(
          "div",
          "tg-reflection-item",
          `<span class="tg-avatar tg-avatar-xs">${togetherInitials(r.profiles?.display_name)}</span>
           <div><p class="tg-reflection-author">${r.profiles?.display_name || "?"} <span class="tg-reflection-time">${togetherTimeAgo(r.created_at)}</span></p>
           <p class="tg-reflection-body">${r.body}</p></div>`,
        );
        reflList.appendChild(row);
      });
    }

    root.querySelector("#tgPrevVerse").addEventListener("click", async () => {
      await window.TogetherDB.updateMyProgress(session.id, currentVerseNum - 1);
      this.renderSession(session.id);
    });
    root.querySelector("#tgNextVerse").addEventListener("click", async () => {
      await window.TogetherDB.updateMyProgress(session.id, currentVerseNum + 1);
      // showToast("+2 pontos ✨");
      this.renderSession(session.id);
    });
    root
      .querySelector("#tgReflectionSubmit")
      .addEventListener("click", async () => {
        const input = root.querySelector("#tgReflectionInput");
        const body = input.value.trim();
        if (!body) return;
        try {
          await window.TogetherDB.addReflection(
            session.id,
            currentVerseNum,
            body,
          );
          // showToast("Reflexão publicada. +5 pontos ✨");
          input.value = "";
          this.renderSession(session.id);
        } catch (e) {
          console.error(e);
          showToast("Não foi possível publicar a reflexão.");
        }
      });
  },

  _watchForInvitee(sessionId, myId) {
    this._stopInvitePoll();
    this._state.invitePoll = setInterval(async () => {
      if (this._state.view !== "session") {
        this._stopInvitePoll();
        return;
      }
      try {
        const fresh = await window.TogetherDB.getSession(sessionId);
        const hasOther = (fresh.together_participants || []).some(
          (p) => p.user_id !== myId,
        );
        if (hasOther) {
          this._stopInvitePoll();
          showToast("Seu convite foi aceito!");
          this.renderSession(sessionId);
        }
      } catch (_) {}
    }, 3000);
  },

  // ------------------------------------------------------------------
  // Aba "You": perfil, streak/pontos, amigos
  // ------------------------------------------------------------------
  async renderYou() {
    const root = this.viewYou;
    root.innerHTML =
      '<div class="tg-loading tg-loading-full">Carregando perfil…</div>';
    try {
      const [profile, stats, incoming, friends] = await Promise.all([
        window.TogetherDB.getMyProfile({ fresh: true }),
        window.TogetherDB.getMyStats(),
        window.TogetherDB.listIncomingRequests(),
        window.TogetherDB.listFriends(),
      ]);

      root.innerHTML = "";
      const wrap = togetherEl("div", "tg-scroll");
      wrap.innerHTML = `
        <div class="tg-header">
          <h1 class="tg-title">You</h1>
          <p class="tg-subtitle">${profile.is_anonymous ? "Continue sem conta — conecte com YouVersion para sincronizar entre dispositivos." : `Conectado(a) com YouVersion como ${profile.youversion_email || profile.display_name}.`}</p>
        </div>
        <div class="tg-you-card">
          <div class="tg-you-row">
            <span class="tg-avatar">${togetherInitials(profile.display_name)}</span>
            <div>
              <p class="tg-card-name">${profile.display_name}</p>
              <p class="tg-card-meta">@${profile.username || "sem-usuario"}</p>
            </div>
          </div>
          <div class="tg-stats-row">
            <div class="tg-stat"><p class="tg-stat-value">${stats.total_points}</p><p class="tg-stat-label">pontos</p></div>
            <div class="tg-stat"><p class="tg-stat-value">${stats.current_streak}🔥</p><p class="tg-stat-label">sequência</p></div>
            <div class="tg-stat"><p class="tg-stat-value">${stats.longest_streak}</p><p class="tg-stat-label">recorde</p></div>
          </div>
        </div>
        <p class="tg-label">Seu usuário (para amigos te encontrarem)</p>
        <div class="tg-username-row">
          <input class="tg-username-input" id="tgUsernameInput" value="${profile.username || ""}" placeholder="seu-usuario" />
          <button class="tg-username-save" id="tgUsernameSave">Salvar</button>
        </div>
        <p class="tg-label">Adicionar amigo(a)</p>
        <div class="tg-username-row">
          <input class="tg-username-input" id="tgFriendSearch" placeholder="Buscar por usuário…" />
        </div>
        <div id="tgFriendResults" class="tg-friend-list"></div>
        ${incoming.length ? `<p class="tg-label">Pedidos recebidos</p><div class="tg-friend-list" id="tgIncomingList"></div>` : ""}
        <p class="tg-label">Seus amigos (${friends.length})</p>
        <div class="tg-friend-list" id="tgFriendsList">
          ${friends.length ? "" : '<p class="tg-empty tg-empty-inline">Nenhum amigo ainda.</p>'}
        </div>
      `;
      root.appendChild(wrap);

      friends.forEach((f) => {
        const row = togetherEl(
          "div",
          "tg-friend-row tg-friend-row-static",
          `<span class="tg-avatar tg-avatar-sm">${togetherInitials(f.display_name)}</span><span class="tg-friend-name">${f.display_name}</span>`,
        );
        root.querySelector("#tgFriendsList").appendChild(row);
      });

      if (incoming.length) {
        const box = root.querySelector("#tgIncomingList");
        incoming.forEach((req) => {
          const row = togetherEl(
            "div",
            "tg-friend-row tg-friend-row-static",
            `<span class="tg-avatar tg-avatar-sm">${togetherInitials(req.requester?.display_name)}</span>
             <span class="tg-friend-name">${req.requester?.display_name}</span>
             <button class="tg-accept-btn" data-id="${req.id}">Aceitar</button>`,
          );
          row
            .querySelector(".tg-accept-btn")
            .addEventListener("click", async (ev) => {
              ev.stopPropagation();
              await window.TogetherDB.respondFriendRequest(req.id, true);
              showToast("Amizade aceita!");
              this.renderYou();
            });
          box.appendChild(row);
        });
      }

      root
        .querySelector("#tgUsernameSave")
        .addEventListener("click", async () => {
          const val = root.querySelector("#tgUsernameInput").value;
          try {
            await window.TogetherDB.setUsername(val);
            showToast("Usuário atualizado!");
          } catch (e) {
            showToast(e.message || "Não foi possível salvar o usuário.");
          }
        });

      const searchInput = root.querySelector("#tgFriendSearch");
      const resultsBox = root.querySelector("#tgFriendResults");
      let searchTimer = null;
      searchInput.addEventListener("input", () => {
        clearTimeout(searchTimer);
        searchTimer = setTimeout(async () => {
          const q = searchInput.value.trim();
          if (!q) {
            resultsBox.innerHTML = "";
            return;
          }
          const results = await window.TogetherDB.searchProfiles(q);
          resultsBox.innerHTML = "";
          results.forEach((p) => {
            const row = togetherEl(
              "div",
              "tg-friend-row tg-friend-row-static",
              `<span class="tg-avatar tg-avatar-sm">${togetherInitials(p.display_name)}</span>
               <span class="tg-friend-name">${p.display_name} <span class="tg-card-meta">@${p.username}</span></span>
               <button class="tg-accept-btn" data-id="${p.id}">Adicionar</button>`,
            );
            row
              .querySelector(".tg-accept-btn")
              .addEventListener("click", async (ev) => {
                ev.stopPropagation();
                try {
                  await window.TogetherDB.sendFriendRequest(p.id);
                  showToast("Pedido de amizade enviado!");
                  resultsBox.innerHTML = "";
                  searchInput.value = "";
                } catch (e) {
                  showToast("Não foi possível enviar o pedido.");
                }
              });
            resultsBox.appendChild(row);
          });
        }, 350);
      });
    } catch (e) {
      console.error(e);
      root.innerHTML =
        '<p class="tg-empty tg-empty-full">Não foi possível carregar seu perfil agora.</p>';
    }
  },
};

window.Together = Together;
Together.init();
