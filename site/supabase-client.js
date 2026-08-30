/* =========================================================================
   SUPABASE + TOGETHER DATA LAYER
   ---------------------------------------------------------------------
   Arquitetura de auth:
     A YouVersion não é um provedor OAuth nativo do Supabase Auth, então
     não dá pra usar `signInWithOAuth`. Em vez disso:

       1. O usuário faz login com YouVersion normalmente (PKCE, já existe
          em script.js). Isso nos dá um `id_token` (JWT) com claims
          (sub, email, name, picture).
       2. Cada dispositivo ganha um UUID estável em localStorage
          (`together_local_uid_v1`), enviado no header `x-together-user-id`.
          RLS usa `together_uid()` (auth.uid() ou esse header).
       3. Quando o login YouVersion é concluído, decodificamos o
          `id_token` e vinculamos o perfil preenchendo
          `profiles.youversion_sub/email/display_name/avatar`.
   ========================================================================= */

const SUPABASE_URL = "https://yllrfrejlhinwtambpmr.supabase.co";
const SUPABASE_ANON_KEY =
  "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJzdXBhYmFzZSIsInJlZiI6InlsbHJmcmVqbGhpbnd0YW1icG1yIiwicm9sZSI6ImFub24iLCJpYXQiOjE3ODgwNDczNTMsImV4cCI6MjEwMzYyMzM1M30.w8l68aGIHKHtT87eQl19fGDVWHU1-0aqpE19kTwIVss";

const TOGETHER_LOCAL_UID_KEY = "together_local_uid_v1";

function getOrCreateLocalTogetherUid() {
  try {
    let id = localStorage.getItem(TOGETHER_LOCAL_UID_KEY);
    if (!id) {
      id = crypto.randomUUID();
      localStorage.setItem(TOGETHER_LOCAL_UID_KEY, id);
    }
    return id;
  } catch (_) {
    return crypto.randomUUID();
  }
}

const localTogetherUid = getOrCreateLocalTogetherUid();

const supabaseClient = window.supabase.createClient(
  SUPABASE_URL,
  SUPABASE_ANON_KEY,
  {
    auth: {
      persistSession: true,
      autoRefreshToken: true,
      detectSessionInUrl: false,
    },
    global: {
      headers: {
        "x-together-user-id": localTogetherUid,
      },
    },
  },
);

function slugifyUsername(seed) {
  const base = String(seed || "leitor")
    .normalize("NFD")
    .replace(/[\u0300-\u036f]/g, "")
    .toLowerCase()
    .replace(/[^a-z0-9]+/g, "")
    .slice(0, 16);
  const suffix = Math.random().toString(36).slice(2, 6);
  return `${base || "leitor"}${suffix}`;
}

const TogetherDB = {
  _profileCache: null,
  _ensurePromise: null,

  /**
   * Garante que existe uma sessão Supabase (anônima ou vinculada) e uma
   * linha em `profiles`. Idempotente — pode ser chamado várias vezes.
   */
  async ensureSession() {
    if (this._ensurePromise) return this._ensurePromise;
    this._ensurePromise = (async () => {
      let user = { id: localTogetherUid };
      try {
        const { data } = await supabaseClient.auth.getSession();
        if (data && data.session && data.session.user) {
          user = data.session.user;
        }
      } catch (_) {}
      await this._ensureProfileRow(user);
      return user;
    })();
    try {
      return await this._ensurePromise;
    } finally {
      this._ensurePromise = null;
    }
  },

  async _ensureProfileRow(user) {
    const { data: existing } = await supabaseClient
      .from("profiles")
      .select("*")
      .eq("id", user.id)
      .maybeSingle();
    if (existing) {
      this._profileCache = existing;
      return existing;
    }
    const insertRow = {
      id: user.id,
      display_name: "Leitor(a)",
      username: slugifyUsername("leitor"),
      is_anonymous: true,
    };
    const { data: created, error } = await supabaseClient
      .from("profiles")
      .insert(insertRow)
      .select("*")
      .single();
    if (error) throw error;
    this._profileCache = created;
    return created;
  },

  async getMyProfile({ fresh } = {}) {
    if (this._profileCache && !fresh) return this._profileCache;
    const user = await this.ensureSession();
    const { data, error } = await supabaseClient
      .from("profiles")
      .select("*")
      .eq("id", user.id)
      .single();
    if (error) throw error;
    this._profileCache = data;
    return data;
  },

  /**
   * Chamado depois que o login YouVersion termina (script.js). Recebe as
   * claims decodificadas do id_token e vincula ao perfil Supabase atual.
   */
  async linkYouVersionProfile(claims) {
    if (!claims) return null;
    const user = await this.ensureSession();
    const displayName =
      claims.name ||
      [claims.given_name, claims.family_name].filter(Boolean).join(" ") ||
      (claims.email ? claims.email.split("@")[0] : null) ||
      "Leitor(a)";
    const patch = {
      youversion_sub: claims.sub || null,
      youversion_email: claims.email || null,
      display_name: displayName,
      avatar_url: claims.picture || null,
      is_anonymous: false,
    };
    const { data, error } = await supabaseClient
      .from("profiles")
      .update(patch)
      .eq("id", user.id)
      .select("*")
      .single();
    if (error) {
      // youversion_sub já usado por outro perfil (ex: mesmo usuário logou
      // em outro dispositivo antes) — não é fatal, mantemos perfil local.
      console.warn("[Together] linkYouVersionProfile falhou:", error.message);
      return null;
    }
    this._profileCache = data;
    return data;
  },

  async setUsername(username) {
    const user = await this.ensureSession();
    const clean = String(username || "")
      .trim()
      .toLowerCase()
      .replace(/[^a-z0-9_.]/g, "");
    if (!clean) throw new Error("Nome de usuário inválido.");
    const { data, error } = await supabaseClient
      .from("profiles")
      .update({ username: clean })
      .eq("id", user.id)
      .select("*")
      .single();
    if (error) throw error;
    this._profileCache = data;
    return data;
  },

  async getMyStats() {
    const user = await this.ensureSession();
    const { data, error } = await supabaseClient
      .from("user_stats")
      .select("*")
      .eq("user_id", user.id)
      .maybeSingle();
    if (error) throw error;
    return (
      data || {
        user_id: user.id,
        total_points: 0,
        current_streak: 0,
        longest_streak: 0,
      }
    );
  },

  // ------------------------------------------------------------------
  // Amigos
  // ------------------------------------------------------------------
  async searchProfiles(query) {
    const user = await this.ensureSession();
    const clean = String(query || "").trim();
    if (!clean) return [];
    const { data, error } = await supabaseClient
      .from("profiles")
      .select("id, username, display_name, avatar_url")
      .neq("id", user.id)
      .ilike("username", `%${clean}%`)
      .limit(10);
    if (error) throw error;
    return data || [];
  },

  async sendFriendRequest(addresseeId) {
    const user = await this.ensureSession();
    const { data, error } = await supabaseClient
      .from("friendships")
      .insert({ requester_id: user.id, addressee_id: addresseeId })
      .select("*")
      .single();
    if (error) throw error;
    return data;
  },

  async ensureFriendship(otherUserId) {
    const user = await this.ensureSession();
    if (!otherUserId || otherUserId === user.id) return null;
    const { data: existing, error: findErr } = await supabaseClient
      .from("friendships")
      .select("*")
      .or(
        `and(requester_id.eq.${user.id},addressee_id.eq.${otherUserId}),and(requester_id.eq.${otherUserId},addressee_id.eq.${user.id})`,
      )
      .maybeSingle();
    if (findErr) throw findErr;
    if (existing) {
      if (existing.status === "accepted") return existing;
      const { data, error } = await supabaseClient
        .from("friendships")
        .update({ status: "accepted" })
        .eq("id", existing.id)
        .select("*")
        .single();
      if (error) throw error;
      return data;
    }
    const { data, error } = await supabaseClient
      .from("friendships")
      .insert({
        requester_id: user.id,
        addressee_id: otherUserId,
        status: "accepted",
      })
      .select("*")
      .single();
    if (error) throw error;
    return data;
  },

  async respondFriendRequest(friendshipId, accept) {
    const { data, error } = await supabaseClient
      .from("friendships")
      .update({ status: accept ? "accepted" : "declined" })
      .eq("id", friendshipId)
      .select("*")
      .single();
    if (error) throw error;
    return data;
  },

  async listIncomingRequests() {
    const user = await this.ensureSession();
    const { data, error } = await supabaseClient
      .from("friendships")
      .select("*, requester:profiles!friendships_requester_id_fkey(id, username, display_name, avatar_url)")
      .eq("addressee_id", user.id)
      .eq("status", "pending");
    if (error) throw error;
    return data || [];
  },

  async listFriends() {
    const user = await this.ensureSession();
    const { data, error } = await supabaseClient
      .from("friendships")
      .select(
        "*, requester:profiles!friendships_requester_id_fkey(id, username, display_name, avatar_url), addressee:profiles!friendships_addressee_id_fkey(id, username, display_name, avatar_url)",
      )
      .eq("status", "accepted")
      .or(`requester_id.eq.${user.id},addressee_id.eq.${user.id}`);
    if (error) throw error;
    return (data || []).map((row) =>
      row.requester_id === user.id ? row.addressee : row.requester,
    );
  },

  // ------------------------------------------------------------------
  // Sessões "Together"
  // ------------------------------------------------------------------
  async listMySessions() {
    const user = await this.ensureSession();
    const { data, error } = await supabaseClient
      .from("together_sessions")
      .select(
        "*, together_participants(id, user_id, current_verse, status, last_read_at, profiles(id, username, display_name, avatar_url))",
      )
      .order("updated_at", { ascending: false });
    if (error) throw error;
    return (data || []).filter((s) =>
      s.together_participants.some((p) => p.user_id === user.id),
    );
  },

  async createSession({
    bookUsfm,
    bookName,
    chapter,
    title,
    subtitle,
    translation,
    totalVerses,
    friendId,
  }) {
    const user = await this.ensureSession();
    const { data: session, error } = await supabaseClient
      .from("together_sessions")
      .insert({
        book_usfm: bookUsfm,
        book_name: bookName,
        chapter,
        title,
        subtitle: subtitle || null,
        translation: translation || "NIV",
        total_verses: totalVerses || 0,
        created_by: user.id,
      })
      .select("*")
      .single();
    if (error) throw error;

    const participantRows = [
      {
        session_id: session.id,
        user_id: user.id,
        role: "creator",
        status: "active",
        joined_at: new Date().toISOString(),
      },
    ];
    if (friendId) {
      participantRows.push({
        session_id: session.id,
        user_id: friendId,
        role: "invitee",
        status: "invited",
      });
    }
    const { error: partErr } = await supabaseClient
      .from("together_participants")
      .insert(participantRows);
    if (partErr) throw partErr;
    return session;
  },

  inviteUrlForSession(sessionId) {
    const u = new URL(window.location.href);
    u.search = "";
    u.hash = "";
    u.searchParams.set("together", sessionId);
    return u.toString();
  },

  async joinSession(sessionId) {
    const user = await this.ensureSession();
    const { data: existing } = await supabaseClient
      .from("together_participants")
      .select("id")
      .eq("session_id", sessionId)
      .eq("user_id", user.id)
      .maybeSingle();
    if (!existing) {
      const { error: insErr } = await supabaseClient
        .from("together_participants")
        .insert({
          session_id: sessionId,
          user_id: user.id,
          role: "invitee",
          status: "active",
          joined_at: new Date().toISOString(),
        });
      if (insErr && insErr.code !== "23505") throw insErr;
    }
    const session = await this.getSession(sessionId);
    if (session && session.created_by && session.created_by !== user.id) {
      try {
        await this.ensureFriendship(session.created_by);
      } catch (e) {
        console.warn("[Together] amizade no convite:", e);
      }
    }
    return session;
  },

  async getSession(sessionId) {
    const { data, error } = await supabaseClient
      .from("together_sessions")
      .select(
        "*, together_participants(id, user_id, current_verse, status, role, last_read_at, profiles(id, username, display_name, avatar_url))",
      )
      .eq("id", sessionId)
      .single();
    if (error) throw error;
    return data;
  },

  async updateMyProgress(sessionId, currentVerse) {
    const user = await this.ensureSession();
    const { data, error } = await supabaseClient
      .from("together_participants")
      .update({ current_verse: currentVerse })
      .eq("session_id", sessionId)
      .eq("user_id", user.id)
      .select("*")
      .single();
    if (error) throw error;
    return data;
  },

  async listReflections(sessionId) {
    const { data, error } = await supabaseClient
      .from("together_reflections")
      .select("*, profiles(id, username, display_name, avatar_url)")
      .eq("session_id", sessionId)
      .order("created_at", { ascending: true });
    if (error) throw error;
    return data || [];
  },

  async addReflection(sessionId, verseNumber, body) {
    const user = await this.ensureSession();
    const { data, error } = await supabaseClient
      .from("together_reflections")
      .insert({
        session_id: sessionId,
        user_id: user.id,
        verse_number: verseNumber,
        body,
      })
      .select("*, profiles(id, username, display_name, avatar_url)")
      .single();
    if (error) throw error;
    return data;
  },

  subscribeToSession(sessionId, onChange) {
    const channel = supabaseClient
      .channel(`together-session-${sessionId}`)
      .on(
        "postgres_changes",
        {
          event: "*",
          schema: "public",
          table: "together_participants",
          filter: `session_id=eq.${sessionId}`,
        },
        onChange,
      )
      .on(
        "postgres_changes",
        {
          event: "*",
          schema: "public",
          table: "together_reflections",
          filter: `session_id=eq.${sessionId}`,
        },
        onChange,
      )
      .subscribe();
    return () => supabaseClient.removeChannel(channel);
  },
};

window.TogetherDB = TogetherDB;
