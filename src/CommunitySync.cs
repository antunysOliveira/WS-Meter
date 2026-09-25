// CommunitySync — shared cache de nick + classId entre WS-engines
// via Supabase Postgres. Ver docs/superpowers/specs/2026-09-23-community-sync-design.md
//
// Módulo aditivo, thread-safe. Sem cache em disco — backend é a única fonte
// de verdade. Boot faz pull síncrono pra popular RAM. Push loop compara
// mem-local vs snapshot backend e sobe apenas deltas reais (nunca sobrescreve
// info válida com null). Intervals são fixos (5min) e NÃO configuráveis por
// usuário — impede spam via config manual. Soft cap 5000 uploads/hora protege
// backend de client comprometido.

using System;
using System.Collections.Generic;
using System.IO;
using System.Text.RegularExpressions;
using System.Threading;

namespace WSEngine
{
    static class CommunitySync
    {
        // Intervals hardcoded — não configuráveis por usuário. Config numérico
        // é IGNORADO no parse (WS-engine.cs), evita spam via edit manual.
        const int PushIntervalMs = 5 * 60000;
        const int PullIntervalMs = 5 * 60000;
        const int HeartbeatIntervalMs = 5 * 60000;
        const int MaxBatch = 500;
        // Warspear nick max chars — filtro client-side pra bater com CHECK constraint
        // no backend (entities.nick BETWEEN 1 AND 10).
        const int MaxNickLen = 10;
        // Soft cap por sessão: se ultrapassar N uploads na última hora, skip push
        // até rollover. Client comprometido não consegue floodar backend.
        const int MaxUploadsPerHour = 5000;
        static readonly Queue<DateTime> _uploadTimestamps = new Queue<DateTime>();
        static int _pushBackoffMultiplier = 1;
        static DateTime _lastPullAt = DateTime.MinValue;
        static DateTime _lastPushOkAtUtc = DateTime.MinValue;
        static int _pullBackoffMultiplier = 1;

        public class RemoteEntry
        {
            public uint EntityId;
            public string Nick;
            public int ClassId;
            public DateTime UpdatedAt;
            public string ClientId;
        }

        internal class LocalSnapshotEntry
        {
            public string Nick;
            public int ClassId;
        }

        internal class PushEntry
        {
            public uint EntityId;
            public string Nick;
            public int ClassId;
            public string ClientId;
        }

        static readonly object _lock = new object();
        // _cache = snapshot RAM do backend. Sole source of truth pra NameFor/ClassFor
        // via SeedFromCache. Populated no boot pull + refreshed cada pull tick.
        static readonly Dictionary<uint, RemoteEntry> _cache = new Dictionary<uint, RemoteEntry>();
        static string _root, _baseUrl, _anonKey, _clientId, _version;
        static bool _enabled;
        static Thread _pushThread, _pullThread, _hbThread;
        static volatile bool _stopping;

        public static Action OnPullMerged;

        // Callback opcional retornando o set de entity_ids que já foram vistos
        // em pelo menos 1 packet real (chat, tag=25 enter, tag=427 damage, etc).
        // Wire pelo MainForm. PushLoop consulta antes de cada delta pra filtrar
        // structs lixo de memscan (UI text, quest object, mob type struct que
        // casaram no fingerprint mas nunca apareceram em wire real).
        public static Func<HashSet<uint>> PacketConfirmedProvider;

        // Providers pra runtime state (RAM). Populados pelo MainForm em boot.
        // Usados pelo push loop pra pegar nick/class decodados de packet
        // (tag=10, tag=207, tag=551, tag=554) que nunca são persistidos em
        // JSON — memscan file só cobre o que a memory scan pegou. Sem esses,
        // class coverage no backend fica muito baixa.
        public static Func<Dictionary<uint, string>> LiveNameMapProvider;
        public static Func<Dictionary<uint, int>> LivePlayerClassProvider;

        public static int CachedCount { get { lock (_lock) return _cache.Count; } }
        public static string ClientIdForDiag { get { return _clientId ?? "(uninitialized)"; } }
        public static DateTime LastPullAtUtc { get { return _lastPullAt; } }
        public static DateTime LastPushOkAtUtc { get { return _lastPushOkAtUtc; } }
        public static string BackendUrl { get { return _baseUrl; } }
        public static bool Enabled { get { return _enabled; } }

        public static void Init(string root, string url, string anonKey, bool enabled, string version)
        {
            // I2: idempotence — second call while already running is a no-op
            if (_pushThread != null && _pushThread.IsAlive) return;

            _root = root;
            _baseUrl = (url ?? "").TrimEnd('/');
            _anonKey = anonKey ?? "";

            // C1: treat REPLACE_ME sentinel as unconfigured → disable
            bool hasSentinel = _baseUrl.IndexOf("REPLACE_ME", StringComparison.OrdinalIgnoreCase) >= 0
                            || _anonKey.IndexOf("REPLACE_ME", StringComparison.OrdinalIgnoreCase) >= 0;
            if (hasSentinel)
            {
                _enabled = false;
                _version = version ?? "unknown";
                _clientId = ResolveClientId(root);
                PersistLogCommunity("disabled — REPLACE_ME sentinel detected in config, edit ws-engine.config.json to enable");
                return;
            }

            _enabled = enabled && !string.IsNullOrEmpty(_baseUrl) && !string.IsNullOrEmpty(_anonKey);
            _version = version ?? "unknown";
            _clientId = ResolveClientId(root);
            if (!_enabled) return;

            // .NET Framework 4.0 defaults to TLS 1.0/1.1 — modern HTTPS endpoints
            // (Supabase, Cloudflare, most 2024+ CDNs) require TLS 1.2. Force it here.
            // Tls12 enum = 3072 (bit flag), Tls11 = 768, Tls = 192. Use raw int to
            // stay .NET 4.0 SDK compatible even if the enum name isn't present.
            try { System.Net.ServicePointManager.SecurityProtocol = (System.Net.SecurityProtocolType)3072; } catch { }

            // Boot pull síncrono — backend é fonte de verdade, popula RAM antes
            // de MainForm exibir dashboard. Se falhar (net down, backend off),
            // _cache fica vazio e leaderboard degrada pra hex até próximo pull.
            int initial = PullOnce();
            PersistLogCommunity("enabled, client_id=" + _clientId + " backend=" + _baseUrl + " initial_pull=" + initial);

            _stopping = false;
            _pushThread = new Thread(PushLoop) { IsBackground = true, Name = "CommunitySync.Push" };
            _pushThread.Start();
            _pullThread = new Thread(PullLoop) { IsBackground = true, Name = "CommunitySync.Pull" };
            _pullThread.Start();
            _hbThread = new Thread(HeartbeatLoop) { IsBackground = true, Name = "CommunitySync.Heartbeat" };
            _hbThread.Start();
        }

        public static void Stop()
        {
            _stopping = true;
            var threads = new[] { _pushThread, _pullThread, _hbThread };
            foreach (var t in threads)
            {
                if (t != null && t.IsAlive)
                {
                    try { t.Join(2000); } catch { }
                }
            }
        }

        public static bool TryLookup(uint id, out RemoteEntry e)
        {
            e = null;
            if (id == 0) return false;
            lock (_lock) { return _cache.TryGetValue(id, out e); }
        }

        public static void SeedFromCache(Dictionary<uint, string> nameCache, Dictionary<uint, int> classCache)
        {
            lock (_lock)
            {
                foreach (var kv in _cache)
                {
                    if (nameCache != null && !nameCache.ContainsKey(kv.Key) && !string.IsNullOrEmpty(kv.Value.Nick))
                        nameCache[kv.Key] = kv.Value.Nick;
                    if (classCache != null && kv.Value.ClassId > 0)
                    {
                        int existing;
                        if (!classCache.TryGetValue(kv.Key, out existing) || existing <= 0)
                            classCache[kv.Key] = kv.Value.ClassId;
                    }
                }
            }
        }

        // ── Mem-json snapshot loader ─────────────────────────────────────────────

        internal static Dictionary<uint, LocalSnapshotEntry> LoadLocalSnapshotFromMemJsons(string root)
        {
            var result = new Dictionary<uint, LocalSnapshotEntry>();

            // 1. Merge runtime state (RAM). Nick de packet decoders (tag=9,
            //    tag=65, tag=207, tag=551, tag=554) + class de tag=10/551/554
            //    /207. Sem isso, só memscan JSON alimentava o push — perdia
            //    ~95% da class coverage.
            try
            {
                var liveNames = LiveNameMapProvider != null ? LiveNameMapProvider() : null;
                var liveClasses = LivePlayerClassProvider != null ? LivePlayerClassProvider() : null;
                if (liveNames != null)
                {
                    foreach (var kv in liveNames)
                    {
                        if (kv.Key == 0 || string.IsNullOrEmpty(kv.Value)) continue;
                        result[kv.Key] = new LocalSnapshotEntry { Nick = kv.Value, ClassId = 0 };
                    }
                }
                if (liveClasses != null)
                {
                    foreach (var kv in liveClasses)
                    {
                        if (kv.Key == 0 || kv.Value <= 0) continue;
                        LocalSnapshotEntry e;
                        if (result.TryGetValue(kv.Key, out e)) e.ClassId = kv.Value;
                        // Sem nick → não sobe (ComputeDeltaVsRemote skip)
                    }
                }
            }
            catch { }

            // 2. Merge memscan JSONs (baseline: cobre players offline).
            try
            {
                string pPlayers = Path.Combine(root, "ws-engine.mem-players.json");
                if (File.Exists(pPlayers))
                {
                    var rx = new Regex("\"0x([0-9A-Fa-f]+)\"\\s*:\\s*\"([^\"]*)\"");
                    foreach (Match m in rx.Matches(File.ReadAllText(pPlayers)))
                    {
                        uint id = Convert.ToUInt32(m.Groups[1].Value, 16);
                        if (id == 0) continue;
                        string nick = m.Groups[2].Value;
                        if (string.IsNullOrEmpty(nick)) continue;
                        // Não sobrescreve nick de packet (mais confiável)
                        if (!result.ContainsKey(id))
                            result[id] = new LocalSnapshotEntry { Nick = nick, ClassId = 0 };
                    }
                }
                string pClasses = Path.Combine(root, "ws-engine.mem-player-classes.json");
                if (File.Exists(pClasses))
                {
                    var rx = new Regex("\"0x([0-9A-Fa-f]+)\"\\s*:\\s*(\\d+)");
                    foreach (Match m in rx.Matches(File.ReadAllText(pClasses)))
                    {
                        uint id = Convert.ToUInt32(m.Groups[1].Value, 16);
                        int cid = int.Parse(m.Groups[2].Value);
                        LocalSnapshotEntry e;
                        // Só preenche se runtime não tiver; tag=554 no runtime
                        // é autoritativo, memscan pode ter versão antiga.
                        if (result.TryGetValue(id, out e) && e.ClassId <= 0) e.ClassId = cid;
                        // Se class sem nick, ignora — precisamos do nick pra subir.
                    }
                }
            }
            catch { }
            return result;
        }

        // ── Push loop ────────────────────────────────────────────────────────────

        static void PushLoop()
        {
            while (!_stopping)
            {
                try
                {
                    var current = LoadLocalSnapshotFromMemJsons(_root);
                    // Snapshot do _cache sob lock pra evitar race com pull
                    Dictionary<uint, RemoteEntry> remoteSnap;
                    lock (_lock) { remoteSnap = new Dictionary<uint, RemoteEntry>(_cache); }

                    HashSet<uint> confirmed = null;
                    try { if (PacketConfirmedProvider != null) confirmed = PacketConfirmedProvider(); } catch { }
                    var delta = ComputeDeltaVsRemote(current, remoteSnap, _clientId, confirmed);
                    if (delta.Count > 0)
                    {
                        // Soft cap: se ultrapassar limite/hora, cai fora do tick
                        // (evita client comprometido floodar backend)
                        if (!CheckUploadCap(delta.Count))
                        {
                            PersistLogCommunity("push skipped: soft cap " + MaxUploadsPerHour + "/hour reached");
                        }
                        else
                        {
                            // Batch em chunks de MaxBatch
                            for (int off = 0; off < delta.Count; off += MaxBatch)
                            {
                                int take = Math.Min(MaxBatch, delta.Count - off);
                                var chunk = delta.GetRange(off, take);
                                string body = SerializeBatch(chunk);
                                var r = HttpPostJson("entities?on_conflict=entity_id", body,
                                    "resolution=merge-duplicates,return=minimal");
                                if (r.Status >= 200 && r.Status < 300)
                                {
                                    // Sucesso — atualiza _cache local também (evita re-push
                                    // desses mesmos entries no próximo tick antes do pull)
                                    lock (_lock)
                                    {
                                        var nowUtc = DateTime.UtcNow;
                                        foreach (var e in chunk)
                                        {
                                            _cache[e.EntityId] = new RemoteEntry
                                            {
                                                EntityId = e.EntityId,
                                                Nick = e.Nick,
                                                ClassId = e.ClassId,
                                                UpdatedAt = nowUtc,
                                                ClientId = e.ClientId
                                            };
                                        }
                                    }
                                    _lastPushOkAtUtc = DateTime.UtcNow;
                                    _pushBackoffMultiplier = 1;
                                }
                                else
                                {
                                    PersistLogCommunity("push failed: status=" + r.Status + " err=" + (r.Error ?? "?"));
                                    _pushBackoffMultiplier = Math.Min(_pushBackoffMultiplier * 2, 30);
                                    break;   // pula chunks restantes, tenta próximo tick
                                }
                            }
                        }
                    }
                }
                catch (Exception ex)
                {
                    PersistLogCommunity("push exception: " + ex.Message);
                }

                int waitMs = PushIntervalMs * _pushBackoffMultiplier;
                for (int slept = 0; slept < waitMs && !_stopping; slept += 500) Thread.Sleep(500);
            }
        }

        // Soft cap: guarda timestamps dos últimos uploads. Retorna false se
        // adicionar 'count' novos rows estouraria MaxUploadsPerHour na última
        // hora. Chamado do PushLoop antes do POST.
        static bool CheckUploadCap(int count)
        {
            lock (_uploadTimestamps)
            {
                DateTime cutoff = DateTime.UtcNow.AddHours(-1);
                while (_uploadTimestamps.Count > 0 && _uploadTimestamps.Peek() < cutoff)
                    _uploadTimestamps.Dequeue();
                if (_uploadTimestamps.Count + count > MaxUploadsPerHour) return false;
                DateTime now = DateTime.UtcNow;
                for (int i = 0; i < count; i++) _uploadTimestamps.Enqueue(now);
                return true;
            }
        }

        // ── Pull loop ────────────────────────────────────────────────────────────

        public static int PullOnce()
        {
            string sinceIso = _lastPullAt == DateTime.MinValue
                ? "1970-01-01T00:00:00Z"
                : _lastPullAt.ToString("o");
            string url = "entities?select=entity_id,nick,class_id,client_id,updated_at"
                         + "&updated_at=gt." + Uri.EscapeDataString(sinceIso)
                         + "&order=updated_at.asc&limit=5000";
            var r = HttpGetJson(url);
            if (r.Status < 200 || r.Status >= 300)
            {
                PersistLogCommunity("pull failed: status=" + r.Status + " err=" + (r.Error ?? "?"));
                return 0;
            }
            DateTime maxAt;
            var list = ParsePullResponse(r.Body, out maxAt);
            int changed;
            lock (_lock)
            {
                changed = MergePullIntoCache(list, _cache);
                // Sem disk write — backend é fonte de verdade, RAM cache é
                // rebuilt on every boot via pull inicial.
            }
            if (maxAt > _lastPullAt) _lastPullAt = maxAt;
            // C2: notify MainForm to re-seed live caches from updated _cache
            if (changed > 0)
            {
                Action cb = OnPullMerged;
                if (cb != null) try { cb(); } catch { }
            }
            return changed;
        }

        static void PullLoop()
        {
            while (!_stopping)
            {
                try
                {
                    int n = PullOnce();
                    if (n < 0) _pullBackoffMultiplier = Math.Min(_pullBackoffMultiplier * 2, 30);
                    else _pullBackoffMultiplier = 1;
                }
                catch (Exception ex) { PersistLogCommunity("pull exception: " + ex.Message); }
                int waitMs = PullIntervalMs * _pullBackoffMultiplier;
                for (int slept = 0; slept < waitMs && !_stopping; slept += 500) Thread.Sleep(500);
            }
        }

        // ── Heartbeat loop ───────────────────────────────────────────────────────

        static void HeartbeatLoop()
        {
            // 1× logo no início pra registrar presença rápido
            DoHeartbeat();
            while (!_stopping)
            {
                for (int slept = 0; slept < HeartbeatIntervalMs && !_stopping; slept += 500) Thread.Sleep(500);
                if (_stopping) break;
                DoHeartbeat();
            }
        }

        static void DoHeartbeat()
        {
            try
            {
                string observerCharId = "";
                string observerNick = "";
                try
                {
                    string meFile = Path.Combine(_root, "ws-engine.me.txt");
                    if (File.Exists(meFile))
                    {
                        string raw = File.ReadAllText(meFile).Trim();
                        uint id;
                        if (uint.TryParse(raw, out id) && id != 0)
                        {
                            observerCharId = "0x" + id.ToString("X8");
                            RemoteEntry re;
                            if (TryLookup(id, out re) && !string.IsNullOrEmpty(re.Nick)) observerNick = re.Nick;
                        }
                    }
                }
                catch { }

                var sb = new System.Text.StringBuilder();
                sb.Append("{\"client_id\":").Append(JsonString(_clientId))
                  .Append(",\"observer_char_id\":").Append(JsonString(observerCharId))
                  .Append(",\"observer_nick\":").Append(JsonString(observerNick))
                  .Append(",\"version\":").Append(JsonString(_version))
                  .Append(",\"last_seen_at\":\"").Append(DateTime.UtcNow.ToString("o")).Append("\"}");
                var r = HttpPostJson("clients?on_conflict=client_id", sb.ToString(),
                    "resolution=merge-duplicates,return=minimal");
                if (r.Status < 200 || r.Status >= 300)
                    PersistLogCommunity("heartbeat failed: status=" + r.Status + " err=" + (r.Error ?? "?"));
            }
            catch (Exception ex) { PersistLogCommunity("heartbeat exception: " + ex.Message); }
        }

        public static void HeartbeatOnce() { DoHeartbeat(); }

        static void PersistLogCommunity(string msg)
        {
            try
            {
                string line = "[" + DateTime.Now.ToString("HH:mm:ss") + "] [community] " + msg + Environment.NewLine;
                File.AppendAllText(Path.Combine(_root, "wsengine.log"), line);
            }
            catch { }
        }

        // ── HTTP layer ──────────────────────────────────────────────────────────

        internal struct HttpResult
        {
            public int Status;      // 0 = network error / timeout, else HTTP status code
            public string Body;     // response body (utf8 decoded), null on error
            public string Error;    // message se Status == 0
        }

        const int HttpTimeoutMs = 10000;

        internal static HttpResult HttpGetJson(string relativeUrl)
        {
            return DoRequest("GET", relativeUrl, null, null);
        }

        internal static HttpResult HttpPostJson(string relativeUrl, string bodyJson, string extraPreferHeader = null)
        {
            return DoRequest("POST", relativeUrl, bodyJson, extraPreferHeader);
        }

        internal static HttpResult HttpPatchJson(string relativeUrl, string bodyJson)
        {
            return DoRequest("PATCH", relativeUrl, bodyJson, null);
        }

        static HttpResult DoRequest(string method, string relativeUrl, string bodyJson, string extraPrefer)
        {
            var r = new HttpResult { Status = 0, Body = null, Error = null };
            try
            {
                string url = relativeUrl.StartsWith("http", StringComparison.OrdinalIgnoreCase)
                    ? relativeUrl
                    : (_baseUrl + (relativeUrl.StartsWith("/") ? "" : "/") + relativeUrl);
                var req = (System.Net.HttpWebRequest)System.Net.WebRequest.Create(url);
                req.Method = method;
                req.Timeout = HttpTimeoutMs;
                req.ReadWriteTimeout = HttpTimeoutMs;
                req.Accept = "application/json";
                req.ContentType = "application/json";
                if (!string.IsNullOrEmpty(_anonKey))
                {
                    req.Headers["apikey"] = _anonKey;
                    req.Headers["Authorization"] = "Bearer " + _anonKey;
                }
                if (!string.IsNullOrEmpty(_clientId)) req.Headers["x-client-id"] = _clientId;
                if (!string.IsNullOrEmpty(extraPrefer)) req.Headers["Prefer"] = extraPrefer;
                if (bodyJson != null)
                {
                    byte[] bytes = System.Text.Encoding.UTF8.GetBytes(bodyJson);
                    req.ContentLength = bytes.Length;
                    using (var s = req.GetRequestStream()) s.Write(bytes, 0, bytes.Length);
                }
                else
                {
                    req.ContentLength = 0;
                }
                using (var resp = (System.Net.HttpWebResponse)req.GetResponse())
                {
                    r.Status = (int)resp.StatusCode;
                    using (var s = resp.GetResponseStream())
                    using (var sr = new StreamReader(s, System.Text.Encoding.UTF8))
                        r.Body = sr.ReadToEnd();
                }
            }
            catch (System.Net.WebException wex)
            {
                r.Status = 0;
                var http = wex.Response as System.Net.HttpWebResponse;
                if (http != null)
                {
                    r.Status = (int)http.StatusCode;
                    try
                    {
                        using (var s = http.GetResponseStream())
                        using (var sr = new StreamReader(s, System.Text.Encoding.UTF8))
                            r.Body = sr.ReadToEnd();
                    }
                    catch { }
                }
                r.Error = wex.Status + ": " + wex.Message;
            }
            catch (Exception ex)
            {
                r.Status = 0;
                r.Error = ex.GetType().Name + ": " + ex.Message;
            }
            return r;
        }

        // ── Pure helpers ────────────────────────────────────────────────────────

        // Rejeita nicks inválidos antes de push:
        //  - vazio ou > 10 chars (Warspear cap)
        //  - todo caixa alta com > 1 char (ex "KILL", "REAGRUPAR" — chat shout,
        //    não é nick real que memscan capturou como false positive)
        //  - caractere fora de [A-Za-z0-9] (nick Warspear só letras+dígitos;
        //    caracteres tipo espaço, hífen, acento = palavra de chat ou lixo)
        internal static bool IsValidNick(string nick)
        {
            if (string.IsNullOrEmpty(nick)) return false;
            if (nick.Length > MaxNickLen) return false;
            bool hasLower = false;
            for (int i = 0; i < nick.Length; i++)
            {
                char c = nick[i];
                bool isLower = (c >= 'a' && c <= 'z');
                bool isUpper = (c >= 'A' && c <= 'Z');
                bool isDigit = (c >= '0' && c <= '9');
                if (!isLower && !isUpper && !isDigit) return false;
                if (isLower) hasLower = true;
            }
            // 1-char pode ser tudo. > 1 char sem letra minúscula = ALL-CAPS = rejeita.
            if (nick.Length > 1 && !hasLower) return false;
            return true;
        }

        // Compara local (memscan) vs remote (backend snapshot em RAM).
        // Só emite push quando local tem info NOVA vs backend:
        //   - Entity ausente no backend → push completo
        //   - Nick difere → push (raro; nick estável)
        //   - Local class > 0 e backend class null/0 → push (upgrade)
        //   - Local class null/0 mas backend class > 0 → SKIP (backend tem mais info)
        //   - Ambos iguais → SKIP
        // Também filtra nick > MaxNickLen (bate CHECK constraint do backend).
        internal static List<PushEntry> ComputeDeltaVsRemote(
            Dictionary<uint, LocalSnapshotEntry> current,
            Dictionary<uint, RemoteEntry> remote,
            string clientId,
            HashSet<uint> packetConfirmed = null)
        {
            var result = new List<PushEntry>();
            foreach (var kv in current)
            {
                if (kv.Value == null || string.IsNullOrEmpty(kv.Value.Nick)) continue;
                if (!IsValidNick(kv.Value.Nick)) continue;

                RemoteEntry r;
                bool hasRemote = remote.TryGetValue(kv.Key, out r) && r != null;

                // Cross-validation gate: aplicada SÓ pra push novo (eid não
                // existe no backend). Se remote já tem o eid, o nick já foi
                // validado por outro client — daqui pra frente qualquer
                // upgrade de class é seguro sem passar pelo packet-confirmed.
                //
                // Bug pré-2026-09-25: gate rodava antes do check hasRemote,
                // então class upgrade também exigia packet-confirmed. Se o
                // player não voltasse em pacote na sessão, class ficava presa
                // local. Backend ficava só 3-4% coverage de class.
                if (!hasRemote)
                {
                    if (packetConfirmed != null && !packetConfirmed.Contains(kv.Key)) continue;
                    result.Add(new PushEntry { EntityId = kv.Key, Nick = kv.Value.Nick, ClassId = kv.Value.ClassId, ClientId = clientId });
                    continue;
                }

                bool nickDiffers = r.Nick != kv.Value.Nick;
                bool classUpgrade = kv.Value.ClassId > 0 && r.ClassId <= 0;

                if (nickDiffers || classUpgrade)
                {
                    // Nick diff: exige packet-confirmed (previne memscan noise
                    // sobrescrever um nick validado por outro client).
                    // Class upgrade: sem gate — eid já validado, memscan class
                    // é estrutural (ScanBuffer_PlayerClass, byte 0x21 marker).
                    if (nickDiffers && packetConfirmed != null && !packetConfirmed.Contains(kv.Key)) continue;
                    int effectiveClass = kv.Value.ClassId > 0 ? kv.Value.ClassId : r.ClassId;
                    result.Add(new PushEntry { EntityId = kv.Key, Nick = kv.Value.Nick, ClassId = effectiveClass, ClientId = clientId });
                }
            }
            return result;
        }

        internal static string SerializeBatch(List<PushEntry> entries)
        {
            var sb = new System.Text.StringBuilder();
            sb.Append('[');
            for (int i = 0; i < entries.Count; i++)
            {
                var e = entries[i];
                if (i > 0) sb.Append(',');
                sb.Append("{\"entity_id\":").Append(e.EntityId)
                  .Append(",\"nick\":").Append(JsonString(e.Nick))
                  .Append(",\"class_id\":").Append(e.ClassId > 0 ? e.ClassId.ToString() : "null")
                  .Append(",\"client_id\":").Append(JsonString(e.ClientId))
                  .Append('}');
            }
            sb.Append(']');
            return sb.ToString();
        }

        static string JsonString(string s)
        {
            if (s == null) return "null";
            var sb = new System.Text.StringBuilder();
            sb.Append('"');
            foreach (char c in s)
            {
                if (c == '\\' || c == '"') sb.Append('\\').Append(c);
                else if (c == '\n') sb.Append("\\n");
                else if (c == '\r') sb.Append("\\r");
                else if (c == '\t') sb.Append("\\t");
                else if (c < 0x20) sb.AppendFormat("\\u{0:x4}", (int)c);
                else sb.Append(c);
            }
            sb.Append('"');
            return sb.ToString();
        }

        internal static List<RemoteEntry> ParsePullResponse(string bodyJson, out DateTime maxUpdatedAt)
        {
            maxUpdatedAt = DateTime.MinValue;
            var result = new List<RemoteEntry>();
            if (string.IsNullOrEmpty(bodyJson) || bodyJson[0] != '[') return result;
            var rx = new Regex(
                "\\{\\s*\"entity_id\"\\s*:\\s*(\\d+)\\s*,\\s*\"nick\"\\s*:\\s*(\"[^\"]*\"|null)\\s*,\\s*\"class_id\"\\s*:\\s*(\\d+|null)\\s*,\\s*\"client_id\"\\s*:\\s*(\"[^\"]*\"|null)\\s*,\\s*\"updated_at\"\\s*:\\s*\"([^\"]+)\"\\s*\\}");
            foreach (Match m in rx.Matches(bodyJson))
            {
                uint id;
                if (!uint.TryParse(m.Groups[1].Value, out id)) continue;
                var e = new RemoteEntry
                {
                    Nick = m.Groups[2].Value == "null" ? null : m.Groups[2].Value.Substring(1, m.Groups[2].Value.Length - 2),
                    ClassId = m.Groups[3].Value == "null" ? 0 : int.Parse(m.Groups[3].Value),
                    ClientId = m.Groups[4].Value == "null" ? "" : m.Groups[4].Value.Substring(1, m.Groups[4].Value.Length - 2),
                };
                DateTime dt;
                if (DateTime.TryParse(m.Groups[5].Value, null, System.Globalization.DateTimeStyles.RoundtripKind, out dt))
                {
                    e.UpdatedAt = dt.ToUniversalTime();
                    if (e.UpdatedAt > maxUpdatedAt) maxUpdatedAt = e.UpdatedAt;
                }
                e.EntityId = id;
                result.Add(e);
            }
            return result;
        }

        internal static int MergePullIntoCache(List<RemoteEntry> incoming, Dictionary<uint, RemoteEntry> cache)
        {
            int changed = 0;
            foreach (var e in incoming)
            {
                if (e == null || e.EntityId == 0 || string.IsNullOrEmpty(e.Nick)) continue;
                // Defesa in-depth [2026-09-25]: rejeita ids com pattern suspeito
                // no pull. Historicamente byte-scan flat populou o backend com
                // rows tipo (0x00E70000, "Criar") — UI/quest strings casadas
                // por acidente. Real player ids são sparse random; nunca terminam
                // em 0x0000. Filtro aplicado no pull evita repolluição de caches
                // locais mesmo se rows lixo persistirem no backend.
                if ((e.EntityId & 0xFFFF) == 0) continue;
                RemoteEntry cur;
                if (cache.TryGetValue(e.EntityId, out cur))
                {
                    if (cur.UpdatedAt >= e.UpdatedAt) continue;
                }
                cache[e.EntityId] = e;
                changed++;
            }
            return changed;
        }

        // ── Client ID resolver ───────────────────────────────────────────────────

        internal static string ResolveClientId(string root)
        {
            // Priority 1: me.txt (decimal entity_id do char do user)
            try
            {
                string meFile = Path.Combine(root, "ws-engine.me.txt");
                if (File.Exists(meFile))
                {
                    string raw = File.ReadAllText(meFile).Trim();
                    uint id;
                    if (uint.TryParse(raw, out id) && id != 0)
                        return "0x" + id.ToString("X8");
                }
            }
            catch { }

            // Priority 2: client-id.txt (GUID gerado em boot anterior)
            try
            {
                string cidFile = Path.Combine(root, "ws-engine.client-id.txt");
                if (File.Exists(cidFile))
                {
                    string raw = File.ReadAllText(cidFile).Trim();
                    if (raw.Length > 0 && raw.Length <= 64) return raw;
                }
            }
            catch { }

            // Priority 3: gerar GUID novo, persistir
            string gid = Guid.NewGuid().ToString("N").Substring(0, 12);
            try { File.WriteAllText(Path.Combine(root, "ws-engine.client-id.txt"), gid); }
            catch { }
            return gid;
        }
    }
}
