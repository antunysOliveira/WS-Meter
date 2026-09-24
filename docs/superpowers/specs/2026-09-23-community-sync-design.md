# Community Sync — WS-engine shared entity cache

**Status:** design, aprovado 2026-09-23
**Author:** Antunys (via Claude Code brainstorming)

## Intent

Compartilhar cache de nicks e classes de jogadores entre múltiplas instâncias do WS-engine rodando em máquinas diferentes. Hoje cada cliente tem apenas dados do próprio `memscan.exe` (só quem esteve na área do char observador aparece). Ligando N clientes num backend comum, cada um vira sensor cooperativo: quem alguém viu, todos veem.

**Requisitos confirmados:**
- Auto-upload silencioso — todo cliente rodando WS-engine sobe seu memscan sem intervenção manual
- Todos leem cache global merged
- Só entity_id → nick e entity_id → classId. **Sem guild.**
- Cada contribuição carrega client_id do observador (preferencialmente char ID do próprio user, fallback GUID anônimo)
- Heartbeat de presença — saber quantos/quais clients tão online agora
- Backend free-tier cloud (Supabase escolhido)
- Trust minimal — swarm de guild fechada. Anti-troll formal fica pra v2

**Não-objetivos:**
- Auth por usuário. Anon-key compartilhada, embutida no exe
- CRDT / vector clocks. Last-writer-wins por `updated_at`
- Sincronização de guild, PMs, damage, buffs
- Chat/support (rejeitado nesta iteração)
- Realtime/websocket. Polling suficiente

## Architecture overview

```
┌─────────────┐         ┌──────────────────────┐         ┌──────────────┐
│ WS-engine A │◄──pull──┤ Supabase Postgres    ├──pull──►│ WS-engine B  │
│  memscan    │──push──►│ (PostgREST + RLS)    │◄──push──│  memscan     │
│  local JSON │         │  entities + clients  │         │  local JSON  │
└─────────────┘         └──────────────────────┘         └──────────────┘
      │                                                          │
      └────► ws-engine.community-cache.json  ◄───────────────────┘
              (merged snapshot local)
```

**Data flow por cliente:**
1. Boot: `GET /entities?updated_at=gt.<last_pull>` → merge → salva `community-cache.json`
2. Loop 60s: lê `ws-engine.mem-players.json` + `mem-player-classes.json`, calcula delta vs último push → `POST /entities` batch
3. Loop 5min: pull incremental delta → merge cache local
4. Loop 5min: `POST /clients` heartbeat
5. Lookup runtime: `PlayerResolver.NameFor(id)` — prioridade `memscan-local > community-cache > hex`

**Componentes novos:**
- `src/CommunitySync.cs` — thread background push+pull+heartbeat
- `ws-engine.community-cache.json` — cache remoto merged (formato do mem-players.json)
- `ws-engine.client-id.txt` — GUID anônimo (fallback quando `me.txt` vazio)
- Bloco `community` em `ws-engine.config.json`

**Não muda:**
- `memscan.exe`, `Database.cs` (SQLite), packet decoders, dashboard UI atual

## Backend — Supabase schema

**Tabelas:**

```sql
CREATE TABLE entities (
  entity_id   BIGINT PRIMARY KEY,        -- ex: 0x00692DA2 = 6893474
  nick        TEXT NOT NULL,
  class_id    SMALLINT,                  -- NULL = desconhecido, 1..20
  client_id   TEXT NOT NULL,             -- último writer
  updated_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX ix_entities_updated ON entities(updated_at);

CREATE TABLE clients (
  client_id           TEXT PRIMARY KEY,
  observer_char_id    TEXT,
  observer_nick       TEXT,
  version             TEXT,
  first_seen_at       TIMESTAMPTZ NOT NULL DEFAULT now(),
  last_seen_at        TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX ix_clients_last_seen ON clients(last_seen_at);
-- Nota: contributions_total (leaderboard "top contributors") deferido pra v2
-- via VIEW derivada: SELECT client_id, COUNT(*) FROM entities GROUP BY client_id.
-- Evita coluna denormalizada + trigger no v1.
```

**RLS (Row Level Security):**

```sql
ALTER TABLE entities ENABLE ROW LEVEL SECURITY;
ALTER TABLE clients  ENABLE ROW LEVEL SECURITY;

CREATE POLICY read_all_entities ON entities FOR SELECT USING (true);
CREATE POLICY read_all_clients  ON clients  FOR SELECT USING (true);

CREATE POLICY write_entities     ON entities FOR INSERT WITH CHECK (true);
CREATE POLICY write_entities_upd ON entities FOR UPDATE USING (true);
CREATE POLICY write_clients      ON clients  FOR INSERT WITH CHECK (true);
CREATE POLICY write_clients_upd  ON clients  FOR UPDATE USING (true);
-- Sem DELETE policy = ninguém deleta via anon-key
```

**Rate-limit:**
- Supabase free tier limita ~200 req/s global por projeto — suficiente pra guild ~50 clients
- Cliente envia batch (múltiplas rows por request) via `Prefer: resolution=merge-duplicates`

**Cost estimate (200 clients ativos):**
- `entities` ~8K rows × ~150B = 1.2MB. Free tier DB = 500MB
- Requests: 200 clients × (60 push/hora + 12 pull/hora + 12 hb/hora) × 24h = ~403K req/dia = ~12M/mês. Supabase free tier não impõe hard limit em req count (limite é CPU/RAM do Postgres compartilhado); 12M reqs de upsert leve = tranquilo
- Egress: pulls delta ~5KB × 12/dia × 200 clients = ~12MB/dia = 360MB/mês. Free tier = 5GB/mês

## Client sync module — `src/CommunitySync.cs`

**Responsabilidades:**
- Manter `client_id` (arquivo `ws-engine.client-id.txt` ou `me.txt` se setado)
- Push loop: diff local vs último push → POST batch
- Pull loop: GET delta → merge cache
- Heartbeat loop: POST /clients
- Expor `TryLookup(uint entityId, out RemoteEntry)` pra `PlayerResolver`

**Estrutura:**

```csharp
namespace WSEngine {
  static class CommunitySync {
    static string _baseUrl;      // https://xxx.supabase.co/rest/v1
    static string _anonKey;
    static string _clientId;
    static bool _enabled;
    static Thread _pushThread, _pullThread, _hbThread;

    static Dictionary<uint, RemoteEntry> _cache = new Dictionary<uint, RemoteEntry>();
    static Dictionary<uint, LocalSnapshotEntry> _lastPushedSnapshot = new Dictionary<uint, LocalSnapshotEntry>();
    static DateTime _lastPullAt = DateTime.MinValue;

    public class RemoteEntry {
      public string Nick;
      public int ClassId;
      public DateTime UpdatedAt;
      public string ClientId;
    }

    public static void Init(string root, string url, string key, bool enabled);
    public static void Stop();
    public static bool TryLookup(uint id, out RemoteEntry e);
    public static int CachedCount { get; }
    public static int OnlineClientsApprox { get; }

    static void PushLoop();
    static void PullLoop();
    static void HeartbeatLoop();
  }
}
```

**Push algorithm (60s tick):**
1. Load `mem-players.json` + `mem-player-classes.json`
2. Merge → `localSnapshot: Dictionary<uint,(nick,classId)>`
3. Diff vs `_lastPushedSnapshot`: nova entry OR (nick mudou) OR (classId mudou) → include
4. `batch.Count == 0` → skip HTTP
5. `POST /rest/v1/entities?on_conflict=entity_id`
   Headers:
     ```
     apikey: <anonKey>
     Authorization: Bearer <anonKey>
     Content-Type: application/json
     Prefer: resolution=merge-duplicates,return=minimal
     x-client-id: <clientId>
     ```
   Body: `[{"entity_id":6893474,"nick":"Centablg","class_id":10,"client_id":"0x00692DA2"}, ...]`
6. 2xx → replace `_lastPushedSnapshot`
7. Erro → mantém snapshot, retry next tick

**Pull algorithm (5min tick):**
1. `sinceIso = _lastPullAt.ToString("o")`
2. `GET /rest/v1/entities?updated_at=gt.<sinceIso>&order=updated_at.asc&limit=5000`
3. Parse array → merge em `_cache` (só se `remote.UpdatedAt > local.UpdatedAt`)
4. `_lastPullAt = max(updated_at)` recebido
5. Serializa `_cache` → `ws-engine.community-cache.json` (atomic write via `File.WriteAllText` em `.tmp` + `File.Replace`)
6. Erro → mantém `_lastPullAt`, retry next tick

**Heartbeat (5min tick):**
```
POST /rest/v1/clients?on_conflict=client_id
Body: {"client_id":"0x00692DA2","observer_char_id":"0x00692DA2",
       "observer_nick":"Centablg","version":"a1b2c3d","last_seen_at":"now()"}
Prefer: resolution=merge-duplicates
```

**HTTP layer:**
- `HttpWebRequest` puro (evita HttpClient .NET 4.5+ dependency, alinha com resto do projeto compilado via csc v4)
- Timeout 10s
- JSON manual (padrão do projeto — sem serializer external)
- Log via `PersistLogLine("[community] ...")` — não polui txtLog UI

**Client ID resolution (Init):**
1. Read `ws-engine.me.txt` → `myId`
2. Se `myId != empty` → `_clientId = "0x" + myId.ToString("X8")`
3. Senão se `ws-engine.client-id.txt` existe → `_clientId = File.ReadAllText().Trim()`
4. Senão → `_clientId = Guid.NewGuid().ToString("N").Substring(0, 12)` + `File.WriteAllText("ws-engine.client-id.txt", _clientId)`
5. `me.txt` mudança em runtime: v1 lê só no boot. FileSystemWatcher opcional em v2.

**Limites:**
- Push batch max 500 entries/request (PostgREST default)
- Pull limit 5000/request (paginação se exceder — v1 assume tabela <5K, adiciona pagination se crescer)
- Cache in-memory unbounded (~1MB pra 10K entries)

## Integration points

**PlayerResolver.NameFor(uint id) — nova prioridade:**
```csharp
public static string NameFor(uint id) {
  string n;
  if (_userNicks.TryGetValue(id, out n)) return n;                  // 1. manual override
  if (_memPlayers.TryGetValue(id, out n)) return n;                 // 2. memscan local
  CommunitySync.RemoteEntry re;
  if (CommunitySync.TryLookup(id, out re) && !string.IsNullOrEmpty(re.Nick))
    return re.Nick;                                                  // 3. community cache
  return "0x" + id.ToString("X8");                                  // 4. hex fallback
}
```

**PlayerResolver.ClassFor(uint id) — mesma prioridade:**
```csharp
public static int ClassFor(uint id) {
  int c;
  if (_memClasses.TryGetValue(id, out c) && c > 0) return c;
  CommunitySync.RemoteEntry re;
  if (CommunitySync.TryLookup(id, out re) && re.ClassId > 0) return re.ClassId;
  return 0;
}
```

**ws-engine.config.json — novos campos:**
```json
{
  "wiresharkDir": "C:\\Program Files\\Wireshark",
  "interface": "Ethernet",
  "community": {
    "enabled": true,
    "url": "https://xxxxxx.supabase.co/rest/v1",
    "anonKey": "eyJhbGciOi...",
    "pushIntervalSec": 60,
    "pullIntervalSec": 300,
    "heartbeatIntervalSec": 300
  }
}
```
- Defaults hardcoded no C# — config sobrescreve
- `enabled=false` desliga tudo (thread nunca inicia)
- Config vazio no primeiro run → cria com defaults, `enabled=true`

**MainForm boot:**
```csharp
// Depois de GameData.Init(root) + LoadConfig
CommunitySync.Init(root, cfg.CommunityUrl, cfg.CommunityAnonKey, cfg.CommunityEnabled);
```

**MainForm shutdown:**
```csharp
protected override void OnFormClosing(FormClosingEventArgs e) {
  CommunitySync.Stop();
  base.OnFormClosing(e);
}
```

**WebViewHost — nova IPC msg (opcional v1, provável v1.1):**
```json
{"type":"community","enabled":true,"cachedCount":1234,
 "lastPushAt":"2026-09-23T18:22:11Z","lastPullAt":"2026-09-23T18:20:03Z",
 "onlineClients":7}
```
Push cada 30s via `CommunitySync.PushStatusToUI()`. `app.js` renderiza no header: `COMMUNITY: 7 online · 1.2K entries · última sync 12s`.

## Error handling + offline

**Falha de rede:**
- HTTP timeout 10s. `WebException`/socket error → `PersistLogLine("[community] push failed: <msg>")` + skip tick
- Backoff exponencial: 1st fail = próximo tick normal, 2nd fail = 2×, 3rd+ = 4× (cap 30min)
- Reset backoff no primeiro sucesso

**Backend indisponível:**
- Cliente segue normal (memscan local intocado)
- `TryLookup()` retorna false, `PlayerResolver` cai naturalmente pro hex fallback
- 1 log/hora `[community] backend unreachable, running local-only`

**Dados corrompidos:**
- `community-cache.json` inválido no boot → apaga, começa vazio, re-pull
- Response JSON malformado → skip merge, log, próximo pull retenta
- Entity inválido no push (nick vazio, id=0) → filtro no client antes de POST

**Conflict resolution:**
- Two clients push mesmo `entity_id` com nicks diferentes → Postgres upsert `on_conflict=entity_id` = last-writer-wins por `updated_at`
- Cliente que perdeu detecta no próximo pull → merge remote
- Sem CRDT, sem vector clocks. Suficiente pra escopo — nicks estáveis, colisão real raríssima

**Rate-limit (429):**
- Log `[community] 429 rate-limited, backoff 60s`
- Dobra intervalo do loop afetado até próximo 2xx

**Config inválida:**
- URL vazia/malformada → `enabled=false` implícito + log `[community] invalid config, disabled`
- Nunca crashea MainForm

**Privacy escape hatch:**
- `enabled=false` → thread nunca inicia, zero bytes saem
- Delete `ws-engine.client-id.txt` → next boot gera GUID novo (reset identidade)
- Doc em `SETUP.md`: "como desligar community sync"

## Testing

**Unit-testable (sem network):**
- `CommunitySync.ComputeDelta(localSnapshot, lastPushedSnapshot)` — pura
- `CommunitySync.MergePullResponse(current, incoming)` — pura
- `CommunitySync.SerializeBatch(entries)` — pure JSON builder
- Testes rodam via PowerShell script `tools/_test-community-sync.ps1 --unit`

**Integration (com Supabase real):**
- Projeto Supabase separado `ws-engine-dev` pra testes
- Script `tools/_test-community-sync.ps1 --integration`:
  1. Wipe teste tables via service_role_key
  2. Roda `WS-engine.exe --community-status`
  3. POST manual 5 entities via curl → asserta pull no client
  4. Push manual do client → asserta linhas no Postgres via curl

**CLI mode novo — `WS-engine.exe --community-status`:**
Boot mínimo (sem UI), imprime:
```
client_id: 0x00692DA2
observer: Centablg
cache: 1234 entries, last pull 3min ago
backend: OK (last push 45s ago, 12 pushed)
```

**Smoke test na entrega:**
- 2 WS-engine em máquinas diferentes
- Máquina A: memscan captura Centablg → aparece em `entities` via Supabase dashboard
- Máquina B: `TryLookup(0x00692DA2)` retorna "Centablg" após próximo pull
- `clients.last_seen_at` bumpa cada 5min em ambas

**Rollback plan:**
- CommunitySync 100% aditivo. Se pau: `config.community.enabled=false` + restart. Zero risco.
- Nada muda em SQLite/memscan/decoder — app funciona igual com community=false

## Open questions (para futuras iterações)

- Voting/reputação anti-troll (v2 se surgir problema)
- FileSystemWatcher em `me.txt` pra atualizar `_clientId` em runtime (v2)
- Pagination no pull quando `entities` > 5K rows (v1.1)
- Dashboard COMMUNITY card no app.js (v1.1 — pode entregar v1 sem UI)
- Supabase Realtime WebSocket pra pull instantâneo (v2, se polling 5min for insuficiente)
- Migration path se `class_id` schema mudar (v2)

## Migration & deploy

**Setup (uma vez):**
1. Criar projeto Supabase na região São Paulo (menor latência BR)
2. Rodar DDL acima no SQL Editor
3. Copiar `anon-key` do Project Settings → API
4. Embutir URL + key nos defaults hardcoded do `CommunitySync.Init()` (usuário pode sobrescrever via config)
5. Documentar em `SETUP.md` como desligar

**Release:**
- Feature nova em `wsengine.log`: `[community] enabled, client_id=0x00692DA2, backend=https://...`
- Sem migration DB local necessária (SQLite intocado)
- Sem changelog na tela — usuário nota via `COMMUNITY: ... online` no header (se UI card entregar em v1)
