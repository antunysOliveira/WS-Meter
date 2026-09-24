# Community Sync Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Adicionar sincronização opcional de cache `entity_id → nick + classId` entre múltiplas instâncias do WS-engine via backend Supabase, com heartbeat de presença por cliente.

**Architecture:** Módulo aditivo `src/CommunitySync.cs` roda 3 threads em background (push 60s, pull 5min, heartbeat 5min). Comunica com Supabase Postgres via PostgREST usando `HttpWebRequest` puro. Popula os dicionários in-memory já existentes (`autoNameCache`, `playerClassId`) sem overwrite — memscan local sempre vence. Zero mudança em memscan/SQLite/decoders.

**Tech Stack:** C# .NET Framework 4 (compilado via `csc.exe` no `build.bat`); `System.Net.HttpWebRequest`; JSON manual (padrão do projeto — sem serializer external); Supabase Postgres + PostgREST + RLS.

**Spec:** `docs/superpowers/specs/2026-09-23-community-sync-design.md`

## Global Constraints

- **Compilação:** .NET Framework 4 via `C:\Windows\Microsoft.NET\Framework\v4.0.30319\csc.exe`. Nada de HttpClient, async/await modernos, `System.Text.Json`, NuGet, MSBuild.
- **JSON:** parser/writer manual seguindo padrão de `NicknamesJson` / `LoadJsonClassesInto` no projeto atual (sem dependência external).
- **Arquivo config:** `ws-engine.config.json` (mesmo arquivo já usado). Novo bloco `community`. Defaults hardcoded no C#.
- **Sem mudanças destrutivas:** memscan.exe intocado, SQLite intocado, decoders intocados. Módulo é 100% aditivo — `community.enabled=false` no config equivale a não ter feature.
- **Admin required:** já garantido pelo manifest.
- **Threads:** cada loop em `Thread` dedicada (não `Timer` — evita reentrância no UI thread). `Thread.IsBackground = true` pra não bloquear shutdown.
- **Logs:** via `PersistLogLine("[community] ...")` em `WS-engine.cs`. Não polui `txtLog` UI. Formato: `[community] <event> ...`.
- **Timeouts HTTP:** 10 segundos hard, sem exceção.
- **Batch size limits:** push max 500 entries/request. Pull max 5000 entries/request.

## Review Focus

Pontos que a spec implica mas nenhum task testa diretamente — os 5 mais prováveis de morder o usuário:

1. **`me.txt` alterado em runtime não atualiza `client_id`** — usuário faz right-click "This is me" após boot, mas heartbeat/uploads continuam com client_id antigo até restart. Test em Task 3: `ClientIdResolver.Resolve` chamado 2× com `me.txt` diferente entre chamadas retorna valores diferentes (comportamento correto do resolver puro); v1 aceita que caller só chama no boot — documentado em `[community] client_id resolved once at boot`.
2. **`community-cache.json` corrompido no boot crasha MainForm** — arquivo com JSON inválido não deve derrubar app. Test em Task 6: `LoadCacheFromDisk("{corrupted")` retorna dict vazio + loga warning, não lança.
3. **Pull response gigante estoura timeout mid-parse** — response de 5MB parcialmente lida deixa cache inconsistente. Test em Task 4: `HttpGetJson` com timeout retorna `(statusCode=0, body=null)` em vez de body truncado.
4. **`entity_id=0` chamado em `TryLookup`** — mob genérico / hit de dano com atacante zero. Test em Task 2: `CommunitySync.TryLookup(0, out _)` retorna `false`.
5. **Duas instâncias WS-engine na mesma máquina (dev testando)** — mesmo `me.txt` → mesmo `client_id` → heartbeats simultâneos. Não é bug (upsert idempotente) mas contribuições ficam misturadas. Test em Task 7: 2 POSTs concorrentes com mesmo `client_id` sucedem sem erro (validado via curl no smoke test da Task 11).

---

## File Structure

**Novos arquivos:**
- `src/CommunitySync.cs` — módulo principal (~500 linhas: init, 3 threads, pure helpers)
- `tools/community-backend-schema.sql` — DDL Supabase + RLS policies
- `tools/_test-community-sync.ps1` — script de testes (unit + integration)
- `docs/community-sync-troubleshoot.md` — doc rápida de operação (uso do `--community-status`, como desligar)

**Arquivos modificados:**
- `build.bat` — adicionar `src\CommunitySync.cs` na lista de compile
- `src/WS-engine.cs` — 4 pontos:
  - `MainForm` ctor: parse novo bloco `community` do config + chamar `CommunitySync.Init`
  - `MainForm.OnFormClosing`: chamar `CommunitySync.Stop`
  - `Main` (top-level): novo CLI branch `--community-status`
  - Loader de boot: após `LoadJsonInto(autoNameCache, ...)`, chamar `CommunitySync.SeedFromCache(autoNameCache, playerClassId)` pra popular dicionários com cache remoto sem overwrite
- `SETUP.md` — nova seção "Community sync — desligar / recriar identidade"
- `ws-engine.config.json` — bloco `community` (documentado; arquivo é gerado em runtime, não editado no repo)

**Novos arquivos runtime (gitignored, gerados pelo app):**
- `ws-engine.community-cache.json` — snapshot pulled do backend
- `ws-engine.client-id.txt` — GUID anônimo (fallback quando `me.txt` vazio)

---

## Task 1: Backend schema + bootstrap docs

**Files:**
- Create: `tools/community-backend-schema.sql`
- Modify: `SETUP.md` (adicionar seção)

**Interfaces:**
- Consumes: nada
- Produces: schema SQL executável no Supabase SQL Editor; anon-key + URL do projeto Supabase que Task 8 vai embutir como default

- [ ] **Step 1: Criar `tools/community-backend-schema.sql`**

```sql
-- WS-engine Community Sync — schema Supabase
-- Rodar no Supabase SQL Editor uma vez no bootstrap do projeto.

CREATE TABLE IF NOT EXISTS entities (
  entity_id   BIGINT PRIMARY KEY,
  nick        TEXT NOT NULL,
  class_id    SMALLINT,
  client_id   TEXT NOT NULL,
  updated_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS ix_entities_updated ON entities(updated_at);

CREATE TABLE IF NOT EXISTS clients (
  client_id           TEXT PRIMARY KEY,
  observer_char_id    TEXT,
  observer_nick       TEXT,
  version             TEXT,
  first_seen_at       TIMESTAMPTZ NOT NULL DEFAULT now(),
  last_seen_at        TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS ix_clients_last_seen ON clients(last_seen_at);

ALTER TABLE entities ENABLE ROW LEVEL SECURITY;
ALTER TABLE clients  ENABLE ROW LEVEL SECURITY;

CREATE POLICY read_all_entities ON entities FOR SELECT USING (true);
CREATE POLICY read_all_clients  ON clients  FOR SELECT USING (true);
CREATE POLICY write_entities     ON entities FOR INSERT WITH CHECK (true);
CREATE POLICY write_entities_upd ON entities FOR UPDATE USING (true);
CREATE POLICY write_clients      ON clients  FOR INSERT WITH CHECK (true);
CREATE POLICY write_clients_upd  ON clients  FOR UPDATE USING (true);
```

- [ ] **Step 2: Criar projeto Supabase manualmente**

Ação manual do dev (não automatizável): acessar https://supabase.com/dashboard, criar projeto `ws-engine-community` na região `São Paulo (sa-east-1)`. Rodar o SQL acima no SQL Editor. Copiar `Project URL` (formato `https://xxxxxxxxxxxx.supabase.co`) e `anon public key` do Settings → API. Anotar essas 2 strings — serão embutidas como defaults na Task 8.

- [ ] **Step 3: Verificar schema aplicado**

Via curl (do próprio dev), asserta que as tabelas respondem:

```
curl -s -H "apikey: <ANON_KEY>" \
  "<PROJECT_URL>/rest/v1/entities?limit=1"
```

Expected: retorna `[]` (array vazio, tabela existe e está vazia). Se retornar erro de policy, verificar que RLS policies foram criadas.

- [ ] **Step 4: Adicionar seção no SETUP.md**

Editar `SETUP.md` adicionando após a seção "5. Adicionar exceção no antivírus":

```markdown
## 6. Community sync (opcional)

O WS-engine tem um recurso opcional que compartilha o cache de nicks e
classes entre todos os usuários rodando o programa. Todo mundo vê os
jogadores que qualquer outro já cruzou.

**Ligado por padrão.** Se quiser desligar:

1. Fechar WS-engine.
2. Abrir `ws-engine.config.json` (ao lado do exe).
3. Setar `"community": { "enabled": false }`.
4. Reabrir.

**Reset de identidade** (regenera seu client_id anônimo):

1. Fechar WS-engine.
2. Apagar `ws-engine.client-id.txt`.
3. Reabrir. Novo GUID é gerado.
```

- [ ] **Step 5: Commit**

```
git add tools/community-backend-schema.sql SETUP.md
git commit -m "feat(community): backend schema + setup docs

DDL Supabase + RLS policies pra tabelas entities e clients. Doc
em SETUP.md pra usuário desligar sync ou resetar identidade."
```

---

## Task 2: CommunitySync module skeleton + public API

**Files:**
- Create: `src/CommunitySync.cs`

**Interfaces:**
- Consumes: nada (só tipos primitivos + `Dictionary<uint,string>` / `Dictionary<uint,int>` do sistema)
- Produces:
  - `class RemoteEntry { public string Nick; public int ClassId; public DateTime UpdatedAt; public string ClientId; }`
  - `static void Init(string root, string url, string anonKey, bool enabled, string version)` — chamada 1× no boot
  - `static void Stop()` — chamada 1× no shutdown
  - `static bool TryLookup(uint id, out RemoteEntry e)` — thread-safe lookup no cache
  - `static void SeedFromCache(Dictionary<uint,string> nameCache, Dictionary<uint,int> classCache)` — merge sem overwrite
  - `static int CachedCount { get; }` — pra CLI status
  - `static string ClientIdForDiag { get; }` — pra CLI status

- [ ] **Step 1: Escrever teste de API skeleton via CLI**

Criar `tools/_test-community-sync.ps1` com bloco inicial:

```powershell
param([string]$mode = "unit")

$exe = Join-Path $PSScriptRoot "..\WS-engine.exe"
if ($mode -eq "unit") {
    # Test 1: --community-status roda sem crashear mesmo com backend inacessível
    $out = & $exe --community-status 2>&1
    if ($LASTEXITCODE -ne 0) { Write-Error "FAIL: --community-status exit=$LASTEXITCODE"; exit 1 }
    if ($out -notmatch "client_id:") { Write-Error "FAIL: no client_id line"; exit 1 }
    Write-Host "PASS: --community-status skeleton"
}
```

- [ ] **Step 2: Rodar teste — deve falhar (CLI ainda não existe)**

```
powershell -ExecutionPolicy Bypass -File tools\_test-community-sync.ps1 unit
```
Expected: FAIL (exe não reconhece `--community-status`).

- [ ] **Step 3: Criar `src/CommunitySync.cs` com skeleton mínimo**

```csharp
// CommunitySync — shared cache de nick + classId entre WS-engines
// via Supabase Postgres. Ver docs/superpowers/specs/2026-09-23-community-sync-design.md
//
// Módulo aditivo, thread-safe. 3 loops em background (push 60s, pull 5min,
// heartbeat 5min). enabled=false → nada roda.

using System;
using System.Collections.Generic;
using System.IO;
using System.Threading;

namespace WSEngine
{
    static class CommunitySync
    {
        public class RemoteEntry
        {
            public string Nick;
            public int ClassId;
            public DateTime UpdatedAt;
            public string ClientId;
        }

        static readonly object _lock = new object();
        static readonly Dictionary<uint, RemoteEntry> _cache = new Dictionary<uint, RemoteEntry>();
        static string _root, _baseUrl, _anonKey, _clientId, _version;
        static bool _enabled;
        static Thread _pushThread, _pullThread, _hbThread;
        static volatile bool _stopping;

        public static int CachedCount { get { lock (_lock) return _cache.Count; } }
        public static string ClientIdForDiag { get { return _clientId ?? "(uninitialized)"; } }

        public static void Init(string root, string url, string anonKey, bool enabled, string version)
        {
            _root = root;
            _baseUrl = (url ?? "").TrimEnd('/');
            _anonKey = anonKey ?? "";
            _enabled = enabled && !string.IsNullOrEmpty(_baseUrl) && !string.IsNullOrEmpty(_anonKey);
            _version = version ?? "unknown";
            _clientId = ResolveClientId(root);
            if (!_enabled) return;
            // Threads ligadas em tasks posteriores. Skeleton só popula _clientId.
        }

        public static void Stop()
        {
            _stopping = true;
            // Threads são background — vão morrer com o processo. Wait explícito em Task 5/6/7.
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

        // Implementado em Task 3.
        internal static string ResolveClientId(string root) { return "(pending-task-3)"; }
    }
}
```

- [ ] **Step 4: Adicionar `src\CommunitySync.cs` no build.bat**

Editar `build.bat`, inserir linha antes de `"%~dp0src\WS-engine.cs"`:

```
    "%~dp0src\CommunitySync.cs" ^
```

- [ ] **Step 5: Adicionar CLI branch `--community-status` em `src/WS-engine.cs`**

Localizar `static int Main(string[] args)` (top-level entry). Adicionar branch antes do fallback GUI:

```csharp
if (args.Length > 0 && args[0] == "--community-status")
{
    string root = Path.GetDirectoryName(System.Reflection.Assembly.GetExecutingAssembly().Location);
    // Config lookup mínimo — Task 8 amplia
    CommunitySync.Init(root, "", "", false, "cli-status");
    Console.WriteLine("client_id: " + CommunitySync.ClientIdForDiag);
    Console.WriteLine("cache: " + CommunitySync.CachedCount + " entries");
    Console.WriteLine("backend: (skeleton — not wired)");
    return 0;
}
```

- [ ] **Step 6: Build + rodar teste**

```
.\build.bat
powershell -ExecutionPolicy Bypass -File tools\_test-community-sync.ps1 unit
```
Expected: PASS (`--community-status` roda, imprime `client_id: (pending-task-3)`).

- [ ] **Step 7: Test `TryLookup(0)` — Review Focus item 4**

Adicionar em `_test-community-sync.ps1` bloco unit:

```powershell
# Test 2: TryLookup(0) via CLI probe
$out = & $exe --community-probe 0 2>&1
if ($out -notmatch "not found") { Write-Error "FAIL: TryLookup(0) should return false"; exit 1 }
Write-Host "PASS: TryLookup(0) returns false"
```

E adicionar branch CLI:

```csharp
if (args.Length >= 2 && args[0] == "--community-probe")
{
    uint id;
    if (!uint.TryParse(args[1], out id)) { Console.Error.WriteLine("bad id"); return 2; }
    string root = Path.GetDirectoryName(System.Reflection.Assembly.GetExecutingAssembly().Location);
    CommunitySync.Init(root, "", "", false, "cli-probe");
    CommunitySync.RemoteEntry e;
    if (CommunitySync.TryLookup(id, out e)) Console.WriteLine("found: nick=" + e.Nick + " class=" + e.ClassId);
    else Console.WriteLine("not found");
    return 0;
}
```

- [ ] **Step 8: Rebuild + rodar full unit**

```
.\build.bat
powershell -ExecutionPolicy Bypass -File tools\_test-community-sync.ps1 unit
```
Expected: 2× PASS.

- [ ] **Step 9: Commit**

```
git add src/CommunitySync.cs build.bat src/WS-engine.cs tools/_test-community-sync.ps1
git commit -m "feat(community): CommunitySync module skeleton + CLI probes

Public API (Init/Stop/TryLookup/SeedFromCache), CLI --community-status
+ --community-probe pra smoke test. Threads sem loop ainda — próximas
tasks."
```

---

## Task 3: Client ID resolver (pure helper)

**Files:**
- Modify: `src/CommunitySync.cs` (substituir stub `ResolveClientId`)
- Modify: `tools/_test-community-sync.ps1` (adicionar testes)

**Interfaces:**
- Consumes: `_root` (path do app)
- Produces: `internal static string ResolveClientId(string root)` retorna string estável entre boots (chame no boot, guarda em `_clientId`)

- [ ] **Step 1: Adicionar teste — me.txt define client_id**

Em `_test-community-sync.ps1`:

```powershell
# Test 3: me.txt setado → client_id = 0x<HEX>
$root = Split-Path $exe -Parent
$meBak = Join-Path $root "ws-engine.me.txt"
$cidBak = Join-Path $root "ws-engine.client-id.txt"
$meBackup = if (Test-Path $meBak) { Get-Content $meBak -Raw } else { $null }
$cidBackup = if (Test-Path $cidBak) { Get-Content $cidBak -Raw } else { $null }

try {
    Set-Content -Path $meBak -Value "6893474"  # 0x00692DA2 decimal
    if (Test-Path $cidBak) { Remove-Item $cidBak }
    $out = & $exe --community-status 2>&1
    if ($out -notmatch "client_id: 0x00692DA2") { Write-Error "FAIL: me.txt not honored ($out)"; exit 1 }
    Write-Host "PASS: me.txt → client_id"

    # Test 4: me.txt vazio + client-id.txt existe → usa client-id.txt
    Remove-Item $meBak
    Set-Content -Path $cidBak -Value "abc123def456"
    $out = & $exe --community-status 2>&1
    if ($out -notmatch "client_id: abc123def456") { Write-Error "FAIL: client-id.txt not honored"; exit 1 }
    Write-Host "PASS: client-id.txt fallback"

    # Test 5: nenhum arquivo → gera GUID + salva
    Remove-Item $cidBak
    $out = & $exe --community-status 2>&1
    if ($out -notmatch "client_id: [a-f0-9]{12}") { Write-Error "FAIL: no GUID generated ($out)"; exit 1 }
    if (-not (Test-Path $cidBak)) { Write-Error "FAIL: client-id.txt not written"; exit 1 }
    Write-Host "PASS: GUID gen + persist"
} finally {
    if ($meBackup) { Set-Content -Path $meBak -Value $meBackup } elseif (Test-Path $meBak) { Remove-Item $meBak }
    if ($cidBackup) { Set-Content -Path $cidBak -Value $cidBackup } elseif (Test-Path $cidBak) { Remove-Item $cidBak }
}
```

- [ ] **Step 2: Rodar — deve falhar (stub retorna "(pending-task-3)")**

```
powershell -ExecutionPolicy Bypass -File tools\_test-community-sync.ps1 unit
```
Expected: FAIL nos testes 3-5.

- [ ] **Step 3: Implementar `ResolveClientId` em `CommunitySync.cs`**

Substituir stub por:

```csharp
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
```

- [ ] **Step 4: Rebuild + rodar testes**

```
.\build.bat
powershell -ExecutionPolicy Bypass -File tools\_test-community-sync.ps1 unit
```
Expected: todos PASS.

- [ ] **Step 5: Commit**

```
git add src/CommunitySync.cs tools/_test-community-sync.ps1
git commit -m "feat(community): client_id resolver (me.txt → GUID fallback)"
```

---

## Task 4: HTTP layer (HttpWebRequest wrapper)

**Files:**
- Modify: `src/CommunitySync.cs` (adicionar região HTTP)

**Interfaces:**
- Consumes: `_baseUrl`, `_anonKey`, `_clientId`
- Produces:
  - `internal struct HttpResult { public int Status; public string Body; public string Error; }`
  - `internal static HttpResult HttpPostJson(string relativeUrl, string bodyJson, string extraPreferHeader = null)`
  - `internal static HttpResult HttpGetJson(string relativeUrl)`
  - `internal static HttpResult HttpPatchJson(string relativeUrl, string bodyJson)`

Todas thread-safe (sem estado compartilhado além de `_baseUrl`/`_anonKey`/`_clientId`).

- [ ] **Step 1: Adicionar teste HTTP timeout (Review Focus item 3)**

Em `_test-community-sync.ps1`, criar bloco integration:

```powershell
if ($mode -eq "integration") {
    # Test IT1: HTTP timeout returns Status=0, Body=null
    # Endpoint dead-drop que aceita conexão mas nunca responde:
    # https://httpstat.us/200?sleep=30000 (dorme 30s > timeout 10s)
    $out = & $exe --community-http-probe "https://httpstat.us/200?sleep=30000" 2>&1
    if ($out -notmatch "Status=0") { Write-Error "FAIL: timeout should return Status=0 ($out)"; exit 1 }
    Write-Host "PASS: HTTP timeout handled"
}
```

Adicionar CLI branch em `WS-engine.cs`:

```csharp
if (args.Length >= 2 && args[0] == "--community-http-probe")
{
    string root = Path.GetDirectoryName(System.Reflection.Assembly.GetExecutingAssembly().Location);
    CommunitySync.Init(root, args[1], "dummy-key", true, "cli-probe");
    var r = CommunitySync.HttpGetJson("");   // GET direto na URL passada
    Console.WriteLine("Status=" + r.Status + " Err=" + (r.Error ?? "none"));
    return 0;
}
```

- [ ] **Step 2: Rodar — deve falhar (método não existe)**

Build vai falhar: `HttpGetJson` não é public/internal. Passar teste PENDING.

- [ ] **Step 3: Implementar HTTP layer em `CommunitySync.cs`**

Adicionar (dentro da classe):

```csharp
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
```

- [ ] **Step 4: Rebuild + rodar integration**

```
.\build.bat
powershell -ExecutionPolicy Bypass -File tools\_test-community-sync.ps1 integration
```
Expected: PASS.

- [ ] **Step 5: Commit**

```
git add src/CommunitySync.cs tools/_test-community-sync.ps1 src/WS-engine.cs
git commit -m "feat(community): HTTP layer (HttpWebRequest wrapper)

GET/POST/PATCH com timeout 10s, headers Supabase (apikey + Bearer +
x-client-id), tratamento uniforme de WebException. --community-http-probe
CLI pra smoke test contra endpoint arbitrário."
```

---

## Task 5: JSON pure helpers (delta + serialize + merge)

**Files:**
- Modify: `src/CommunitySync.cs`

**Interfaces:**
- Consumes: nada (funções puras)
- Produces:
  - `internal class LocalSnapshotEntry { public string Nick; public int ClassId; }`
  - `internal class PushEntry { public uint EntityId; public string Nick; public int ClassId; public string ClientId; }`
  - `internal static List<PushEntry> ComputeDelta(Dictionary<uint,LocalSnapshotEntry> current, Dictionary<uint,LocalSnapshotEntry> lastPushed, string clientId)`
  - `internal static string SerializeBatch(List<PushEntry> entries)`
  - `internal static List<RemoteEntry> ParsePullResponse(string bodyJson, out DateTime maxUpdatedAt)`
  - `internal static int MergePullIntoCache(List<RemoteEntry> incoming, Dictionary<uint,RemoteEntry> cache)` — retorna N novos/atualizados

- [ ] **Step 1: Adicionar testes unit**

Em `_test-community-sync.ps1` (mode=unit), CLI branch nova:

```csharp
if (args.Length > 0 && args[0] == "--community-unit-delta")
{
    // Vazio → vazio
    var current = new Dictionary<uint, CommunitySync.LocalSnapshotEntry>();
    var last = new Dictionary<uint, CommunitySync.LocalSnapshotEntry>();
    var d = CommunitySync.ComputeDelta(current, last, "cli");
    if (d.Count != 0) { Console.Error.WriteLine("FAIL: empty→empty should have 0 delta"); return 1; }

    // Nova entry
    current[0x0069u] = new CommunitySync.LocalSnapshotEntry { Nick = "A", ClassId = 1 };
    d = CommunitySync.ComputeDelta(current, last, "cli");
    if (d.Count != 1 || d[0].Nick != "A") { Console.Error.WriteLine("FAIL: new entry not in delta"); return 1; }

    // Sem mudança
    last[0x0069u] = new CommunitySync.LocalSnapshotEntry { Nick = "A", ClassId = 1 };
    d = CommunitySync.ComputeDelta(current, last, "cli");
    if (d.Count != 0) { Console.Error.WriteLine("FAIL: unchanged in delta"); return 1; }

    // Nick mudou
    current[0x0069u].Nick = "B";
    d = CommunitySync.ComputeDelta(current, last, "cli");
    if (d.Count != 1 || d[0].Nick != "B") { Console.Error.WriteLine("FAIL: nick change not detected"); return 1; }

    // Serialize
    string j = CommunitySync.SerializeBatch(d);
    if (!j.Contains("\"entity_id\":105") || !j.Contains("\"nick\":\"B\"")) {
        Console.Error.WriteLine("FAIL: serialize wrong: " + j); return 1;
    }

    Console.WriteLine("PASS: unit-delta");
    return 0;
}
```

E no ps1:
```powershell
$out = & $exe --community-unit-delta 2>&1
if ($LASTEXITCODE -ne 0) { Write-Error "FAIL unit-delta: $out"; exit 1 }
Write-Host $out
```

- [ ] **Step 2: Rodar — falha (métodos não existem)**

- [ ] **Step 3: Implementar helpers em `CommunitySync.cs`**

```csharp
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

internal static List<PushEntry> ComputeDelta(
    Dictionary<uint, LocalSnapshotEntry> current,
    Dictionary<uint, LocalSnapshotEntry> lastPushed,
    string clientId)
{
    var result = new List<PushEntry>();
    foreach (var kv in current)
    {
        if (kv.Value == null || string.IsNullOrEmpty(kv.Value.Nick)) continue;
        LocalSnapshotEntry prev;
        if (lastPushed.TryGetValue(kv.Key, out prev))
        {
            if (prev != null && prev.Nick == kv.Value.Nick && prev.ClassId == kv.Value.ClassId) continue;
        }
        result.Add(new PushEntry
        {
            EntityId = kv.Key,
            Nick = kv.Value.Nick,
            ClassId = kv.Value.ClassId,
            ClientId = clientId
        });
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
    // Parser tolerante — regex simples pra extrair objetos flat (sem nesting).
    var rx = new System.Text.RegularExpressions.Regex(
        "\\{\\s*\"entity_id\"\\s*:\\s*(\\d+)\\s*,\\s*\"nick\"\\s*:\\s*(\"[^\"]*\"|null)\\s*,\\s*\"class_id\"\\s*:\\s*(\\d+|null)\\s*,\\s*\"client_id\"\\s*:\\s*(\"[^\"]*\"|null)\\s*,\\s*\"updated_at\"\\s*:\\s*\"([^\"]+)\"\\s*\\}");
    foreach (System.Text.RegularExpressions.Match m in rx.Matches(bodyJson))
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
        // Nota: incoming pode ter entity_id fora do range (mob 0x05xxxxxx etc.)
        //       filtro em MergePullIntoCache — aqui parse é literal.
        _tmp[id] = e;
        result.Add(e);
    }
    return result;
}

// staging pra ID→entry na parse (não usado externo; caller usa RemoteEntry.EntityId? não temos.
// Simplify: incluir EntityId no RemoteEntry.
```

**Correção:** `RemoteEntry` precisa ter `EntityId` pra o merge funcionar. Ajustar classe:

```csharp
public class RemoteEntry
{
    public uint EntityId;
    public string Nick;
    public int ClassId;
    public DateTime UpdatedAt;
    public string ClientId;
}
```

E remover a variável `_tmp` (não precisa) — setar `e.EntityId = id` diretamente antes de `result.Add(e)`.

Implementar `MergePullIntoCache`:

```csharp
internal static int MergePullIntoCache(List<RemoteEntry> incoming, Dictionary<uint, RemoteEntry> cache)
{
    int changed = 0;
    foreach (var e in incoming)
    {
        if (e == null || e.EntityId == 0 || string.IsNullOrEmpty(e.Nick)) continue;
        RemoteEntry cur;
        if (cache.TryGetValue(e.EntityId, out cur))
        {
            if (cur.UpdatedAt >= e.UpdatedAt) continue;   // já temos versão mais nova/igual
        }
        cache[e.EntityId] = e;
        changed++;
    }
    return changed;
}
```

- [ ] **Step 4: Rebuild + rodar unit**

```
.\build.bat
powershell -ExecutionPolicy Bypass -File tools\_test-community-sync.ps1 unit
```
Expected: PASS.

- [ ] **Step 5: Commit**

```
git add src/CommunitySync.cs tools/_test-community-sync.ps1 src/WS-engine.cs
git commit -m "feat(community): pure helpers (ComputeDelta, Serialize, Parse, Merge)

Sem I/O, sem thread. Testados via CLI --community-unit-delta."
```

---

## Task 6: Cache file I/O + Review Focus item 2

**Files:**
- Modify: `src/CommunitySync.cs`

**Interfaces:**
- Consumes: `_root`, `_cache`, `_lock`, `RemoteEntry`, `MergePullIntoCache`
- Produces:
  - `internal static Dictionary<uint,RemoteEntry> LoadCacheFromDisk(string root)` — retorna dict vazio se arquivo missing/corrupto
  - `internal static void SaveCacheToDisk(string root, Dictionary<uint,RemoteEntry> cache)` — atomic write via `.tmp` + `File.Replace`

- [ ] **Step 1: Adicionar teste — cache corrupto não crasha**

Adicionar CLI branch:

```csharp
if (args.Length > 0 && args[0] == "--community-unit-cache")
{
    string root = Path.GetDirectoryName(System.Reflection.Assembly.GetExecutingAssembly().Location);
    string p = Path.Combine(root, "ws-engine.community-cache.json");
    string bak = null;
    if (File.Exists(p)) { bak = File.ReadAllText(p); File.Delete(p); }
    try
    {
        // Arquivo missing → dict vazio
        var d = CommunitySync.LoadCacheFromDisk(root);
        if (d.Count != 0) { Console.Error.WriteLine("FAIL: missing file should return empty"); return 1; }

        // Arquivo corrupto → dict vazio, sem exceção
        File.WriteAllText(p, "{corrupted json,,,");
        d = CommunitySync.LoadCacheFromDisk(root);
        if (d.Count != 0) { Console.Error.WriteLine("FAIL: corrupt file should return empty"); return 1; }

        // Round-trip: save → load
        d[0x00692DA2u] = new CommunitySync.RemoteEntry {
            EntityId = 0x00692DA2u, Nick = "Centablg", ClassId = 10,
            UpdatedAt = new DateTime(2026, 9, 23, 12, 0, 0, DateTimeKind.Utc),
            ClientId = "0x00692DA2"
        };
        CommunitySync.SaveCacheToDisk(root, d);
        var d2 = CommunitySync.LoadCacheFromDisk(root);
        if (d2.Count != 1 || d2[0x00692DA2u].Nick != "Centablg") {
            Console.Error.WriteLine("FAIL: round-trip broken");
            return 1;
        }
        Console.WriteLine("PASS: unit-cache (missing, corrupt, round-trip)");
        return 0;
    }
    finally
    {
        if (bak != null) File.WriteAllText(p, bak);
        else if (File.Exists(p)) File.Delete(p);
    }
}
```

E no ps1:
```powershell
$out = & $exe --community-unit-cache 2>&1
if ($LASTEXITCODE -ne 0) { Write-Error "FAIL unit-cache: $out"; exit 1 }
Write-Host $out
```

- [ ] **Step 2: Rodar — falha (métodos não existem)**

- [ ] **Step 3: Implementar em `CommunitySync.cs`**

```csharp
const string CacheFileName = "ws-engine.community-cache.json";

internal static Dictionary<uint, RemoteEntry> LoadCacheFromDisk(string root)
{
    var result = new Dictionary<uint, RemoteEntry>();
    try
    {
        string p = Path.Combine(root, CacheFileName);
        if (!File.Exists(p)) return result;
        string body = File.ReadAllText(p);
        DateTime unused;
        var list = ParsePullResponse(body, out unused);
        foreach (var e in list)
        {
            if (e.EntityId == 0 || string.IsNullOrEmpty(e.Nick)) continue;
            result[e.EntityId] = e;
        }
    }
    catch { /* return empty */ }
    return result;
}

internal static void SaveCacheToDisk(string root, Dictionary<uint, RemoteEntry> cache)
{
    try
    {
        string p = Path.Combine(root, CacheFileName);
        string tmp = p + ".tmp";
        var sb = new System.Text.StringBuilder();
        sb.Append('[');
        bool first = true;
        foreach (var kv in cache)
        {
            var e = kv.Value;
            if (e == null || string.IsNullOrEmpty(e.Nick)) continue;
            if (!first) sb.Append(','); first = false;
            sb.Append("{\"entity_id\":").Append(e.EntityId)
              .Append(",\"nick\":").Append(JsonString(e.Nick))
              .Append(",\"class_id\":").Append(e.ClassId > 0 ? e.ClassId.ToString() : "null")
              .Append(",\"client_id\":").Append(JsonString(e.ClientId ?? ""))
              .Append(",\"updated_at\":\"").Append(e.UpdatedAt.ToUniversalTime().ToString("o")).Append("\"}");
        }
        sb.Append(']');
        File.WriteAllText(tmp, sb.ToString(), System.Text.Encoding.UTF8);
        if (File.Exists(p)) File.Replace(tmp, p, null);
        else File.Move(tmp, p);
    }
    catch { /* swallow — próximo save tenta de novo */ }
}
```

- [ ] **Step 4: Rebuild + rodar unit**

```
.\build.bat
powershell -ExecutionPolicy Bypass -File tools\_test-community-sync.ps1 unit
```
Expected: PASS.

- [ ] **Step 5: Commit**

```
git add src/CommunitySync.cs tools/_test-community-sync.ps1 src/WS-engine.cs
git commit -m "feat(community): cache file load/save + corruption handling

Atomic write via .tmp + File.Replace. Load tolerante a arquivo missing
ou JSON corrupto (retorna dict vazio, não lança)."
```

---

## Task 7: Push loop thread

**Files:**
- Modify: `src/CommunitySync.cs`

**Interfaces:**
- Consumes: `_root`, `_clientId`, `HttpPostJson`, `ComputeDelta`, `SerializeBatch`
- Produces:
  - `static void PushLoop()` — thread body
  - `static Dictionary<uint,LocalSnapshotEntry> _lastPushedSnapshot`
  - `static Dictionary<uint,LocalSnapshotEntry> LoadLocalSnapshotFromMemJsons(string root)` — lê `ws-engine.mem-players.json` + `ws-engine.mem-player-classes.json`

- [ ] **Step 1: Adicionar teste — LoadLocalSnapshotFromMemJsons parse**

Adicionar CLI branch:

```csharp
if (args.Length > 0 && args[0] == "--community-unit-loadmem")
{
    string root = Path.GetDirectoryName(System.Reflection.Assembly.GetExecutingAssembly().Location);
    string p1 = Path.Combine(root, "ws-engine.mem-players.json");
    string p2 = Path.Combine(root, "ws-engine.mem-player-classes.json");
    string bak1 = File.Exists(p1) ? File.ReadAllText(p1) : null;
    string bak2 = File.Exists(p2) ? File.ReadAllText(p2) : null;
    try
    {
        File.WriteAllText(p1, "{\"0x00692DA2\": \"Centablg\", \"0x006D8A08\": \"Ncro\"}");
        File.WriteAllText(p2, "{\"0x00692DA2\": 10, \"0x006D8A08\": 5}");
        var snap = CommunitySync.LoadLocalSnapshotFromMemJsons(root);
        if (snap.Count != 2) { Console.Error.WriteLine("FAIL: expected 2 entries, got " + snap.Count); return 1; }
        if (snap[0x00692DA2u].Nick != "Centablg" || snap[0x00692DA2u].ClassId != 10) {
            Console.Error.WriteLine("FAIL: Centablg wrong"); return 1;
        }
        Console.WriteLine("PASS: unit-loadmem");
        return 0;
    }
    finally
    {
        if (bak1 != null) File.WriteAllText(p1, bak1); else File.Delete(p1);
        if (bak2 != null) File.WriteAllText(p2, bak2); else File.Delete(p2);
    }
}
```

- [ ] **Step 2: Rodar — falha**

- [ ] **Step 3: Implementar `LoadLocalSnapshotFromMemJsons`**

```csharp
static Dictionary<uint, LocalSnapshotEntry> _lastPushedSnapshot = new Dictionary<uint, LocalSnapshotEntry>();

internal static Dictionary<uint, LocalSnapshotEntry> LoadLocalSnapshotFromMemJsons(string root)
{
    var result = new Dictionary<uint, LocalSnapshotEntry>();
    try
    {
        string pPlayers = Path.Combine(root, "ws-engine.mem-players.json");
        if (File.Exists(pPlayers))
        {
            var rx = new System.Text.RegularExpressions.Regex("\"0x([0-9A-Fa-f]+)\"\\s*:\\s*\"([^\"]*)\"");
            foreach (System.Text.RegularExpressions.Match m in rx.Matches(File.ReadAllText(pPlayers)))
            {
                uint id = Convert.ToUInt32(m.Groups[1].Value, 16);
                if (id == 0) continue;
                string nick = m.Groups[2].Value;
                if (string.IsNullOrEmpty(nick)) continue;
                result[id] = new LocalSnapshotEntry { Nick = nick, ClassId = 0 };
            }
        }
        string pClasses = Path.Combine(root, "ws-engine.mem-player-classes.json");
        if (File.Exists(pClasses))
        {
            var rx = new System.Text.RegularExpressions.Regex("\"0x([0-9A-Fa-f]+)\"\\s*:\\s*(\\d+)");
            foreach (System.Text.RegularExpressions.Match m in rx.Matches(File.ReadAllText(pClasses)))
            {
                uint id = Convert.ToUInt32(m.Groups[1].Value, 16);
                int cid = int.Parse(m.Groups[2].Value);
                LocalSnapshotEntry e;
                if (result.TryGetValue(id, out e)) e.ClassId = cid;
                // Se class sem nick, ignora — precisamos do nick pra subir.
            }
        }
    }
    catch { }
    return result;
}
```

- [ ] **Step 4: Implementar `PushLoop` + integrar em `Init`**

Adicionar constantes + method:

```csharp
const int PushIntervalMs = 60_000;
const int MaxBatch = 500;
static int _pushBackoffMultiplier = 1;

static void PushLoop()
{
    while (!_stopping)
    {
        try
        {
            var current = LoadLocalSnapshotFromMemJsons(_root);
            var delta = ComputeDelta(current, _lastPushedSnapshot, _clientId);
            if (delta.Count > 0)
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
                        // Sucesso — atualiza lastPushed pra chunk
                        foreach (var e in chunk)
                        {
                            _lastPushedSnapshot[e.EntityId] = new LocalSnapshotEntry {
                                Nick = e.Nick, ClassId = e.ClassId
                            };
                        }
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
        catch (Exception ex)
        {
            PersistLogCommunity("push exception: " + ex.Message);
        }

        int waitMs = PushIntervalMs * _pushBackoffMultiplier;
        for (int slept = 0; slept < waitMs && !_stopping; slept += 500) Thread.Sleep(500);
    }
}

static void PersistLogCommunity(string msg)
{
    try
    {
        string line = "[" + DateTime.Now.ToString("HH:mm:ss") + "] [community] " + msg + Environment.NewLine;
        File.AppendAllText(Path.Combine(_root, "wsengine.log"), line);
    }
    catch { }
}
```

Atualizar `Init`:

```csharp
public static void Init(string root, string url, string anonKey, bool enabled, string version)
{
    _root = root;
    _baseUrl = (url ?? "").TrimEnd('/');
    _anonKey = anonKey ?? "";
    _enabled = enabled && !string.IsNullOrEmpty(_baseUrl) && !string.IsNullOrEmpty(_anonKey);
    _version = version ?? "unknown";
    _clientId = ResolveClientId(root);
    if (!_enabled) return;

    // Load cache from disk INTO _cache
    var loaded = LoadCacheFromDisk(root);
    lock (_lock) { foreach (var kv in loaded) _cache[kv.Key] = kv.Value; }

    _stopping = false;
    _pushThread = new Thread(PushLoop) { IsBackground = true, Name = "CommunitySync.Push" };
    _pushThread.Start();
    // Pull + Heartbeat threads em Tasks 8 e 9.
    PersistLogCommunity("enabled, client_id=" + _clientId + " backend=" + _baseUrl + " cached=" + loaded.Count);
}
```

- [ ] **Step 5: Rebuild + rodar unit**

```
.\build.bat
powershell -ExecutionPolicy Bypass -File tools\_test-community-sync.ps1 unit
```
Expected: PASS all.

- [ ] **Step 6: Commit**

```
git add src/CommunitySync.cs tools/_test-community-sync.ps1 src/WS-engine.cs
git commit -m "feat(community): push loop thread + mem-json snapshot loader

PushLoop tick 60s: diff local vs lastPushed → POST batch (max 500/req).
Backoff exponencial em erro (2×, cap 30×). Enabled=false → thread nunca
inicia."
```

---

## Task 8: Pull loop thread + config bloco community

**Files:**
- Modify: `src/CommunitySync.cs` (PullLoop)
- Modify: `src/WS-engine.cs` (config parser + Init wire)

**Interfaces:**
- Consumes: `_root`, `HttpGetJson`, `ParsePullResponse`, `MergePullIntoCache`, `SaveCacheToDisk`
- Produces: pull thread rodando; `SubmitEnabledStatus()` retorna bool pro CLI

- [ ] **Step 1: Adicionar teste integration — pull retorna dados**

Precondição: Task 1 aplicada, projeto Supabase real, credenciais em variáveis de ambiente `$env:WSE_URL` e `$env:WSE_KEY`.

Em `_test-community-sync.ps1` (mode=integration):

```powershell
if (-not $env:WSE_URL -or -not $env:WSE_KEY) {
    Write-Warning "Skip pull test — set WSE_URL and WSE_KEY env vars"
} else {
    # Wipe entities via SQL RPC não é possível com anon-key — clean manual via SQL Editor.
    # Push 1 entry via curl → asserta pull no client.
    $body = '[{"entity_id":6893474,"nick":"Centablg","class_id":10,"client_id":"test-runner"}]'
    $r = Invoke-WebRequest -Uri "$env:WSE_URL/rest/v1/entities?on_conflict=entity_id" `
        -Method POST -Body $body -ContentType "application/json" `
        -Headers @{ "apikey" = $env:WSE_KEY; "Authorization" = "Bearer $env:WSE_KEY"; "Prefer" = "resolution=merge-duplicates,return=minimal" }
    if ($r.StatusCode -ne 201) { Write-Error "FAIL: seed push status=$($r.StatusCode)"; exit 1 }

    # Roda --community-pull-once (branch novo)
    $out = & $exe --community-pull-once $env:WSE_URL $env:WSE_KEY 2>&1
    if ($out -notmatch "pulled=1") { Write-Error "FAIL: expected pulled=1, got: $out"; exit 1 }
    Write-Host "PASS: pull-once"
}
```

- [ ] **Step 2: Adicionar CLI `--community-pull-once`**

Em `WS-engine.cs`:

```csharp
if (args.Length >= 3 && args[0] == "--community-pull-once")
{
    string root = Path.GetDirectoryName(System.Reflection.Assembly.GetExecutingAssembly().Location);
    CommunitySync.Init(root, args[1], args[2], true, "cli-pull-once");
    int n = CommunitySync.PullOnce();
    Console.WriteLine("pulled=" + n);
    return 0;
}
```

- [ ] **Step 3: Implementar `PullOnce` + `PullLoop`**

Em `CommunitySync.cs`:

```csharp
const int PullIntervalMs = 5 * 60_000;
static DateTime _lastPullAt = DateTime.MinValue;
static int _pullBackoffMultiplier = 1;

public static int PullOnce()
{
    string sinceIso = _lastPullAt == DateTime.MinValue
        ? "1970-01-01T00:00:00Z"
        : _lastPullAt.ToString("o");
    string url = "entities?updated_at=gt." + Uri.EscapeDataString(sinceIso)
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
        if (changed > 0) SaveCacheToDisk(_root, _cache);
    }
    if (maxAt > _lastPullAt) _lastPullAt = maxAt;
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
```

Wire no `Init` (após criar `_pushThread`):

```csharp
_pullThread = new Thread(PullLoop) { IsBackground = true, Name = "CommunitySync.Pull" };
_pullThread.Start();
```

- [ ] **Step 4: Wire config parser em `WS-engine.cs`**

Localizar o bloco onde `ws-engine.config.json` é lido. Adicionar parse do sub-objeto `community` via regex simples:

```csharp
// Depois de LoadConfig() ou equivalente
string communityUrl = "";
string communityKey = "";
bool communityEnabled = true;
try
{
    string cfgPath = Path.Combine(root, "ws-engine.config.json");
    if (File.Exists(cfgPath))
    {
        string body = File.ReadAllText(cfgPath);
        var mUrl = System.Text.RegularExpressions.Regex.Match(body,
            "\"community\"\\s*:\\s*\\{[^}]*\"url\"\\s*:\\s*\"([^\"]*)\"");
        if (mUrl.Success) communityUrl = mUrl.Groups[1].Value;
        var mKey = System.Text.RegularExpressions.Regex.Match(body,
            "\"community\"\\s*:\\s*\\{[^}]*\"anonKey\"\\s*:\\s*\"([^\"]*)\"");
        if (mKey.Success) communityKey = mKey.Groups[1].Value;
        var mEn = System.Text.RegularExpressions.Regex.Match(body,
            "\"community\"\\s*:\\s*\\{[^}]*\"enabled\"\\s*:\\s*(true|false)");
        if (mEn.Success) communityEnabled = (mEn.Groups[1].Value == "true");
    }
}
catch { }

// Defaults hardcoded (substituir por URL/key reais do projeto Supabase criado na Task 1)
if (string.IsNullOrEmpty(communityUrl)) communityUrl = "https://REPLACE_ME.supabase.co/rest/v1";
if (string.IsNullOrEmpty(communityKey)) communityKey = "REPLACE_ME_ANON_KEY";

string ver = "unknown";
try { ver = System.Diagnostics.FileVersionInfo.GetVersionInfo(
    System.Reflection.Assembly.GetExecutingAssembly().Location).FileVersion ?? "unknown"; }
catch { }
CommunitySync.Init(root, communityUrl, communityKey, communityEnabled, ver);

// Seed autoNameCache + playerClassId com cache remoto (não overwrite)
CommunitySync.SeedFromCache(autoNameCache, playerClassId);
```

Nota: substituir `REPLACE_ME` pelos valores reais da Task 1 Step 2 antes de rodar.

- [ ] **Step 5: Rebuild + rodar unit + integration**

```
.\build.bat
powershell -ExecutionPolicy Bypass -File tools\_test-community-sync.ps1 unit
$env:WSE_URL = "<url>"; $env:WSE_KEY = "<key>"
powershell -ExecutionPolicy Bypass -File tools\_test-community-sync.ps1 integration
```
Expected: unit PASS, integration PASS (pulled=1).

- [ ] **Step 6: Commit**

```
git add src/CommunitySync.cs src/WS-engine.cs tools/_test-community-sync.ps1
git commit -m "feat(community): pull loop + config parser + seed cache

PullOnce() sync via ?updated_at=gt.<since>. Merge no-overwrite policy.
Config parser lê bloco community de ws-engine.config.json. SeedFromCache
popula autoNameCache/playerClassId no boot."
```

---

## Task 9: Heartbeat loop + shutdown wiring

**Files:**
- Modify: `src/CommunitySync.cs` (HeartbeatLoop)
- Modify: `src/WS-engine.cs` (OnFormClosing)

**Interfaces:**
- Consumes: `HttpPostJson`, `_clientId`, `_version`
- Produces: heartbeat thread rodando; `Stop()` faz `Thread.Join` com timeout

- [ ] **Step 1: Implementar `HeartbeatLoop`**

Em `CommunitySync.cs`:

```csharp
const int HeartbeatIntervalMs = 5 * 60_000;

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
```

Wire em `Init` (após `_pullThread.Start()`):

```csharp
_hbThread = new Thread(HeartbeatLoop) { IsBackground = true, Name = "CommunitySync.Heartbeat" };
_hbThread.Start();
```

- [ ] **Step 2: Melhorar `Stop()` — join com timeout**

```csharp
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
```

- [ ] **Step 3: Wire `OnFormClosing` em `WS-engine.cs`**

Localizar override de `OnFormClosing` (se existir) ou adicionar:

```csharp
protected override void OnFormClosing(FormClosingEventArgs e)
{
    try { CommunitySync.Stop(); } catch { }
    base.OnFormClosing(e);
}
```

Se já existir override, adicionar `CommunitySync.Stop();` como primeira linha.

- [ ] **Step 4: Adicionar teste integration — heartbeat aparece no /clients**

Em `_test-community-sync.ps1` (integration):

```powershell
if ($env:WSE_URL -and $env:WSE_KEY) {
    # Roda WS-engine em background por 8s (tempo suficiente pra DoHeartbeat inicial)
    $job = Start-Job -ScriptBlock {
        param($exe, $url, $key)
        $cfg = @{ community = @{ enabled = $true; url = $url; anonKey = $key } } | ConvertTo-Json -Depth 5
        # Escrever config temporário seria complexo — usar CLI hb-once no lugar
    } -ArgumentList $exe, $env:WSE_URL, $env:WSE_KEY

    $out = & $exe --community-hb-once $env:WSE_URL $env:WSE_KEY 2>&1
    if ($LASTEXITCODE -ne 0) { Write-Error "FAIL hb-once: $out"; exit 1 }

    # Verifica via HTTP que client apareceu
    $r = Invoke-WebRequest -Uri "$env:WSE_URL/rest/v1/clients?client_id=eq.hb-test-client&select=*" `
        -Headers @{ "apikey" = $env:WSE_KEY; "Authorization" = "Bearer $env:WSE_KEY" }
    if ($r.Content -notmatch "hb-test-client") { Write-Error "FAIL: client not registered"; exit 1 }
    Write-Host "PASS: heartbeat integration"
}
```

E CLI branch:

```csharp
if (args.Length >= 3 && args[0] == "--community-hb-once")
{
    string root = Path.GetDirectoryName(System.Reflection.Assembly.GetExecutingAssembly().Location);
    // Força client_id conhecido pro teste
    File.WriteAllText(Path.Combine(root, "ws-engine.client-id.txt"), "hb-test-client");
    try { File.Delete(Path.Combine(root, "ws-engine.me.txt")); } catch { }
    CommunitySync.Init(root, args[1], args[2], true, "cli-hb");
    CommunitySync.HeartbeatOnce();   // método público novo
    return 0;
}
```

Adicionar em `CommunitySync.cs`:

```csharp
public static void HeartbeatOnce() { DoHeartbeat(); }
```

- [ ] **Step 5: Rebuild + rodar**

```
.\build.bat
powershell -ExecutionPolicy Bypass -File tools\_test-community-sync.ps1 integration
```
Expected: PASS.

- [ ] **Step 6: Commit**

```
git add src/CommunitySync.cs src/WS-engine.cs tools/_test-community-sync.ps1
git commit -m "feat(community): heartbeat loop + shutdown wiring

HeartbeatLoop tick 5min POST /clients upsert com observer + version.
Stop() faz Join(2s) em todas threads. OnFormClosing chama Stop."
```

---

## Task 10: --community-status CLI completo + PushStatusToUI opcional

**Files:**
- Modify: `src/CommunitySync.cs` (getters de stats)
- Modify: `src/WS-engine.cs` (--community-status output rico)

**Interfaces:**
- Consumes: `_cache`, `_lastPullAt`, `_lastPushedSnapshot`, `_baseUrl`
- Produces:
  - `static DateTime LastPullAtUtc { get; }`
  - `static DateTime LastPushOkAtUtc { get; }` (nova var — bump em push sucesso)
  - `static string BackendUrl { get; }`

- [ ] **Step 1: Adicionar getters**

Em `CommunitySync.cs`:

```csharp
static DateTime _lastPushOkAtUtc = DateTime.MinValue;

public static DateTime LastPullAtUtc { get { return _lastPullAt; } }
public static DateTime LastPushOkAtUtc { get { return _lastPushOkAtUtc; } }
public static string BackendUrl { get { return _baseUrl; } }
public static bool Enabled { get { return _enabled; } }
```

Bump `_lastPushOkAtUtc = DateTime.UtcNow;` dentro do bloco `Status 2xx` em `PushLoop`.

- [ ] **Step 2: Enriquecer `--community-status`**

Substituir CLI branch da Task 2 por:

```csharp
if (args.Length > 0 && args[0] == "--community-status")
{
    string root = Path.GetDirectoryName(System.Reflection.Assembly.GetExecutingAssembly().Location);
    // Ler config real igual boot
    string communityUrl = "", communityKey = "";
    bool communityEnabled = true;
    try
    {
        string cfgPath = Path.Combine(root, "ws-engine.config.json");
        if (File.Exists(cfgPath))
        {
            string body = File.ReadAllText(cfgPath);
            var mUrl = System.Text.RegularExpressions.Regex.Match(body,
                "\"community\"\\s*:\\s*\\{[^}]*\"url\"\\s*:\\s*\"([^\"]*)\"");
            if (mUrl.Success) communityUrl = mUrl.Groups[1].Value;
            var mKey = System.Text.RegularExpressions.Regex.Match(body,
                "\"community\"\\s*:\\s*\\{[^}]*\"anonKey\"\\s*:\\s*\"([^\"]*)\"");
            if (mKey.Success) communityKey = mKey.Groups[1].Value;
            var mEn = System.Text.RegularExpressions.Regex.Match(body,
                "\"community\"\\s*:\\s*\\{[^}]*\"enabled\"\\s*:\\s*(true|false)");
            if (mEn.Success) communityEnabled = (mEn.Groups[1].Value == "true");
        }
    }
    catch { }

    CommunitySync.Init(root, communityUrl, communityKey, communityEnabled, "cli-status");
    Console.WriteLine("client_id: " + CommunitySync.ClientIdForDiag);
    Console.WriteLine("enabled: " + CommunitySync.Enabled);
    Console.WriteLine("backend: " + CommunitySync.BackendUrl);
    Console.WriteLine("cache: " + CommunitySync.CachedCount + " entries");
    Console.WriteLine("last_pull_utc: " + (CommunitySync.LastPullAtUtc == DateTime.MinValue ? "never" : CommunitySync.LastPullAtUtc.ToString("o")));

    // Probe conectividade
    if (CommunitySync.Enabled)
    {
        int pulled = CommunitySync.PullOnce();
        Console.WriteLine("probe_pull: " + pulled + " entries");
    }
    CommunitySync.Stop();
    return 0;
}
```

- [ ] **Step 3: Adicionar teste — --community-status output completo**

Em `_test-community-sync.ps1` (unit):

```powershell
$out = & $exe --community-status 2>&1
$expected = @("client_id:", "enabled:", "backend:", "cache:", "last_pull_utc:")
foreach ($needle in $expected) {
    if ($out -notmatch [regex]::Escape($needle)) {
        Write-Error "FAIL: --community-status missing '$needle'`n$out"
        exit 1
    }
}
Write-Host "PASS: --community-status rich output"
```

- [ ] **Step 4: Rebuild + rodar**

```
.\build.bat
powershell -ExecutionPolicy Bypass -File tools\_test-community-sync.ps1 unit
```
Expected: PASS.

- [ ] **Step 5: Commit**

```
git add src/CommunitySync.cs src/WS-engine.cs tools/_test-community-sync.ps1
git commit -m "feat(community): --community-status output completo

Imprime client_id, enabled, backend, cache count, last_pull_utc + faz
probe_pull sincrono contra backend. Útil pra troubleshoot sem abrir GUI."
```

---

## Task 11: Smoke test end-to-end + docs finais

**Files:**
- Create: `docs/community-sync-troubleshoot.md`
- Modify: `SETUP.md` (finalizar seção 6)
- Modify: `.gitignore` (adicionar `ws-engine.community-cache.json` + `ws-engine.client-id.txt`)

**Interfaces:**
- Consumes: nada
- Produces: doc de troubleshoot + smoke passing

- [ ] **Step 1: Adicionar entradas ao `.gitignore`**

```
ws-engine.community-cache.json
ws-engine.client-id.txt
```

- [ ] **Step 2: Criar `docs/community-sync-troubleshoot.md`**

```markdown
# Community Sync — Troubleshoot

## Verificar estado atual

```
WS-engine.exe --community-status
```

Imprime client_id, se está enabled, URL backend, tamanho do cache local,
timestamp do último pull e faz probe pull síncrono contra backend.

## Ver logs

Toda linha do módulo é prefixada `[community]` em `wsengine.log`:

```
grep community wsengine.log
```

Eventos comuns:
- `[community] enabled, client_id=... backend=... cached=N` — boot OK
- `[community] push failed: status=... err=...` — falha temporária, backoff
- `[community] pull failed: ...` — mesmo
- `[community] heartbeat failed: ...` — mesmo
- `[community] 429 rate-limited` — backend a limitar, ignora

## Desligar sync

Editar `ws-engine.config.json`:

```json
{ "community": { "enabled": false } }
```

Restart. Nenhum byte sai.

## Resetar identidade

Fecha WS-engine, apaga `ws-engine.client-id.txt`. Novo GUID no próximo boot.

## Regenerar cache do zero

Fecha WS-engine, apaga `ws-engine.community-cache.json`. Próximo pull
baixa tudo desde o zero (limit 5000 rows).
```

- [ ] **Step 3: Rodar smoke test — 2 processos em máquinas diferentes**

Manual (não automatizável):
1. Máquina A e B ambas com WS-engine + Warspear rodando.
2. Máquina A: `wsengine.log` deve conter `[community] enabled ... client_id=0x<HEXA>`.
3. Após 60s: `wsengine.log` da máquina A: `[community] push ok` (ou similar).
4. Máquina B, após 5min: `wsengine.log` contém `[community] pulled=N` com N>0.
5. Máquina B: `--community-status` mostra `cache: N entries` com N incluindo IDs vistos pela máquina A mas não pela B.

Documentar no `wsengine.log` de A e B que o smoke passou (via `Add-Content wsengine.log "[SMOKE] ..."` manual).

- [ ] **Step 4: Rodar full test suite (unit + integration)**

```
.\build.bat
powershell -ExecutionPolicy Bypass -File tools\_test-community-sync.ps1 unit
$env:WSE_URL = "<url>"; $env:WSE_KEY = "<key>"
powershell -ExecutionPolicy Bypass -File tools\_test-community-sync.ps1 integration
```
Expected: todos PASS.

- [ ] **Step 5: Commit final + atualizar CLAUDE.md**

Adicionar seção no CLAUDE.md "Session log":

```markdown
- **2026-09-23 (Community sync)** — Novo módulo `src/CommunitySync.cs`
  sincroniza cache `entity_id → nick + classId` entre WS-engines via
  Supabase Postgres. 3 threads background (push 60s, pull 5min, heartbeat
  5min). Client-id via `ws-engine.me.txt` (char do user) ou GUID em
  `ws-engine.client-id.txt`. Aditivo puro — memscan/SQLite/decoders
  intocados. Config: bloco `community` em `ws-engine.config.json`.
  Smoke test: 2 máquinas viram os mesmos nicks/classes após 1 ciclo pull.
```

```
git add .gitignore docs/community-sync-troubleshoot.md SETUP.md CLAUDE.md
git commit -m "docs(community): troubleshoot doc + gitignore + session log

Fecha feature Community Sync v1. Smoke test 2 máquinas OK."
```

---

## Notas finais

- **Ordem obrigatória:** Tasks 1→11. Task 2 introduz módulo, Tasks 3-9 completam camadas, 10 e 11 são polish + validação.
- **Backend real vs local:** integration tests exigem projeto Supabase real (var env `WSE_URL` + `WSE_KEY`). Unit tests independem de rede.
- **Rollback:** se qualquer task quebrar produção, revert commit + `config.community.enabled=false` em máquinas afetadas. Nada persistente muda no SQLite/memscan.
- **Diferido pra v1.1 / v2:** UI card COMMUNITY no dashboard (spec seção 4.6), FileSystemWatcher em me.txt, pagination >5K entities, voting anti-troll, Supabase Realtime.
