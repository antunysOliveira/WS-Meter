# Plano — captura contínua + lutas como segmentos

**Data:** 2026-09-21. Origem: sessão Tecnópolis mostrou que todos os
gaps (pet órfão Koryceif, classe ausente, Defensoras 683) vêm de
pacotes que passaram antes do dumpcap iniciar.

## Objetivo

Desacoplar tempo-de-vida da CAPTURA do tempo-de-vida da LUTA.

**Estado alvo**:
- CAPTURA = tempo-de-vida do processo Warspear.exe (auto)
- LUTA = segmento lógico dentro da captura (botão play/stop = "nova luta")
- PERSISTENTE (pet→dono, classes, nomes, guilds, self) nunca zera no botão
- LUTA (dmg/recv/heal/DPS/MAX/timer) zera no botão

## Fase 1 — Process Monitor + Auto-Capture

**Novos arquivos**:
- `src/ProcessMonitor.cs` — poll `Process.GetProcessesByName("Warspear")`
  a cada 2s, dispara `OnGameStarted` / `OnGameStopped`.

**Mudanças em `WS-engine.cs`**:
- No constructor: `pm.OnGameStarted += StartCapture; pm.OnGameStopped += StopCapture; pm.Start();`
- Se Warspear já rodando ao boot: chama StartCapture imediatamente
  + push status "captura iniciada com jogo em andamento" via WebViewHost.
- `StartCapture()` sem confirmação; loga `warspear_started_ts`.

**Watchdog**:
- Se `OnProcExited` disparar e Warspear ainda estiver rodando →
  ProcessMonitor detecta e chama StartCapture de novo. Novo pcap.
- SQLite: `sessions` table já tem `pcap_path` — cada restart cria
  nova session (mantém contexto legível).

**Rotação**:
- dumpcap suporta `-b filesize:N` (KB) e `-b duration:N` (segundos)
  para ring/incrementing. Adotar `-b filesize:102400 -b files:20`
  = 20 arquivos de 100MB cada, ~2GB max, ~30h de captura contínua.
- Cada arquivo novo = nova session no DB (session_id herda contexto).

**Aceite Fase 1**: abrir WS-engine com Warspear fechado, abrir jogo,
capture inicia sozinha; fechar jogo, capture para; matar dumpcap, ele
reinicia.

## Fase 2 — Split PersistentState vs BoutState

**Novo arquivo**: `src/BoutState.cs`
```csharp
class BoutState {
    public DateTime StartedAt;
    public long BoutId;               // FK sessions/raw_messages
    public Dictionary<uint, DamageAgg> PerAttacker;
    public Dictionary<uint, long> PerTargetReceived;
    public Dictionary<uint, long> PerTargetHealed;
    public double MaxHit;
    public int TotalHits;
    public double LastDamageTime;
    public void ResetForNewBout();
}
```

`PersistentState` (fica em `MainForm` como campos):
- `nameMap`, `guildMap`, `classMap` (já existem — permanecem)
- `SummonOwnerMap` singleton (já existe — permanece)
- `myEntityId`, nicknames (já existem — permanecem)

`btnStart` (STOP/START) muda de "capture toggle" para "bout toggle":
- START → `_bout.ResetForNewBout()` + emit `BoutStarted` message
- STOP → freeze bout state, keep displaying totals

Auto-detect início de luta (opcional Fase 2b):
- Se `now - _bout.LastDamageTime > 30s` E chega evento 427 → auto-start
  new bout. (Pode ser toggle na UI.)

## Fase 3 — SQLite bouts table

Schema:
```sql
CREATE TABLE bouts (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  session_id INTEGER NOT NULL,
  iniciada_em INTEGER NOT NULL,
  encerrada_em INTEGER,
  raw_id_min INTEGER,      -- first raw_messages.id
  raw_id_max INTEGER,      -- last raw_messages.id
  label TEXT,              -- optional user-set name/zone
  FOREIGN KEY(session_id) REFERENCES sessions(id)
);
CREATE INDEX ix_bouts_session ON bouts(session_id);
```

API:
- `Database.StartBout(sessionId) → long boutId`
- `Database.EndBout(boutId, rawIdMin, rawIdMax, label)`
- `Database.ListBouts(sessionId)` — pra picker "reprocess this bout"

Qualquer luta reprocessável: `SELECT body FROM raw_messages WHERE id BETWEEN raw_id_min AND raw_id_max` → feed no decoder atual.

## Fase 4 — Aceite final (critério do usuário)

Repetir cenário Tecnópolis:
1. Abrir WS-engine antes do Warspear
2. Abrir Warspear → captura inicia sozinha
3. Entrar em Tecnópolis
4. Fazer luta
5. Verificar: Koryceif com classe + pet atribuído, recv exato pra todos

Se bater 100% → arquitetura validada.
Se falhar → nova rodada de RE nos gaps específicos.

## Riscos / notas

- dumpcap ring buffer usa nome `<base>_00001.pcapng`, `<base>_00002.pcapng`,
  etc. Novo naming precisa ser handled em `RefreshCaptures` + Database.
- Se Warspear crashar e reabrir 3× em 1min, ficamos com 3 sessions
  curtas. Aceite: OK, cada uma persiste seu contexto.
- ProcessMonitor poll a cada 2s tem race — se dumpcap iniciar 2s
  depois do jogo, perde os 2s iniciais. Aceitável (spawn de pet leva
  mais que isso). Alt: hookar WMI event `Win32_ProcessStartTrace`.
- Watchdog restart: cuidado com loop infinito se dumpcap falha imediato
  (interface fechou). Após 3 falhas em 30s, parar e mostrar erro.

## Ordem sugerida de execução

1. **Fase 1** primeiro (auto-capture + watchdog) — resolve o gap
   principal.
2. **Fase 3** (bouts table) — infra pra Fase 2 fazer sentido.
3. **Fase 2** (split state) — UI/UX refactor.
4. **Fase 4** (aceite) — teste em cenário real.
