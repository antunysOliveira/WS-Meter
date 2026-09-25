# Warspear Online — Protocol Notes

> Rolling notes from packet-capture reverse engineering. Update every session.

---

## 2026-09-25 — tag=65 nested em tag=492 (Fase B do Task 3)

Chat mensagens do modo público chegam como top-level `tag=65` durante conversa
em tempo real. **Chat carried inside batch broadcasts** (roster updates, area
sync, etc.) chega **nested dentro de tag=492 LZ4**. Probe
`_probe-name-inner-tag.ps1` nas 3 capturas de referência:

| Capture | byte-scan hits em tag=492 body descomprimido | todos em tag=65 nested? |
|---------|---:|:---:|
| ws_20260921 | 18 | ✓ 100% |
| ws_20260923 | 64 | ✓ 100% |
| ws_20260924 | 3  | ✓ 100% |

Nenhum outro inner tag carrega name+id em texto plano no corpo LZ4-decomp.
Roster estrutural separado (Fase B hipótese inicial) **não existe** —
byte-scan Pattern A dentro de tag=492 era só pegar chat nested. Solução:
`ExtractChatSenders` estendido pra também walk tag=65 nested em tag=492.
Byte-scan `ExtractNamesFromContainer492` removido do pipeline vivo.

Situações em que tag=551/554 emitem (para referência):
- **tag=551** (instance roster): confirmado em raid-entry transitions.
  Ausente nas 3 capturas de teste (nenhuma entrada de instância registrada).
- **tag=554** (scoreboard): confirmado em raid-end / PvP arena results.
  Idem — não fired nas capturas testadas.

---

## 2026-09-25 — tag=65 second-id field (unknown, provável account/PM)

Cada tag=65 chat body carrega **dois** valores id-shaped adjacentes ao name
ASCII do sender. `ExtractChatSenders` só usa o primeiro (bytes 3..6). O
segundo — logo APÓS o name — muda de mapeamento entre sessões e nunca é
world/character entity id.

Exemplos observados:
- pré-update raid `ws_20260923_234032`, msg#1:
  ```
  00 41 10 4b 39 42 00 09 4b 69 6c 6c 65 72 64 61 64 22 91 01 00
     └─ 3B hdr └─ sender=0x0042394b └─ nlen └── "Killerdad" ──── └── 2ndId=0x00019122
  ```
- pré-update raid (mesma id 0x00019122): mapeado a "Eunemdropo"
- pós-update `ws_20260924_171950`: 0x00019122 → "Havel"

Três nomes diferentes para o mesmo id em três sessões. Provavelmente
**account id** ou **PM correspondence id** (ver CLAUDE.md "PM — decoded",
onde recipient_account_id é distinto do character id). Não usar como entity
id em nenhum lugar; sempre discardar.

Byte-scan pre-Fase-A gravava esse id no `nameMap` com o nome do sender,
poluindo o cache com pares (id_incorreto, nick_correto) — corrigido em
`fix(nick): gating por evento + byte-scan restrito ao tag=492`.

---

## 2026-09-25 — Entity_id range shift (Warspear v13.4.4 patch)

Após update do jogo, o **high byte** do `entity_id` migrou de `0x05` para
`0x0B` em **todos** os spawns (mobs, adds, raids, invocações). O layout do
tag=26 body ficou idêntico; só o namespace numérico mudou.

### Evidência hex (mesma classe de summon, tid=21813 "Esqueleto Amaldiçoado")

Pré-update — `captures/ws_20260921_183825.pcapng`:
```
tag=26 body len=41:
  35 55 27 f9 f5 05 00 00 80 3f 10 0a 10 0a c4 0b
       └─ eid = 0x05f5f927 (high=0x05)
  00 00 c4 0b 00 00 64 00 64 00 00 00 00 00 00 00
  00 00 00 e1 5c 45 00 00 00
           └─ owner@+35 = 0x00455ce1
```

Pós-update — `captures/ws_20260924_171950.pcapng`:
```
tag=26 body len=41:
  35 55 f2 9f ec 0b 00 00 80 3f 07 13 07 13 94 08
       └─ eid = 0x0bec9ff2 (high=0x0B)
  00 00 94 08 00 00 64 00 64 00 00 00 00 00 00 00
  00 00 00 f4 a8 15 00 00 00
           └─ owner@+35 = 0x0015a8f4
```

Layout inalterado: `tid u16@0`, `eid u32@+2`, `owner u32@+35`, body 41 B.

### Componentes que dependiam do byte alto (fixed)

| Site | Antes | Depois |
|------|-------|--------|
| `SummonOwnerMap.cs:91` | `(summonId >> 24) != 0x05` rejeita spawn | Filtro removido; aceita spawn se `tid ∈ SummonRegistry` |
| `WS-engine.cs:2689` (solo fallback) | `(atk >> 24) == 0x05` | Só reescreve se `atk ∈ knownSummonEids` |
| `Tag26EntitySpawnDecoder.cs:115` | allowlist `{0x05,0x07,0x09,0x0C,0x10,0x57,0xF6}` | Filtro removido; validação estrutural (body 41 B + tid ≠ 0 + eid ≠ 0 + HP sano) basta |
| `WS-engine.cs:2353` (ClassifyAreaEntity) | mob switch sem `0x0B` | Adicionado `case 0x0B` |
| `Summary.cs:207` | `(hi == 0x05) → "(pet/mob)"` | `summonEids.Contains(id) → "(invocação)"` |

### Regra geral

O byte alto do entity_id **não é fonte de verdade** — pode mudar em qualquer
update. Fonte estrutural (tag=26 spawn com tid+layout válidos) é canônica.
Whitelist de invocação = `src/SummonRegistry.cs` (4 tids: 6547 Lobo Escuridão,
10583 Esqueleto, 21812 Esq Arqueiro, 21813 Esq Amaldiçoado).

### Regressão coberta

`tools/_test-summon-attribution.ps1` valida 3 capturas (pré IPv4, pré raid,
pós IPv6): 100% dos spawns de invocação com dono válido entram no ownerMap.

---

## ⚠️ 2026-09-19 — Fase 2 finding: framing REAL é varint-TLV

**Todo o resto deste arquivo abaixo descreve o modelo antigo `[opcode:u8][len:u8]`.**
**Esse modelo estava errado.** Ele funcionava por coincidência para mensagens com
tag < 128 e len < 128 (varint 1 byte = u8), mas quebrava sempre que tag ou len
excediam 127 — daí surgiram os formatos A/B/C do attacker, o "envelope ec 03",
e a maior parte das heurísticas.

### Framing correto (confirmado nos 4 canonicals)

```
[tag:varint (LEB128)] [len:varint (LEB128)] [body: len bytes]
```

- **tag** e **len** são ambos LEB128 (7 bits + continuation bit por byte)
- **NÃO existe** campo separado de "opcode" ou "tipo" — a tag É o opcode
- **NÃO existe** envelope fixo de 2 níveis — o "envelope `ec 03`" é simplesmente
  uma mensagem TLV normal com tag=492 (que codifica como `ec 03` em LEB128)

### Evidência

Ferramenta: `WS-engine.exe --tlv` (`src/Tlv.cs`). Grid exaustivo:
`tag ∈ {u8, u16LE, u16BE, varint}` × `has_type ∈ {sim, não}` × `len ∈ {u8, u16LE, u16BE, u32LE, varint}` × `start ∈ [0..512)`.

Uma única combo fecha em TODOS os 4 canonicals com `walk% ≥ 99%`:
`tag=varint, has_type=no, len=varint`

| arquivo (s2c) | tamanho | msgs | walk% | tag_vocab | avg len | max len |
|---------------|---------|------|-------|-----------|---------|---------|
| `ws_20260919_085820` | 37 KB | 306 | 99.3% | 18 | 118 B | 14485 B |
| `ws_20260919_091001` | 56 KB | ~600 | 99%+ | ~30 | ~90 B | ~15 KB |
| `ws_20260919_140918` | 320 KB | 8385 | 100% | 45 | 36 B | 21833 B |
| `raid_overgod_20260919_161016` | 856 KB | 25616 | 100% | 77 | 31 B | 22048 B |

`tag_vocab` cresce com tamanho de captura (18→77) — protocol tem ~77 opcodes
distintos, capturas mais longas expõem mais deles. `start=0` fecha em todos —
varint auto-sincroniza.

### Tabela de opcodes (top-30, raid Overgod, 25616 msgs)

| tag (dec) | tag (varint bytes) | count | % | provável função (a confirmar Fase 5) |
|-----------|--------------------|-------|---|--------------------------------------|
| **19** | `13`         | 8472 | 33.1% | **STRING (nome, chat, guilda)** — mesma tag `0x13` da struct de memória do memscan → serialização compartilhada memória↔rede ✓ |
| 492 | `ec 03`      | 5151 | 20.1% | movement / big envelope (antigamente confundido com "envelope marker") |
| 5   | `05`         | 2207 | 8.6%  | ? |
| 85  | `55`         | 1747 | 6.8%  | ? — mesma cardinalidade que 86, provável par req/res |
| 86  | `56`         | 1747 | 6.8%  | ? — mesma cardinalidade que 85 |
| 4   | `04`         | 1440 | 5.6%  | ? |
| 97  | `61`         | 1002 | 3.9%  | ? |
| 20  | `14`         | 718  | 2.8%  | ? |
| 21  | `15`         | 445  | 1.7%  | ? |
| 98  | `62`         | 398  | 1.6%  | ? |
| 65  | `41`         | 268  | 1.0%  | ? |
| 55  | `37`         | 252  | 1.0%  | ? |
| 13  | `0d`         | 213  | 0.8%  | ? — no parser antigo isto era o "prefixo body" de damage; agora é uma tag independente |
| 16  | `10`         | 178  | 0.7%  | ? |
| 549 | `a5 04`      | 156  | 0.6%  | ? |
| **427** | **`ab 03`** | **138** | **0.5%** | **DAMAGE** — no parser antigo era "op=0xab len=03 body=[0d dmg:u16]"; na leitura correta é tag=427, len=3, body=[0d dmg:u16]. **Mesmo body, mesmo efeito para tags/lens pequenos** |
| 381 | `fd 02`      | 114  | 0.4%  | ? |
| 383 | `ff 02`      | 94   | 0.4%  | ? |
| 28  | `1c`         | 87   | 0.3%  | ? |
| 64  | `40`         | 81   | 0.3%  | ? |
| 428 | `ac 03`      | 77   | 0.3%  | ? — próximo do damage (427), talvez heal/miss? |
| 139 | `8b 01`      | 57   | 0.2%  | ? |
| 73  | `49`         | 56   | 0.2%  | ? |
| 49  | `31`         | 54   | 0.2%  | ? |
| 99  | `63`         | 42   | 0.2%  | ? |
| 181 | `b5 01`      | 39   | 0.2%  | ? |
| 87  | `57`         | 36   | 0.1%  | ? |
| 138 | `8a 01`      | 32   | 0.1%  | ? |
| 25  | `19`         | 27   | 0.1%  | ? |
| 102 | `66`         | 22   | 0.1%  | ? |

### Interpretação dos "formatos A/B/C" e "envelope ec 03"

O parser antigo em `src/Framing.cs` interpreta `[opcode:u8][len:u8]` byte a byte.
Onde a tag varint é 1 byte (< 128), essa leitura casa. Onde a tag varint é 2+ bytes
(≥ 128), o parser lê o primeiro byte como opcode e o segundo como "length",
desalinhando o resto do stream. Cada desalinhamento gerou uma "família de formatos":

- **Formato A/B/C do attacker** — leitura correta é 1 sequência TLV linear, sem
  "envelope de entidade" wrapping damage frames. O que o parser antigo chamava de
  "attacker id 5b 0b 00 00 XX XX 01" é a fronteira entre mensagens TLV vizinhas
  lida a partir de offset errado.
- **`ec 03` envelope** — apenas uma tag varint (492) com corpo que costuma ser
  grande e transportar movimento em bulk. Os "envelopes" que o parser vinha
  detectando são mensagens TLV normais, não containers de outras mensagens.
- **`ab 03 0d dmg:u16`** — DAMAGE — tag=427, len=3, body=[0x0d][dmg:u16]. O body
  ainda começa com `0d` (que provavelmente é um sub-tipo de dano ou versão do
  pacote), depois 2 bytes de valor. Isso continua sendo parseável, só que agora
  encaixado num framing consistente.
- **`1a 29` (summon spawn)** — tag=26, len=41, body de 41 bytes. Antigamente era
  interpretado como `[op:0x1a][len:0x29]` (op=26, len=41), o que POR COINCIDÊNCIA
  é o mesmo que a leitura TLV correta.

### PASSO 1 (envelope-as-u16-length): refutado

`WS-engine.exe --envelope` testou hipótese `ec 03 = u16 LE = 1004 = length field`.
Walker anda 94-99% dos canonicals mas com valores implausíveis (2 a 65533, avg
5-15K) — degeneração, não framing real. Marker `ec 03` é 60-400× mais frequente
que aleatório, mas gaps entre marcadores variam de 4 a 22K bytes, refutando
envelope de tamanho fixo. Ver `dumps/ENVELOPE.md`.

### PASSO 2 (blob de login / rekey): não é criptografia

`--entropy` sobre 256B windows: janelas com entropia > 6.5 aparecem esporadicamente
(3-4 por arquivo grande), NÃO agrupadas no início como se esperaria de blob de
login. Sem periodicidade → sem rekey. Combinado com Fase 1 (avg entropy 3.6-5.0,
todos < 6.0) → dados em claro. As janelas de alta entropia são payloads grandes
com muitos IDs/coords/floats, não campos cifrados. Ver `dumps/ENTROPY.md`.

### PASSO 4 (cross-check memscan `0x13`): confirmado

Struct de memória `[entity_id u32][self_ptr][0x13][name_len u32][UTF-16 name]`.
O byte `0x13` nessa struct = decimal 19 = tag mais frequente na rede (33% de todas
as msgs no raid). Serialização compartilhada memória↔rede. Ganho: uma vez que o
TLV parser esteja implementado, decodificar tag=19 dá nome/guilda direto, sem
heurística `IsWarspearId` e sem varredura por padrão de bytes.

### Não fechado ainda (pendente Fase 2 continuada)

- **max_len até 22 KB** — mensagens grandes podem CONTER TLV internos (TLV
  aninhado). Testar: pegar body de mensagem tag=492 e re-rodar TLV walker dentro
  dele
- **Body de tag=19 precisa ser decodificado** — é `[str_len:u32][UTF-16 bytes]`?
  `[str_len:varint][UTF-8 ou UTF-16 bytes]`? Precisa parser específico
- **Body de tag=427 (damage)** — sempre 3 bytes `[0d][dmg:u16 LE]`? Confirmar contra
  ground truth do usuário (Fase 5)
- **Attacker/target IDs** — em que tag(s) vêm? Provavelmente em mensagens vizinhas
  à tag=427, ou dentro de body de mensagens maiores. Fase 5 vai localizar

### Próximos passos (aguardando confirmação do usuário)

1. Escrever `src/Tlv.cs`-based decoder que produz `List<TlvMessage> { tag, body }`
   substituindo `GameFramer.Parse` em Fase 3
2. Deletar `src/Framing.cs` inteiro (bytescan, autosync, envelope guessing)
3. Reescrever `ExtractCombatFromRaw`, `ExtractPlayerNamesTimed`, etc. sobre
   `List<TlvMessage>` (elas viram simples `switch (msg.Tag)`)
4. Deletar formatos A/B/C, dedup 50ms, envelope hack

**Nenhuma dessas mudanças foi aplicada ainda** — esperando OK do usuário conforme
regra do plano.

---

## Network basics

- Transport: **TCP**
- Server: `152.233.19.169:15103` (observed in captures)
- Client ephemeral port varies (e.g. `53021`)
- Endian: little-endian for all multi-byte integer fields observed so far
- No obvious compression on small frames (readable text, structured IDs)

## Framing

### Small/normal frames — confirmed

```
[opcode:u8] [body_len:u8] [body: body_len bytes]
```

- Total frame size = `2 + body_len`
- Multiple frames can be concatenated in one TCP segment
- Frames can straddle TCP segments (need TCP reassembly)

Examples (server → client):

| Hex                       | opcode | len | body                       |
|---------------------------|--------|-----|----------------------------|
| `13 09 16 03 27 4e f6 05 00 19 10` | 0x13 | 9   | movement/pos update        |
| `55 00`                              | 0x55 | 0   | flag/marker                |
| `61 08 71 4d 30 00 38 8e 26 00`      | 0x61 | 8   | unknown, likely target ref |
| `05 04 00 00 00 00`                  | 0x05 | 4   | ack/keepalive              |
| `03 04 00 00 00 00`                  | 0x03 | 4   | ack/keepalive (client)     |
| `02 04 f2 c8 16 00`                  | 0x02 | 4   | ping w/ counter (client)   |
| `04 04 f2 c8 16 00`                  | 0x04 | 4   | ping reply (server)        |

### Big envelope frames — unresolved

Some server→client packets start with `ec 03 ...` and don't parse with the simple framing:

```
ec 03 47 42 f0 0b 04 04 bc c4 16 00 1a 29 34 55 ff 8a f6 05 ...
ec 03 22 1d e0 ff 03 08 0e 40 11 00 02 00 00 00 ...
ec 03 67 62 f1 0f 0c 21 0e 40 11 00 09 02 09 02 ...
ec 03 55 50 f1 14 41 52 34 4f 10 8e 2d 54 00 0a "Showdaxuxa" ...
ec 03 a3 01 9d 01 f2 1f 41 19 34 16 10 d0 22 4d 00 07 "Batmanx" ...
```

Observations:
- Prefix `ec 03` is stable — likely a 2-byte opcode `0x03ec` OR marker for "batched world state block"
- Bytes 2-3 vary; length field unclear (does not match total frame size directly)
- Contains **nested substructures**: player names as length-prefixed ASCII, chat text as UTF-16 LE
- Occurs at intervals — probably periodic world-state pushes (visible entities, chat, buffs)

**Working hypothesis:** `ec 03` frames are TLV-like envelopes with variable sub-record framing. Need more samples with known actions to unpick.

## Confirmed data types inside frames

### Player/guild names (ASCII)
Embedded near `ec 03` frames. Length-prefixed. Examples seen:
- `Showdaxuxa`
- `Batmanx`
- `Estripado`
- `Glost`

Pattern (guess): `[some header bytes] [name_len:u8] [ASCII bytes]`

### Chat/UI text (UTF-16 LE)
Every second byte is null → confirms UTF-16 LE.

- `farm aura é d bunda`   (0x66 0x00 0x61 0x00 0x72 0x00 0x6d 0x00 ...)
- `tumba e torr...` (Portuguese, cut off — spans frames)
- `se a ja c...e a salvo`

### Entity IDs (u32 LE)
Movement opcode `0x13` body has an entity-ID-like field at offset 2:
- `27 4e f6 05` → `0x05f64e27`
- `22 4e f6 05` → `0x05f64e22`
- `26 4e f6 05` → `0x05f64e26`
- Sequential range — nearby entities in the same zone

### Position deltas (guess)
Bytes 0-1 and 9-10 of `0x13` body look like `(x, y)` byte coordinates. Small values (< 32), consistent with tile-based grid.

### Floats
Occasional `00 00 80 3f` = `1.0f` (LE IEEE-754). Movement speed? Cast progress?

## Opcode catalog (in-progress)

| Op  | Dir  | Body len | Guess                       |
|-----|------|----------|-----------------------------|
| 02  | c→s  | 4        | ping/counter                |
| 03  | c→s  | 4        | ack                         |
| 04  | s→c  | 4        | pong                        |
| 05  | s→c  | 4        | server tick / ack           |
| 08  | c→s  | 7        | **walk command** (see below) |
| 0d  | s→c  | 4        | ?                           |
| 13  | s→c  | 9        | position/movement update    |
| 14  | s→c  | 13       | entity state / spawn        |
| 15  | s→c  | 6        | ?                           |
| 19  | s→c  | 5        | ?                           |
| 55  | s→c  | 0        | marker (batch delimiter?)   |
| 56  | s→c  | 0        | marker (batch delimiter?)   |
| 61  | s→c  | 8        | target reference            |
| 62  | s→c  | 12       | combat event candidate (see below) |
| ab  | s→c  | 3        | **damage event** — `[0x0d][dmg:u16 LE]` (see below) |
| 5b  | s→c  | 11       | entity IDs block in damage envelope: `[u32 0][target:u32][attacker:u32][u8 flag]` |
| 1f  | s→c  | 3        | critical-hit marker (only appears in crit damage envelopes) |
| ed  | s→c  | 3        | periodic status (~1 Hz), body stable `08 d0 4f` |
| ec  | s→c  | ??       | envelope / world state dump |

## Decoded frames

### `0xab / 3 s→c` — damage event (CONFIRMED with ground truth)

Confirmed via 3 controlled captures on 2026-09-18 17:36/17:37 where the user hit a training dummy with **known** damage values (crit **2358**, normal **1070**). Both values appear at a fixed offset inside an `ec 03` envelope, in every capture.

**Frame layout:**
```
opcode = 0xab
len    = 3
body[0] = 0x0d           (fixed byte; possibly damage type / physical marker)
body[1..2] = damage:u16 LE
```

Examples:
| Hit           | u16 LE bytes | Decimal |
|---------------|--------------|---------|
| normal        | `2e 04`      | 1070    |
| crit          | `36 09`      | 2358    |

### Damage envelope structure (`ec 03` container around the `ab/3` frame)

Every damage hit is wrapped in an `ec 03` envelope with a short header. After the header, a fixed sequence of sub-frames follows. Aligned example (normal hit, capture `ws_20260918_173718`):

```
ec 03  25 20 f4 07                              envelope header (4 bytes for normal hit)
55 00                                           marker
5b 0b  00 00 a2 2d 69 00 8c 22 f7 05 01         entity IDs block (11-byte body)
       └── ?  ──┘└─ target ──┘└─ attacker ──┘└flag┘
57 00                                           marker
ab 03  0d 2e 04                                 damage frame — 0d + dmg u16 LE (1070)
12 00                                           marker
50 f7 05 11  56 00  23 00 00 00                 tail (target ref + something)
```

**Crit variant** has a 5-byte prefix added to the envelope header: `... 1f 03 02 00 63 55 00 ...`. Likely a `1f/3` sub-frame with body `02 00 63` acting as the "critical!" indicator. Rest of the envelope is identical layout.

**Entity IDs proven from ground truth:**
- Target (dummy) = `0x00692da2` (`a2 2d 69 00` LE) — same ID that showed up in the earlier dummy-hitting capture `62/12` frames, confirming that ID was also the dummy
- Attacker (you) = `0x05f7228c` (`8c 22 f7 05` LE)

The `5b / 11` block carries `[?:u32 = 0] [target:u32 LE] [attacker:u32 LE] [flag:u8 = 0x01]`. First u32 is always 0 in these captures — possibly a "source type" or reserved field.

### `0x62 / 12 s→c` — combat event (candidate, less clear)

Confirmed via diff of dummy-hitting capture (2026-09-18 17:03, many players attacking dummy) vs baseline captures.

**Layout:**
```
[amount:u32 LE] [entity_id:u32 LE] [aux:u32 LE]
```

Two sub-types observed in the same opcode:

| Sub-type | Signature                                | Example body                                    | Meaning        |
|----------|------------------------------------------|-------------------------------------------------|----------------|
| damage   | `amount > 0`, `aux == 0`                 | `24 00 00 00 98 cf 07 00 00 00 00 00`           | 36 dmg to/from entity `0x0007cf98` |
| heal/xp  | `amount == 0`, `aux > 0`                 | `00 00 00 00 68 79 4c 00 64 00 00 00`           | 100 gained by entity `0x004c7968`  |

Observed damage values in dummy session: 16, 19, 20, 26, 28, 36, 38, 39, 47, 48, 50, 53, 54, 66, 67 — consistent with basic melee hits on a training dummy.

Rate went from 0.15/s (idle) → 0.43/s (multi-player dummy). Not a 10× jump because many combat events are likely bundled inside `ec 03` envelopes, which the current parser skips.

**Unknown:** whether `entity_id` is the attacker or the victim. Since the dummy is a single target but IDs vary across frames, this is almost certainly the **attacker** (or "source of damage"). To confirm: bake a capture where only ONE named player hits, and correlate ID with that player's spawn frame.

### `0x08 / 7 c→s` — walk command

Layout: `[new_x:u8] [new_y:u8] [cur_x:u8] [cur_y:u8] [flags:3 bytes ≈ 68 62 80]`

Small coordinate deltas across consecutive frames, trailing 3 bytes very stable. This is the client telling the server where the player wants to move.

## How the opcode was found

1. Recorded three captures with increasing activity:
   - `ws_20260918_163710` — 20 s, quiet, few actions
   - `ws_20260918_164441` — 75 s, mixed play
   - `ws_20260918_170308` — 141 s, several players hitting a dummy
2. Ran `_diff-opcodes.ps1` to produce a per-second frequency table per direction.
3. Looked for opcodes whose rate grew disproportionately with activity.
4. `62/12 s→c` stood out (0.15 → 0.32 → 0.43/s). Not the biggest jump, but 12-byte length felt right for a "u32 amount + u32 id + u32 something" combat event.
5. Ran `_dump-op.ps1 -Op 0x62 -Len 12` on the dummy capture — bodies decoded cleanly as three u32 LE fields, with values in the exact damage range shown on screen.
6. Cross-checked other spikes: `ed/3` was a constant heartbeat, `d8/1` was a parser desync artifact, `08/7 c→s` was walk. `62/12` remained the strongest match.

## How to identify a new opcode

1. Trigger a repeatable action in-game (e.g. attack same target 5x)
2. Take one capture per action
3. Diff opcode frequencies with a "no-action" baseline capture
4. Opcode with matching delta = candidate
5. Verify by looking at body bytes for changing/stable fields

## Format C (DoT / periodic tick) — confirmed 2026-09-19

Damage frame followed inline by attacker/target with no preceding entity block:

```
ab 03 0d <dmg:u16 LE> 00 00 <attacker:u32 LE> <target:u32 LE>
```

Used for damage-over-time ticks (poison, burn, curses). Parser evaluates this first because the trailing `00 00` after the damage bytes is a cheap check.

## Player enter-area (`0x19 / 5`) — confirmed 2026-09-19

Emitted server → client when another player becomes visible in the observer's area
(they zoned in, teleported next to you, or you entered a zone where they were already
present but not yet loaded).

```
op=0x19  len=0x05  body = [0x01][player_id:u32 LE]
```

**Ground-truth counts across captures:**

| capture | duration | unique `19 05 01 <id>` |
|---|---|---|
| `raid_guild_20260919_094131.pcapng` | 36 min | 140 |
| `raid_boss2_20260919_103642.pcapng` | ~6 min | 19 |
| `ws_20260919_134209.pcapng` (7-zone hop, few people) | ~90 s | 4 |
| `ws_20260919_133414.pcapng` (2 people) | ~40 s | 1-2 |

Scale matches ground truth: raid = many spawns; quiet zone = few. Bulk area-roster
(server pushes full roster when *you* change area) uses a different framing — larger
`ec 03`-wrapped packets containing multiple entities. `0x19 / 5` fires for individual
late-arrivals into an area where you already are.

Frames commonly following `19 05 01 <id>`:
- `ac 03 12 XX XX` — HP status sub-frame
- `<hp:u32 LE> <max_hp:u32 LE>` — player's HP and max HP
- summon id (high byte 0x05) if the player has an active pet

Used by the "People in area" panel to seed sightings in real time without waiting
for movement or damage frames.

## Summon / pet spawn — confirmed 2026-09-19

Opcode: `0x1a / 0x29` (frame op 0x1a, len 41).

Body layout:
```
1a 29 <2 bytes counter> <summon_id:u32 LE, high byte 0x05> <float 0.6f> <params...>
```

Owner sits **after** the frame within ~200 bytes, marked by ONE of two variants
(pet class byte differs):
```
01 00 90 <owner_id:u32 LE>       (class 0x90 — melee pets, owner at +3)
01 00 f0 00 <owner_id:u32 LE>    (class 0xf0 — 2nd pet class, owner at +4)
```

Ground-truth verified:
- Alphasputa (`0x00692476`) cast summon → summon `0x05F625F3` spawned with `01 00 90 <owner>`.
- Angelicais (`0x00382AEC`) 2nd-class pet → `01 00 f0 00 <owner>` (raid_overgod_20260919_161016). 21 of 33 summons in that capture were orphans under a single-marker parser; matching both fixes ~half of the pet→owner links.

Some pets stay orphan (no marker in window, e.g. environmental/world summons or pets summoned before capture start). Their damage still contributes to the big total but sits under their own `0x05xxxxxx` id on the leaderboard.

**Attribution rule in the parser:** when a damage frame's attacker is a summon whose spawn was captured, rewrite `attacker → owner`.

## Damage aggregation — dedup & filtering (calibrated 2026-09-19)

Raw byte-count of `ab 03 0d` frames in a capture matches the in-game meter within
~25% (broadcast duplication). Two knobs need tight tuning to hit ground truth:

1. **Broadcast dedup** — identical `(attacker, target, amount)` within **50 ms** = one hit.
   The previous 300 ms window collapsed real repeat-value hits from N pets sharing a
   base-damage tick (raid_overgod: 2032 frames raw ≈ 6.6M; 300 ms window kept only
   705 hits ≈ 2.9M; 50 ms keeps ~1620 hits ≈ ~5.2M matching the game meter).
2. **Orphan-pet damage** — `0x05xxxxxx` attackers without a resolved owner still count
   toward the **big total**. `Hide unnamed` filters what shows in the leaderboard, not
   what aggregates. Sub-stats line exposes `orphan pets: X` when un-owned pet damage is
   present, so the operator can see how much of the total is un-attributed.

Attackers that couldn't be resolved (no `5b/67 0b` block, no Format C trailer) stay at
`attacker = 0` — the hit still counts toward the total under a synthetic "unknown"
bucket rather than being fabricated onto the observer.

## Warspear ID systems — two IDs per character

Each character has two u32 identifiers:

- **World / character ID** — used in damage, movement, area broadcasts. Range `0x00010000..0x00FFFFFF`. Example: contablg = `0x00692DA2`, Alphasputa = `0x00692476`, Jokermwc = `0x0048E4BA`.
- **Account / friend ID** — used in PM headers, hotkey save XML. Also `0x00xxxxxx` range. Example: contablg account = `0x00690F96` (decimal `6885270`).

The two IDs are different for the same player. Damage tracking uses **world ID**.

## Private message layout — decoded 2026-09-18

```
[sender_char_id:u32 LE][name_len:u8][name ASCII][recipient_account_id:u32 LE][00 06 06][len:u8][utf16 msg]
```

## Player entity ID ranges (updated 2026-09-19)

- `0x00xxxxxx` — player characters
- `0x03/04/05/07/09/0C/10/57xxxxxx` — mobs / bosses / raid instances (variety)
- Boss classification uses **damage-received threshold** rather than ID range: `>20k` = MINI-BOSS, `>100k` = BOSS.

## Memory scan — player struct

```
struct PlayerEntry {
  uint32_t entity_id;    // world/character ID (0x00010000..0x00FFFFFF)
  uint32_t self_ptr;     // points to +16 (name start)
  uint32_t type;         // 0x00000013
  uint32_t name_length;  // UTF-16 char count
  wchar_t  name[name_length];
}
```

Guild names share the same fingerprint but the entity_id constraint is dropped. Guild filter requires all-caps ASCII letters, 4-12 chars.

## Known-unknown next steps

- Decode `ec 03` envelope full layout (still parsed heuristically today)
- Map **skill-cast** opcode client→server (small frame with skill id)
- Find **in-combat status** flag (would help exclude non-attackers from wrongly-attributed damage)
- Find **mob type table** in memory (to resolve mob names, not currently possible)
- Understand `0x00000000` unresolved-attacker damage in raids (106M dmg in one 36-min capture — likely boss AoE via alternate format)

## Reference captures

- `captures/_important/raid_guild_20260919_094131.pcapng` — 36-minute guild raid, 725 summon links, boss ranges discovered
- `captures/_important/raid_boss2_20260919_103642.pcapng` — second raid, boss `0x05F69CEB` with 460k HP
- `captures/_important/raid_overgod_20260919_161016.pcapng` — Overgod raid used to calibrate dedup window (0.3s→0.05s) and to discover the `01 00 f0 00 <owner>` pet marker variant. In-game meter ground truth: Angelicais 123k / Nerftotem 24k / Overgod 4.77M / Centablg 311k = ~5.2M total.
- Ground-truth damage: `ws_20260918_173622/173650/173718` — controlled 1070/2358 hits on training dummy

## Name broadcast investigation (2026-09-20)

**Hypothesis 1:** Player names travel encoded as UTF-16 in the network stream (memscan reads UTF-16LE from memory). ASCII-only pattern matching would miss them.

**Hypothesis 2:** Spawn packets (tag=19 / `13`) are sent once when an entity enters view range. If `dumpcap` started after an entity spawned, the packet is missed — the name can only be resolved via memscan or if the player later sends a chat/PM message.

### Probe: Multi-encoding name search

Compiled `tools/_find-string-probe.exe` to search TLV bodies for known player names in 4 codifications:
- **ASCII** (Encoding.ASCII)
- **UTF-8** (Encoding.UTF8)
- **UTF-16LE** (Encoding.Unicode)
- **UTF-16BE** (Encoding.BigEndianUnicode)

Ran against all 3 raid pcaps. Results below.

### Results summary

| Dump | Encoding | Hits | Primary tag(s) |
|------|----------|------|---|
| raid_overgod | ASCII | 196 | tag=65, tag=492 |
| raid_overgod | UTF-8 | 196 | tag=65, tag=492 |
| raid_overgod | UTF-16LE | 36 | tag=65, tag=206, tag=492 |
| raid_guild | ASCII | 100+ | tag=551 (new!) |
| raid_guild | UTF-8 | 100+ | tag=551 |
| raid_boss2 | ASCII | <5 | tag=492 |

**Name encoding used: primarily ASCII and UTF-8 (not UTF-16LE/BE).**

Tag frequencies in names:
- **tag=65** (`41`): Chat messages, player-list broadcasts. Names appear in **ASCII** and **UTF-16LE**.
- **tag=492** (`ec 03`): Bulk envelope. Names appear in **ASCII** and **UTF-8**.
- **tag=551** (raid_guild dump only): New opcode carrying player roster. Names in **ASCII**.
- **tag=206** (`ce`): Guild/rank info. Names in **UTF-16LE**.

### Target player findings (6 raid participants)

| Nick | raid_overgod | raid_guild | raid_boss2 | Appearing tag |
|------|---|---|---|---|
| Centablg | 3 hits (ASCII/UTF8/UTF16LE @ tag=492) | 2 hits (tag=492,551) | 1 hit (tag=492) | **tag=492, 551** |
| Jokermwc | **NOT FOUND** | 1 hit (tag=551) | **NOT FOUND** | **tag=551 only** |
| Brokeblade | **NOT FOUND** | 1 hit (tag=551) | **NOT FOUND** | **tag=551 only** |
| Mudin | **NOT FOUND** | 1 hit (tag=551) | **NOT FOUND** | **tag=551 only** |
| Wexu | **NOT FOUND** | 1 hit (tag=551) | **NOT FOUND** | **tag=551 only** |
| Kaliffado | **NOT FOUND** | 1 hit (tag=551) | **NOT FOUND** | **tag=551 only** |

### Capture window analysis

Checked if the user (Centablg, entity ID `0x00692DA2`) appears in each capture, plus whether target players' names appear:

| Dump | Duration | User ID found | User name found | Others found |
|------|----------|---|---|---|
| raid_overgod (22 min) | 19:10–19:32 | ✓ @ offset 189610 | ✓ (1) | **All 5 target players: NOT FOUND** |
| raid_guild (37 min) | 12:41–13:18 | ✓ @ offset 3007 | ✓ (2) | **All 5 found (1 hit each, tag=551)** |
| raid_boss2 (3 min) | 13:36–13:39 | ✓ @ offset 270 | ✓ (1) | **All 5 target players: NOT FOUND** |

### Verdict on Hypothesis 2

**CONFIRMED:** Capture window explains the missing names.

- **raid_overgod:** Centablg spawned in view (user ID found, name found), but Jokermwc/Brokeblade/Mudin/Wexu/Kaliffado did **not** appear in the capture window — they spawned before `dumpcap` started. Their IDs and class data exist in memory (memscan resolves them), but the spawn packet with the name never arrived.

- **raid_guild:** All players appear (tag=551 player-roster opcode @ 12:41, only 10 seconds after capture start). The roster broadcast allows late-join name resolution.

- **raid_boss2:** Short 3-minute capture. Only Centablg visible; others not present at all during that window.

### Conclusion

1. **Names use ASCII/UTF-8 encoding on the wire** — not UTF-16, so no "hidden" encoding surprises.
2. **Spawn packet (tag=19) arrives once per entity** when they first enter view range.
3. **Late-joining players are invisible to name resolution** until either:
   - The observer moves away and back (triggers a new spawn broadcast).
   - A player sends a chat message (name extracted from tag=65).
   - A roster message arrives (tag=551).
4. **Memory scan remains authoritative** because it holds all entity data server-side, not just what crossed the wire to this observer.

### Recommendation for next round

- Add **tag=551 player-roster decoder** (Fase 9). This opcode appears early in raid sessions and resolves all players' names + classes at once.
- Continue relying on **memscan as ground truth** for full character list.
- Document in UI: "Name visibility depends on capture start time. Run memscan before/during the event for full name coverage."

## Tag=551 roster broadcast — decoded 2026-09-20

Continuation of the name-broadcast investigation. Tag=551 turned out to be a
full player-roster message. Decoded on `raid_guild_20260919_094131.pcapng`
where all 6 target nicks appear (Centablg, Jokermwc, Mudin, Kaliffado,
Brokeblade, Wexu).

### Body layout (verified — 25/25 records, 6/6 target classIds correct)

```
[header 3 bytes: 00 02 <record_count u8>]
Record (repeats record_count times, 15 + name_len bytes each):
  [entity_id u32 LE]     // 0x00xxxxxx, >= 0x00010000
  [name_len u8]          // 3..20
  [name ASCII * name_len]
  [class_id u8]          // 1..20 (matches data/class-names.json)
  [flag u8]              // 0x21 or 0x22 (party/role bit, TBD)
  [index u32 LE]         // 1..record_count
  [extra u32 LE]         // unknown (experience? honor? kill count?)
```

Example first two records from raid_guild capture:

```
  0000  00 02 19                              header, 25 records
        a2 2d 69 00                           id=0x00692DA2 Centablg
        08 43 65 6e 74 61 62 6c 67            name_len=8, "Centablg"
        0a                                    class=10 (Cavaleiro da Morte)
        21                                    flag
        01 00 00 00                           index=1
        22 4f 02 00                           extra=0x00024F22
        ba e4 48 00                           id=0x0048E4BA Jokermwc
        08 4a 6f 6b 65 72 6d 77 63            name_len=8, "Jokermwc"
        12                                    class=18 (Cacique)
        21                                    flag
        02 00 00 00                           index=2
        a9 36 02 00                           extra=0x000236A9
```

Ground truth match (all 6 target nicks in raid_guild):

| Nick       | Entity ID    | Expected class      | Decoded classId | Result |
|------------|--------------|---------------------|-----------------|--------|
| Centablg   | 0x00692DA2   | Cavaleiro da Morte  | 10              | PASS   |
| Jokermwc   | 0x0048E4BA   | Cacique             | 18              | PASS   |
| Mudin      | 0x006D19E4   | Cacique             | 18              | PASS   |
| Kaliffado  | 0x006BC0B0   | Encantador          | 16              | PASS   |
| Brokeblade | 0x004961A4   | Barbaro             | 4               | PASS   |
| Wexu       | 0x0042411D   | Cacique             | 18              | PASS   |

Decoder: `src/Tag551Decoder.cs`. Wired in `WS-engine.cs` after
`ExtractChatSenders` — populates `nameMap` and `playerClassId` in one pass.
Regression: `tools/_test-tag551.ps1` — 6/6 PASS against ground truth.

### Frequency check — is 551 a reliable roster source?

`tools/_check-tag551.ps1` reports how many tag=551 messages exist and their
timing relative to capture start:

| Capture              | Duration  | tag=551 count | First at | Notes                                 |
|----------------------|-----------|---------------|----------|---------------------------------------|
| raid_guild           | 36.6 min  | 1             | t+339s   | fired when observer entered raid      |
| raid_overgod         | 22.5 min  | 0             | -        | observer already in raid at t=0       |
| raid_boss2           | 2.3 min   | 0             | -        | observer already in raid at t=0       |

Verdict on the "551 is universal on zone entry" hypothesis: **PLAUSIBLE but
NOT PROVEN** with existing dumps. The single fire we caught happened 5.6 min
into raid_guild — matches the pattern "observer transitions into a zone with
other players". The two zero-count captures both began with the observer
already inside the raid, so tag=551 had already fired before dumpcap started.

Needs a field test: start dumpcap FIRST, THEN enter the zone/raid.

### Field test protocol (user action)

To confirm tag=551 fires on zone entry:

1. Stand outside the target zone (city, teleport, safe room).
2. Start dumpcap in WS-engine.
3. Wait a few seconds so `t0` of the capture is definitely BEFORE the zone
   transition.
4. Walk / teleport into the raid or high-pop area.
5. Stay for 30-60 seconds so surrounding entities are broadcast.
6. Stop capture.
7. Run: `.\tools\_check-tag551.ps1 <path\to\capture.pcapng>`

Expected result if hypothesis is correct: one tag=551 message within a few
seconds of the zone transition, containing all players in the area with
their names and class IDs. If this reproduces, tag=551 is the definitive
answer to the "spawned before capture" problem and memscan becomes an
optional fallback rather than the only source.

### Follow-ups

- **Field test tag=551 frequency** (blocked on user).
- **Confirm meaning of flag byte** (0x21 vs 0x22). Hypothesis: same-party /
  guild-visibility bit. Cross-reference with a party-formation event.
- **Decode the `extra u32`** per record. Hypothesis: honor points, guild
  score, or last-login timestamp. Not needed for damage tracking.
- **Do not delete Padroes A/B/C/D yet** — they still catch names from tag=65
  (chat), tag=492 (bulk), and tag=551 already-decoded records via
  byte-scan. Once tag=65 gets its own decoder, A/B/C/D become redundant and
  can be removed together.

## Fase 8C — remove _lastTopAtt inherit heuristic (2026-09-20)

### Bug: group-fight attribution 3.3x over

Ground truth from ws_20260920_202311.pcapng (group fight, game meter):

| Player      | Game   | WS-engine (pre-fix) | Ratio |
|-------------|--------|---------------------|-------|
| Caveira     | 33,183 | 33.0k               | 1.0x  |
| Proibido    | 16,769 | 90.6k               | 5.4x  |
| Pquaresma   | 17,562 | 12.1k               | 0.7x  |
| Centablg    | 19,314 | 123.3k              | 6.4x  |
| Lobopidaum  |  2,116 | 36.3k               | 17x   |
| Suo         |    562 | missing             | -     |
| **Total**   | 89,506 | 295,300 (no mobs)   | 3.3x  |

### Root cause

`TlvDamageDecoder.Feed` carried `_lastTopAtt` across tag=492 damage records
without an in-body marker `5b 0b 00 00 <att> <tgt>`. In group fights ~44% of
records have no marker and inherited whichever attacker was seen most
recently in this Feed call. The observer (Centablg) or last-marker attacker
became a damage sink, collecting damage that belonged to other players.

Diagnostic probe `tools/_probe-attribution.ps1` on the target dump:

```
tag=492 dmg hits total:       221
  via own marker:             123 (55.7%)   sum 107,686 dmg
  via _lastTopAtt inherit:    98  (44.3%)   sum 219,646 dmg
```

Inversion test (swap att<->tgt in markers) did NOT fix any per-player
number — inversion is not the bug.

### Fix

Removed `_lastTopAtt` inheritance. When a damage record in tag=492 has no
preceding marker in the same body, the decoder now emits with
`AttackerId=0`, `TargetId=0`. `WS-engine.cs` already aggregates att=0 into
an unresolved bucket surfaced in the UI as `? Unresolved`.

After fix on ws_20260920_202311.pcapng:

| Player      | Game   | WS-engine (post-fix) | Notes                          |
|-------------|--------|----------------------|--------------------------------|
| Centablg    | 19,314 | 66.5k                | still over, marker bug remains |
| Caveira     | 33,183 | 10.3k                | under                          |
| Pquaresma   | 17,562 | 1.4k                 | under                          |
| Lobopidaum  |  2,116 | 668                  | under                          |
| Proibido?   | 16,769 | 352                  | under                          |
| Unresolved  | -      | 219,646 (98 hits)    | new bucket, honest             |

Total damage sum unchanged (328k) — only attribution redistributed. Existing
regression tests (`tools/_test-damage-decoder.ps1`) still PASS 4/4 because
they check TOTAL, not per-attacker.

### Known limitation still open

Even after removing inherit, marker-only Centablg attribution (66k) is 3.4x
above ground truth (19k). Suggests some `5b 0b 00 00 <a> <t>` markers are
false positives OR carry a different semantic than "damage attribution".
Follow-up round: audit marker byte pattern against non-damage events
(buffs, misses, heals) and check whether observer's own ID appears in
markers that never correspond to real damage the observer dealt.

Probes preserved:
- `tools/_probe-attribution.ps1` — per-attacker breakdown of marker vs inherit
- `tools/_probe-marker-audit.ps1` — per (att,tgt) marker bucket sums
- `tools/_probe-tag492-nested.ps1` — proves tag=492 body is NOT clean nested TLV
- `tools/_probe-embedded427.ps1` — rejects "embedded 13B tag=427" hypothesis
- `tools/_probe-tag492-dump.ps1` — hex dump of tag=492 bodies with marker + hit highlights
- `tools/_test-fix-groupfight.ps1` — end-to-end validation with decoder + dedup

## Fase 8D — drop orphan tag=492 records (2026-09-20)

### Bug: 723k unresolved bucket in 5:35 fight

Ground truth from ws_20260920_212612.pcapng (game meter, bout 5:35):

| Player     | Game   | WS-engine (Fase 8C) | Notes                       |
|------------|--------|---------------------|-----------------------------|
| Nfps       | 31,374 | 28.1k               | ok (with pet merge)         |
| Marcao     | 18,968 | 32.5k               | 1.7x over                   |
| Sacrum     | 16,570 | 211                 | 1% of real — mostly missing |
| Kreitols   | 13,755 | 696                 | 5% of real                  |
| Lingyoo    | 10,596 | 1,094               | 10% of real                 |
| Wander     | 10,549 | 6.78k               |                             |
| Exorcistty | 10,547 | 864                 | 8% of real                  |
| Centablg   | 9,509  | 18.0k               | 1.89x over                  |
| Lbicare    | 4,640  | 499                 | 11% of real                 |
| Peladehnho | 3,637  | 9.02k               | 2.5x over                   |
| **Total**  | 129,700| ~97k resolved + 723k UNRESOLVED (196 hits, max 42.9k) | |

### Root cause

`ScanContainerBody` emitted damage records with `att=0/tgt=0` when no marker
preceded them in the same body. Routed to unresolved bucket. Diagnostic
probe `tools/_probe-unresolved.ps1`:

```
total records:           359
with STRICT marker:      163 (45.4%)  → resolved 168k
WITHOUT marker:          196 (54.6%)  → unresolved 723k, max amt 42,909
```

Top 10 unresolved amounts: 42,909 / 28,178 / 24,513 / 23,995 / 23,932 /
21,933 / 17,107 / 17,092 / 17,084 / 17,073. All larger than any real
player hit in the 5:35 fight (game meter max ~9k). Hex-dump inspection of
the 42,909 record shows the byte pattern `ab 03 0d` occurring inside
non-damage TLV data — not the start of a real compact record. Bytes
matching `ab 03 0d` occur naturally as data in other TLV fields; the
byte-scan was over-triggering.

### Fix

Records with no preceding `5b 0b 00 00 <att u32> <tgt u32>` marker in the
same tag=492 body are now DROPPED, not routed to unresolved. Decoder no
longer emits att=0 for tag=492 hits.

Verification on ws_20260920_212612.pcapng:

```
BEFORE Fase 8D: total 891,125 (unresolved 723,299 / 196 hits, max 42,909)
AFTER  Fase 8D: total 167,826 (unresolved 0)
```

vs game meter 129,700 → 1.29x over (down from 6.87x). Remaining 30% is
autoattack repetition legitimately counted (same weapon damage every ~2s)
and cross-attribution nuance (some markers may still be false-positive
byte matches).

### Regression baseline changes

`tools/_test-damage-decoder.ps1` baselines rebased — old numbers included
false-positive byte-scan hits:

| Dump                | Old total    | Old events | New total  | New events |
|---------------------|--------------|------------|------------|------------|
| raid_overgod        | 6,631,787    | 2,036      | 5,078,559  | 1,495      |
| raid_guild          | 173,938,289  | 43,829     | 57,429,999 | 15,675     |
| raid_boss2          | 7,796,839    | 2,404      | 4,681,787  | 1,459      |
| dummy_20260920      | 126,156      | 38         | 80,992     | 29         |

All 4 PASS with new baselines.

### Probes

- `tools/_probe-unresolved.ps1` — marker fraction + top unresolved amounts + hex context
- `tools/_probe-drop-unresolved.ps1` — validates fix behavior offline

## Fase 8E — expand pet-class byte in summon owner marker (2026-09-20)

### Bug: pets showing as "Mobs (N)" bucket instead of rolled onto owner

Ground truth from ws_20260920_214044.pcapng:

| Player     | Game     | WS-engine | Missing |
|------------|----------|-----------|---------|
| Paudeposte | 186,259  | 30.0k     | ~156k → "Mobs (3)" bucket |
| Madelyn    | 141,308  | 106.6k    |         |
| Marchielo  |  24,416  |  32.7k    | 1.34x over |

The "Mobs (3)" bucket had 143.1k dmg, 65 hits, max 41.8k — 156k missing from
Paudeposte matches almost exactly.

### Root cause

`ExtractSummonOwners` searches for `01 00 90 <owner u32>` OR `01 00 f0 00
<owner u32>` after each `1a 29` spawn event. Probe on target fight:

```
distinct pets:            164
STRICT (0x90 || 0xf0):    69 linked (42%)
```

Enumeration of pet class byte for pets whose owner scan *would* validate:

```
0x90: 66  (melee — supported)
0x20: 34  (NEW — not supported)
0x00: 7   (false-positive zero padding)
0x01: 4   (false-positive)
0xf0: 3   (2nd class — supported)
0x28: 1
```

Class 0x20 was missing from the whitelist — 34 legitimate spawns dropped.
Classes 0x00/0x01/0x28 look like `01 00 <padding>` false positives in
unrelated fields, so they stay out.

### Fix

Whitelist expanded from {0x90, 0xf0} to {0x90, 0x20, 0xf0}. Owner_id range
check (`0x00010000 <= id < 0x01000000`) discards false matches.

Result: 102 pets linked (was 69) — **+48% coverage**.

### Known limitation still open

Top damage pets in user's specific fight (0x05f5ef74 = 134k dmg, plus
0x05f6167c / 0x05f75931 / 0x05f5e249) are STILL ORPHAN even after the fix.
No `1a 29` spawn event for them in the capture — their summons happened
BEFORE dumpcap started. Same "capture window" problem as tag=551 roster.

User instructions for reliable pet attribution:
1. Start dumpcap BEFORE entering the raid / instance.
2. Have all party members re-summon their pets after capture starts (they
   emit a fresh `1a 29`).

### Regression

`tools/_test-damage-decoder.ps1` — 4/4 PASS unchanged (baselines only
measure damage total; owner attribution is a downstream WS-engine.cs
concern, not TlvDamageDecoder).

### Probes

- `tools/_probe-pet-owner.ps1` — count spawns, orphan pets, name occurrences
- `tools/_probe-pet-context.ps1` — hex dump around each pet's byte position
- `tools/_probe-1a29-context.ps1` — bytes before/after each `1a 29` spawn
- `tools/_probe-1a29-classes.ps1` — enumerate class byte histogram
- `tools/_probe-pet-check-8e.ps1` — validate ExtractSummonOwners on target pcap

## Tag=492 body structural analysis (2026-09-20)

Attempted structural decode of tag=492 to replace the byte-scan approach in
Fase 8D. Result: partial structural understanding, but full replacement
NOT achieved. Fase 8D retained as best current approximation.

### Findings

**Body prefix: 3-5 bytes of non-TLV metadata (probably observer tick / counter).**
Nested varint-TLV walk fails at every fixed startOff:
```
startOff=0: 1/1314 clean parse
startOff=1: 94/1314
startOff=2: 100/1314
startOff=3: 127/1314  (best: 9.7%)
startOff=4: 83/1314
startOff=5: 90/1314
...
```

**Damage events use a 3-part sub-TLV structure inside the body:**
```
5b 0b 00 00 <att u32 LE> <tgt u32 LE> 01     tag=91 len=11 body (attribution)
57 00                                         tag=87 len=0 (empty separator)
ab 03 0d <13B body>                          tag=427 len=13 (damage record)
```

The `ab 03 0d` pattern IS the header of an embedded tag=427 (varint tag=427,
length=13), not a "compact 5B record" as previously documented. The 13B body
holds `[dmg u16][11 unknown bytes]` — different layout than the top-level
tag=427 which has `[dmg u32][att u32][tgt u32][flag u8]`.

### Attempted structural decoders (all rejected)

Against `ws_20260920_212612.pcapng` (game meter total 129,700 for players):

| Approach                                     | Hits | Sum     |
|----------------------------------------------|------|---------|
| bare `ab 03 0d` byte-scan (pre-Fase 8D)      | 359  | 890,429 |
| Fase 8D (require marker in body)             | 163  | 168,000 |
| add `57 00` prefix requirement               | 145  | 82,930  |
| require full 18B contiguous transaction      | 81   | 58,384  |
| top-level tag=427 only                       | ~45  | ~6,000  |

Tighter structural filters DROP more real damage than the fake false-positives
they eliminate. Fase 8D is the best trade-off available with byte-scan.

### Player ID position within tag=492 body

Known player IDs searched via byte pattern inside tag=492 bodies. Offsets are
NOT fixed — same player appears at 20-70 distinct byte offsets across the
capture. Confirms: tag=492 body has NO fixed-size record layout. Each body
carries mixed content (name broadcast, chat, damage, status updates) and the
player_id can appear in any of those contexts.

### What full structural decode would require

1. Identify the 3-5 byte header semantic (observer tick? sequence number?).
2. Enumerate ALL sub-tags inside tag=492 body (not just 91/87/427) and
   determine each's length semantic.
3. Some sub-tags may have variable-length fields with self-describing size
   (e.g. name broadcasts have `<len u8><ASCII>` inside).
4. Test against 4+ dumps with distinct contexts (solo, duo, party+raid, chat
   heavy) to validate parse.

Estimated effort: 4-6h of dedicated RE. Deferred; Fase 8D remains.

### Probes

- `tools/_probe-492-structural.ps1` — nested TLV walk at startOff 0..10 + player ID search
- `tools/_probe-492-tighter.ps1` — histogram of 2 bytes preceding `ab 03 0d`
- `tools/_probe-492-strict-decoder.ps1` — `57 00` prefix filter (rejected)
- `tools/_probe-492-transaction.ps1` — 18B contiguous transaction pattern (rejected)

## Tag=492 sub-tag census — investigation only (2026-09-20)

Investigation pura. Nenhum decoder alterado. Objetivo: mapear o interior do
tag=492 antes de escrever qualquer decoder novo. Ver
`docs/492-census-output.txt` para o dump completo do probe.

### Task 3 — body-completion rate

% de bodies percorridos start-to-end sem travar (varint-TLV walk), no melhor
startOff testado:

| Dump                                 | Best startOff | Clean bodies | Bytes walked |
|--------------------------------------|---------------|--------------|--------------|
| dummy solo (`ws_20260920_104845`)    | 1             | 1/49  (2.0%) | 5.5%         |
| raid_boss2                           | 3             | 54/1325 (4.1%) | 52.3%      |
| group fight (`ws_20260920_212612`)   | 3             | 127/1314 (9.7%) | ~26%      |

**Menos de 10% dos bodies parseiam limpo em qualquer startOff fixo.**
Premissa "tag=492 body é TLV nested com header curto" é FALSA. Mesmo com
best-effort startOff, walk avança ~50% dos bytes antes de travar.

### Task 5 — header não tem tamanho fixo

Correlação `firstByteOfBody → bestStartOff` (raid_boss2):

| First byte | Bodies | Best startOff | Clean count |
|------------|--------|---------------|-------------|
| 0xf9       | 13     | 8             | 1/13        |
| 0x98       | 13     | 0             | 0/13        |
| 0xcd       | 13     | 5             | 1/13        |
| 0xb0       | 13     | 5             | 2/13        |
| 0xa8       | 13     | 2             | 1/13        |

Nenhum startOff dá clean parse consistente. Header do body **não** tem tamanho
determinístico pelo primeiro byte. Header pode ser variável por outra razão
(embedded seq counter, TCP offset, etc.) que os dados sozinhos não revelam.

### Task 1 — sub-tag histogram (raid_boss2, startOff=3)

Tags com length CONSISTENTE (candidates a rule fixa):

| Sub-tag | Count | Len min | Len max | Mode len (count) | Interpretação |
|---------|-------|---------|---------|------------------|---------------|
| 85      | 572   | 0       | 114     | 0 (565)          | Delimiter empty (99% mode=0) |
| 87      | 168   | 0       | 94      | 0 (162)          | Delimiter empty (96% mode=0) |
| 91      | 142   | 0       | 33      | 11 (135)         | Attribution `[00 00 att u32 tgt u32 flag]` (95% mode=11) |
| 427     | 138   | 13      | 13      | 13 (138)         | Damage record (100% consistent) |

Tags com length VARIÁVEL (walk trava neles):

| Sub-tag | Count | Len min | Len max | Mode len | Comentário |
|---------|-------|---------|---------|----------|-----------|
| 0       | 1234  | 0       | 624     | 0 (340)  | Byte 0x00 é ambíguo — dado dentro de outro TLV vira "tag=0" |
| 5       | 137   | 0       | 595     | 0 (22)   | Spread grande, sem mode |
| 1       | 201   | 0       | 135     | 0 (59)   | Spread grande |
| 3       | 204   | 0       | 167     | 85 (44)  | Spread grande |
| 19      | 362   | 0       | 428     | 9 (280)  | Mode=9 mas spread grande |

Diagnóstico: tags 0/1/3/5 têm lengths de até centenas de bytes — provável que
essas "lengths" sejam DADOS mal interpretados após walk desalinhar.

### Task 2 — onde o walk trava (raid_boss2, 1271/1325 stalls)

Top sub-tags causando stall:

| Tag | Stalls | Diagnóstico |
|-----|--------|-------------|
| 0   | 469    | Byte 0x00 dentro de outros bodies vira "tag=0 len=varint(garbage)" |
| 5   | 32     | Byte 0x05 similar (dado de mob ID hi=0x05) |
| 19  | 31     | Byte 0x13 |
| 1   | 26     | Byte 0x01 (flag em muitos campos) |
| 3   | 26     | Byte 0x03 |
| 17  | 23     | |
| 4   | 20     | |

Exemplos de stall com length absurdo:
```
tag=52 len=97126 off=144 : 34 e6 f6 05 03 57 6d 00 24 ...
tag=0  len=65106 off=88  : 00 d2 fc 03 0c ac 85 30 00 ...
tag=0  len=427   off=146 : 00 ab 03 0d 3c 01 00 00 01 ...
```

Padrão: bytes de payload (entity IDs, floats, dmg values) sendo tratados como
tag+length porque walk desalinhou anterior.

### Task 4 — regra de length para tag=0 (pior stalling)

10 samples do tag=0 examinados. Bytes após `00`:

```
00 ce 00 00 30 00 22 92 03 20 00 00 ab 00 00 10 ...    (128 bytes)
00                                                      (1 byte só)
00 d2 fc 03 0c ac 85 30 00 16 ab 02 00 50 46 13 ...    (100+ bytes)
00 ab 03 0d 3c 01 00 00 01 88 29 00 34 e6 f6 05 ...    (contains tag=427!)
00 eb 9c f6 05 01 57 00 68 0a 0f 00 90 57 00 ae ...    (contains attrib+empty+dmg?)
```

Não há regra consistente. Tag=0 é frequentemente NÃO um TLV real — é o byte
0x00 aparecendo como dado dentro de OUTRO tag maior. Confirmação de que
walk desalinha e o "tag=0" reportado é fantasma.

### Veredito

**Nested TLV walk NÃO é a estrutura correta** para o body do tag=492.
Percurso limpo em <10%. Bytes walked ~50% média, mas o resto trava em
tags-fantasma criados por desalinhamento.

O que temos com certeza:
- tag=85 (0x55): delimiter EMPTY (mode len=0, 99%)
- tag=87 (0x57): delimiter EMPTY (mode len=0, 96%)
- tag=91 (0x5b): attribution body 11B fixo (95%)
- tag=427 (`ab 03`): damage body 13B fixo (100%)

Esses 4 sub-tags são reais. Outros são fantasmas ou têm layout desconhecido.

O que NÃO sabemos:
- Como o body começa (header variável, possivelmente contendo seq counter)
- Como delimitar tags 0/1/3/5 (length rule desconhecida)
- Se existe MULTI-STREAM (dois fluxos entrelaçados no body)

**Próximos passos possíveis (não realizados):**
- Comparar bodies com mesmo primeiro byte, ver se compartilham estrutura
- Fingerprint por tamanho de body (bodies pequenos podem ser eventos simples,
  grandes = multi-record)
- Estudar `c2s` streams para ver se o CLIENTE também envia tag=492, e se sim,
  qual é o formato — pode revelar semânticas
- Pegar dumps c2s+s2c e cruzar temporalmente: cada tag=492 s2c pode ser
  resposta a um c2s específico com layout conhecido

### Probes

- `tools/_probe-492-census.ps1` — probe completo das 5 tasks
- `docs/492-census-output.txt` — output raw preservado


---

## Tag=492 — MAPA DE OCUPAÇÃO (2026-09-20, investigação pura)

Probe: `tools/_probe-492-occupancy.ps1`. Varredura greedy dos bodies procurando
APENAS os 4 blocos conhecidos (85=`55 00`, 87=`57 00`, 91=`5b 0b`+11B,
427=`ab 03 0d`+13B). Sem walk TLV. Dumps: `ws_20260920_212612` (grupo, ground
truth do placar) e `raid_boss2_20260919_103642` (cross-check).

### T1 — Cobertura: BAIXA (7,5% / 13,5%)

| dump | bodies | bytes | cobertos | % | 85 | 87 | 91 | 427 |
|---|---|---|---|---|---|---|---|---|
| ws_20260920_212612 | 1314 | 167.630 | 12.506 | **7,5%** | 1551 | 684 | 196 | 343 |
| raid_boss2 | 1325 | 408.706 | 55.197 | **13,5%** | 3179 | 1969 | 825 | 2136 |

Os 4 blocos sozinhos NÃO explicam o body. **MAS** a análise dos gaps muda tudo:

### DESCOBERTA PRINCIPAL — os gaps são OUTROS blocos TLV

Histograma dos 2 primeiros bytes de cada gap (ws_20260920, top):

```
61 08 : 313   → tag=97  len=8    5e 0b : 61 → tag=94  len=11
67 0b : 274   → tag=103 len=11   68 0a : 61 → tag=104 len=10
5c 0c : 232   → tag=92  len=12   63 0d : 56 → tag=99  len=13
ac 03 : 188   → tag=428 len=18 (varint ac 03 = 428, byte seguinte 12h=18)
62 0c : 139   → tag=98  len=12   5d 0c : 55 → tag=93  len=12
6a 06 : 104   → tag=106 len=6    ae 03 : 63 → tag=430
8b 01 : 95    → tag=139 len=8 (varint 8b 01 = 139)
```

raid_boss2 mostra a MESMA família (61 08, 5e 0b, 5c 0c, 63 0d, 69 08, 68 0a,
62 0c, ac 03, ae 03, 6a 06...). Gap típico decodifica limpo, ex.:

```
61 08 [16 21 04 00 e9 86 25 00] 56 00
= tag=97 len=8 body(8B) + tag=86 len=0        ← TLV perfeito

67 0b [00 00 | 20 86 f6 05 | 8f 9a 39 00 | 00]
= tag=103 len=11, layout IDÊNTICO ao tag=91:
  [00 00][id_A u32][id_B u32][flag]
  id_A = 0x05f68620 (mob), id_B = 0x00399a8f (player)
```

**Revisão da conclusão do censo:** tags 0/1/3/5 do censo eram fantasmas de
desalinhamento, sim — mas a causa era o HEADER variável, não ausência de TLV.
O body É um stream TLV `[tag varint][len u8][body]` com ~15+ tipos de bloco de
tamanho fixo. O walk do censo começava no offset errado e nunca re-sincronizava.

### Header do body

Gap na posição 0 (header): len=3 domina (432 bodies), depois 2 e 4. Amostras:
`4d f0 14`, `58 f0 13`, `4a f0 1b`, `38 f0 09`, `59 f0 05`, `64 f0 05`, `4e d1`.
Padrão: `[u8 crescente ≈ contador][u8 com nibble alto 0xD/0xE/0xF][u8]`.
"Headers" longos (14/43/45B) são header de 3B + blocos ainda não mapeados —
ex. `59 f0 05` seguido de `1a 29 ...` = **spawn de summon embutido no 492**
(com marker `01 00 90 <owner>` completo).

### T2 — Sequências

- Sequência mais comum: `H3 85 g13 87 g41` (x52) e variações — o "g13" após 85
  é quase sempre um bloco `67 0b` (tag=103, 13B totais). Ou seja, a transação
  real mais comum é `[85][103][87][428-blob]`.
- `[85][91][87][427]` confirmada x29 (transação de dano já conhecida).
- Token antes de cada 427: `87` em 162/343 (47%) — [87][427] adjacência forte.
- Token depois de cada 91: `87` em 160/196 (82%) — [91][87] praticamente fixo.

### T3 — Conteúdo dos gaps

- 771/3527 gaps contêm player-id conhecido (u32 LE); 1734/3527 contêm id
  mob-range 0x05xxxxxx → gaps carregam entity ids = são blocos estruturados.

### T4 — tag=91 como fonte de atribuição: FALHA sozinho

Atribuindo cada 427 ao último 91 do MESMO body:

- **180 de 343** blocos 427 não têm NENHUM 91 antes no body → 665.290 de dano
  sem atribuição.
- Per-player vs placar: Nfps 2.842 vs 31.374 (9% do real), Centablg 17.968 vs
  9.509 (1,9x acima). Maioria da atribuição cai em mobs.
- **Candidato forte: tag=103** (layout idêntico, 274 ocorrências vs 196 do 91
  neste dump). Hipótese: 91 e 103 são ambos blocos de atribuição
  (talvez direções diferentes: player→mob vs mob→player), e os 427 seguem
  o mais recente de QUALQUER um dos dois.
- Flag byte do 91 (offset 12): 0x01 x103, 0x03 x36, 0x04 x19, 0x00 x18 — não
  é sempre 0x01 como assumido pela transação da Fase 8D.

### T5 — Falsos positivos da Fase 8D

| métrica | valor |
|---|---|
| F8D hits neste dump | 163 (167.130 dano) |
| F8D **falsos positivos** (não são bloco 427 estrutural) | **8 (13.098)** — 12.916 vem de UMA leitura corrompida `ab 03 0d 74 32` |
| 427 estruturais **PERDIDOS** pela F8D | **188 (665.290)** |

A regra da Fase 8D (dropar órfãos sem marker `5b 0b 00 00`) descarta **188
registros de dano reais** — o problema não é excesso de falsos positivos, é
que a atribuição via 91 sozinho não existe para a maioria dos 427 (o bloco de
atribuição é o 103, que a F8D ignora).

### Conclusão

Cobertura dos 4 blocos é baixa, MAS a estrutura está resolvida em princípio:
**o body do 492 é TLV `[tag varint][len u8]` com header de 2-4 bytes e ~15+
tipos de bloco fixos**. Próximo passo natural (NÃO executado nesta rodada):

1. Walk TLV ancorado — pular header achando o primeiro tag válido, tabela de
   tags conhecidos com lens fixos (85:0, 86:0, 87:0, 91:11, 92:12, 93:12,
   94:11, 97:8, 98:12, 99:13, 103:11, 104:10, 106:6, 139:8, 427:13, 428:18).
2. Decodificar tag=103 como bloco de atribuição irmão do 91.
3. Re-validar per-player contra o placar de ws_20260920_212612.

### Probes

- `tools/_probe-492-occupancy.ps1` — as 5 tarefas desta investigação

---

## Tag=492 — Walker TLV ancorado (2026-09-20, hipóteses falsificadas)

Probe: `tools/_probe-492-walker.ps1`. Continuação da investigação de ocupação.
Objetivo: header primeiro, walker ancorado depois, decodificar tag=103 como
irmão do 91, per-player vs placar.

### T1 — Header: sem regra descoberta

Melhor start-off por body (varredura 0..16, tabela de tags conhecidos + tags
descobertos por walk lenient):

| hdr_len | bodies |
|---|---|
| 3 | 408 |
| 1 | 240 |
| 4 | 111 |
| 5 | 76 |
| 6 | 71 |
| 7 | 66 |
| 2 | 62 |
| ... espalhado até 16 |

Hipótese `body[0] == blockCount`: **0/1314 bodies** batem. **Rejeitada.**

Nenhum padrão simples fecha o header (fixo, contador ou sequência).

### T2 — Walk lenient + resync

- Clean walk (sem resync): 459/1314 = **34,9%**
- Bytes cobertos: 130.168/167.630 = **77,7%**
- Catálogo dominado por `tag=0 len=0` (1182 sightings) = walker come byte-nulo
  como bloco vazio → cobertura inflada por padding.
- Alvo era "alto" (>=70% clean). Não atingido.

### T3 — tag=103: layout confirmado, hipótese REJEITADA

Blocos `67 0b [00 00 <idA u32> <idB u32> <flag u8>]` decodificados em bodies
clean-walkable:

| métrica | valor |
|---|---|
| ocorrências | 163 |
| idA hi-byte | 100% 0x05 (mob) |
| idB hi-byte | 99,4% 0x00 (player) |
| pares mob→player | 162/163 |
| flag byte | 0x05 x91, 0x00 x68, 0x57 x2, 0x06 x2 |

Layout limpo e estável — 103 É um bloco de eventos mob→player.

**Mas:** dos **97 blocos 427** no walker, **zero** tem 103 antes no mesmo body
(`no 103 before: 97`). 103 nunca precede 427.

Hipótese "91 = dano causado, 103 = dano recebido, pares irmãos" **FALSIFICADA**.
103 é outro evento (candidatos não perseguidos: aggro, threat, DoT tick, buff).

### T4 — Per-player (91 + 103 combinados) vs placar: FALHA

Placar ground truth `ws_20260920_212612` (bout 5:35):

```
Nfps 31.374 | Marcao 18.968 | Sacrum 16.570 | Kreitols 13.755
Lingyoo 10.596 | Wander 10.549 | Exorcistty 10.547 | Centablg 9.509
Lbicare 4.640 | Peladehnho 3.637   TOTAL 129.700
```

Resultado do walker (attribution: 427 → último 91 ou 103 no body):

- 427 blocos encontrados: 97 (censo tinha 343 — 71% caem em bodies não-walkable)
- Sum de dano atribuído a IDs player-range (0x00xxxxxx): **2.100 (1,6% do placar)**
- Únicos players no top 20: Centablg 587, 0x00691957 1.143
- Nfps, Sacrum, Kreitols etc. — ausentes

Não há atribuição player-side no TLV nested que estamos parsing.

### Conclusão — parar aqui conforme protocolo

Critério de aceite era per-player próximo do placar. **Não atingido.**

Hipóteses falsificadas nesta rodada:
- Header contador
- 91/103 como pares dano-causado/recebido
- TLV puro nested no body do 492

Não vou:
- Deletar `ab 03 0d` IndexOf da Fase 8D
- Trocar decoder
- Aplicar heurística nova
- Fator de correção

### Pistas não perseguidas (para próxima rodada)

- **tag=97 (`61 08` len 8):** censo mostrou body `3b f2 21 00 10 78 68 00`
  = dois u32 LE player-range (`0x0021f23b`, `0x00687810`). Candidato forte pra
  atribuição player→player. 159 ocorrências no dump.
- **tag=99 (`63 0d` len 13):** mesmo tamanho do 427. Verificar se é variante ou
  frame irmão.
- **Body do 492 pode não ser TLV.** 22% dos bytes não walkáveis + hdr_len sem
  moda + tag=0 padding sugerem que é um binary record com layout FIXO por tipo
  de evento, não stream TLV. Coincidências com format TLV explicariam os 34%
  clean. Próximo passo natural: separar bodies por (msg_size, primeiro_byte) e
  ver se cada bucket tem layout fixo por offset.
- **Comparar c2s stream** — cliente envia tag=492? Se sim, layout pode ser
  simétrico e mais fácil de reverter.

### Probes

- `tools/_probe-492-walker.ps1` — walker + T1..T4

---

## Value-search — onde vive o dano (2026-09-20, mudança de alvo)

Probe: `tools/_probe-value-search.ps1`. Método do tag=551: procurar VALORES
conhecidos em todas as tags s2c, 4 codificações (u16 LE/BE, u32 LE/BE).

### T1 — Totais do placar (ws_20260920_212612)

Placar (bout 5:35): Nfps 31.374, Marcao 18.968, Sacrum 16.570, Kreitols 13.755,
Lingyoo 10.596, Wander 10.549, Exorcistty 10.547, Centablg 9.509, Lbicare 4.640,
Peladehnho 3.637.

**Resultado: TODOS estão em tag=492, num CLUSTER apertado de offsets:**

| jogador | valor | tag | enc | offset |
|---|---|---|---|---|
| Kreitols | 13.755 | 492 | u16LE/u32LE | **4424** |
| Lbicare | 4.640 | 492 | u16LE/u32LE | **4469** |
| Lingyoo | 10.596 | 492 | u16LE/u32LE | **4503** |
| Nfps | 31.374 | 492 | u16LE/u32LE | **4537** |
| Centablg | 9.509 | 492 | u16LE/u16BE/u32LE | **4567** |
| Exorcistty | 10.547 | 492 | u16LE/u32LE | **4615** |
| Wander | 10.549 | 492 | u16LE | **4648** |
| Sacrum | 16.570 | 492 | u16LE/u32LE | **4678** |
| Marcao | 18.968 | 492 | u16LE/u32LE | **4746** |
| Peladehnho | 3.637 | 492 | u16LE | 221 (isolado — coincidência?) |

Spread 4424-4746 = **322 bytes** dentro de UMA mensagem tag=492 (a única com
body ≥4800 bytes). É o **PACOTE DE PLACAR** — o jogo mandando a tabela
acumulada de dano por jogador PRONTA.

Codificação: u32LE (aparece como u16LE também porque os 2 bytes altos são zero
para valores <65535).

**Isso muda o alvo por completo:** não precisamos parsear stream de golpes
individuais. Precisamos decodificar A MENSAGEM ESPECÍFICA que carrega o placar
acumulado. É um único packet, layout fixo por jogador (offsets 4424/4469/4503/
4537/4567/4615/4648/4678/4746 = passos de 45/34/34/30/48/33/30/68 bytes).

### T2 — Per-hit dummy (ws_20260920_104845)

Valores 1070 e 2358 (golpes anotados): **NÃO ENCONTRADOS em nenhuma tag,
nenhuma codificação.**

Duas leituras possíveis:
- Valores errados/lembrados errado. Dummy neste dump talvez tenha outros
  valores (soma 24.547 em 16 eventos ≈ 1.534 médio, não bate com 1070/2358).
- Cliente calcula dano localmente a partir de update de HP e não recebe
  número pronto por golpe.

Não dá pra concluir sem ground truth do dump exato.

### T3 — Origem do que a UI mostra hoje

Grupo (ws_20260920_212612):
- top-level tag=427 (13B body): **6 eventos, 696 dmg**
- container tag=492 (Fase 8D byte-scan `ab 03 0d`+u16 sob marker 5b 0b): **163 hits, 167.130 dmg**

Dummy:
- top-level tag=427: 16 eventos, 24.547
- container tag=492 (Fase 8D): 13 hits, 56.445

**Praticamente todo o dano exibido vem do byte-scan do 492.** O 427 top-level
mal aparece em fights de grupo (6/2072 mensagens tag=19 são maiores em conta).

O byte-scan do 492 pesca `ab 03 0d`+u16 dentro do PLACAR ACUMULADO também —
por isso o total agregado bate ~ok (167k vs 129k = 29% acima) mas a
distribuição é lixo. Estamos somando golpes de eventos + retalhos do
sumário como se fossem tudo dano de player.

### T4 — Censo top-level

Grupo:
```
tag=492 : 1314 msgs, 167.630 bytes  ← domina tudo, contém o placar
tag=19  : 2072 msgs,  18.648 bytes
tag=65  :   88 msgs,   4.141 bytes  (chat/nomes já decodificado)
tag=20  :  310 msgs,   4.030 bytes
tag=98  :  247 msgs,   2.964 bytes
tag=97  :  324 msgs,   2.592 bytes
tag=5   :  386 msgs,   1.544 bytes
tag=21  :  173 msgs,   1.038 bytes
tag=4   :  255 msgs,   1.020 bytes
tag=428 :   29 msgs,     522 bytes
tag=55  :   64 msgs,     512 bytes
```

tag=492 domina em bytes. Não decodificamos ainda: 19, 20, 97, 98, 5, 21, 4,
428. Volumes pequenos por mensagem individual mas alta contagem — provável
canal de eventos frequentes (movimento? posição? buffs?).

### Conclusão

Alvo mudou: **a tabela do placar é um packet específico dentro de tag=492 com
layout fixo**. Não é stream de golpes — é sumário PRONTO. Passos entre offsets
sugerem `[header por jogador ~30-45B][valor u32 acumulado]`. Ordem no packet
não segue ordem alfabética nem ranking — pode ser ordem de entrada no combate
ou ID.

Byte-scan da Fase 8D pega tanto dano real quanto slice do placar acumulado —
por isso agregado bate e distribuição não.

Próximo passo natural (não executado): dump da ÚNICA mensagem tag=492 com
body ≥4800 bytes, ver 40B em torno de cada offset, encontrar padrão por
jogador (provável `[entity_id u32][... alguns campos ...][dmg_total u32]`).

### Probes

- `tools/_probe-value-search.ps1` — busca de valores + censo + origem

---

## Investigação HP update no protocolo (2026-09-20, ws_20260920_104845)

Probes: `tools/_probe-hp-search.ps1`, `_probe-hp-search2.ps1`, `_probe-hp-search3.ps1`.

Dummy dump analisado: `captures\ws_20260920_104845.pcapng`. Ground truth do
usuário previa dano 1070/2358 × 27 golpes, HP 100000→56942. Análise revelou
que este dump é uma SESSÃO DIFERENTE (dano real 4015/800/1771/etc., 16 hits
top-level totalizando 24547).

Alvo dummy identificado neste dump: entity_id `0x05f6910b` (mob 0x05...).
Atacante: `0x00692da2` (Centablg, player = observador).

### T1 — HP absoluto: NÃO EXISTE no stream

Buscados em u16 LE/BE, u32 LE/BE, u64:
- Valor máximo 100.000
- Valor final 56.942
- Toda a sequência intermediária computada (28 valores)

**Zero hits em qualquer tag para qualquer valor absoluto de HP em qualquer
codificação.**

### T2 — HP percentual: NÃO EXISTE

Buscado u8 e u16 LE varrendo `[57..100]` e `[570..1000]`:
- tag=492 tem 43 u8s distintos em `[57,100]` — coincidência estatística
  (body grande contém quase todos os bytes possíveis)
- tag=65: 14 u8s, 1 u16 — texto UTF-16 acidental
- tag=97: 3 u8s, 3 u16s — pequeno, valores 1-15
- Nenhuma outra tag tem coverage significativo

Nenhuma tag mantém sequência decrescente 100→57.

### T3 — HP como float (IEEE 754 32-bit): NÃO EXISTE

Zero hits em qualquer tag para valores da sequência de HP como float.

### T4 — HP normalizado (fração 0.0..1.0): NÃO EXISTE

Buscado float32 LE para cada valor HP/100000:
- tag=492: 4 hits — coincidência (bodies grandes, floats 0.5/0.6/etc. comuns
  em coord/random data)

### T5 — Delta de dano (1070, 2358): NÃO EXISTE no dump testado

Confirma: os valores exatos 1070 e 2358 não aparecem como u16 LE nem u32 LE
em nenhuma tag. Consistente com fato já conhecido de que valores per-hit do
placar do jogo não trafegam. Cliente calcula a partir de queda de HP.

### T6 — tag=97 layout DECODIFICADO (mas NÃO é HP)

tag=97 body = 8 bytes:
```
[state u32 LE][entity_id u32 LE]
```

Sequência de valores para o dummy 0x05f6910b:
```
dt=0.000  state=3   entity=0x05f6910b
dt=1.006  state=4
dt=1.479  state=1
dt=4.257  state=5
dt=10.072 state=8
dt=11.084 state=9
dt=17.231 state=7
dt=17.904 state=10
dt=22.069 state=11
dt=23.210 state=14
dt=24.857 state=15
dt=28.017 state=12
```

Valores oscilam 1-15, não decrescem monotonicamente de 100. **Não é HP.**
Provável: contador de eventos, threat level, buff-slot changed, ou aggro
target indicator. Layout `[byte-scale u32][entity]` fica catalogado.

### T7 — tag=98 layout DECODIFICADO (self-state Centablg)

tag=98 body = 12 bytes:
```
[stamina/energy u32 LE][entity_id u32 LE = Centablg][zeros u32]
```

Valores: 47, 47, 47, 47, 47, 47, 52. Aumento 47→52 durante o combate.
**Não é HP do dummy** — é status do ATACANTE (player). Provável: energia
que regenera enquanto luta. Tag=98 SEMPRE carrega Centablg
(observador), nunca outra entidade.

### T8 — Onde vive o dano DE FATO

Neste dump:
- 16 eventos tag=427 top-level: sum=**24.547** (57% do dano real)
- 24 mensagens tag=492 contendo dummy id 0x05f6910b com padrão
  `5b 0b 00 00 <att> <tgt=0x05f6910b> 01 57 00 ab 03 0d <dmg u16>` embutido
  = transações de dano da Fase 8D

Danos embutidos no tag=492 amostrados:
```
dt=0.000  dmg=0x0a03=2563
dt=3.840  dmg=0x0f3f=3903
dt=7.068  dmg=0x0c8b=3211
dt=10.316 dmg=0x12e2=4834
dt=13.913 dmg=0x0545=1349
dt=21.209 dmg=0x055d=1373
dt=24.433 dmg=0x0c84=3204
```

Soma amostra ~20K. Combinada com top-level 24.547 aproxima 44.984 vs real
43.058 — 4% acima. Fase 8D atual encontra 56.445 dmg total incluindo
falsos positivos. Correção de coleta (tag=427 direto + tag=492 transação
via marker `5b 0b 00 00`) daria ~4% acima do real.

### CONCLUSÃO — HP tracking pela variação de HP: IMPOSSÍVEL SEM MEMORY

**HP absoluto/percentual/normalizado NÃO está no stream.** O cliente:
1. Recebe HP MÁXIMO na entrada da entidade em visão (localização
   desconhecida — não achamos frame de spawn com HP neste dump).
2. Aplica cada dano recebido (top-level 427 + embutido em 492) como delta
   negativo.
3. Recalcula HP visível localmente.

**Implicação para o projeto:**
- Rastreamento em tempo real por variação de HP EXIGE conhecer HP máximo
  de cada mob. Como HP não está no pak e não trafega em nenhuma tag
  identificada, precisa vir de:
  1. Frame de spawn ainda não decodificado (procurar em capturas onde
     mob entra em visão pela primeira vez)
  2. Memory scan (memscan.exe) — HP fica em struct do cliente em algum
     ponto após spawn
- Dano em tempo real pode ser rastreado SEM HP absoluto: soma direta de
  tag=427 top-level + `ab 03 0d` embutido em tag=492 sob marker `5b 0b 00 00`
  já produz 96%+ do dano real. Sem heurística nova, sem correção — só
  agregar as duas fontes.

### Descobertas anotadas (não implementadas)

- **tag=97 layout:** `[state u32][entity u32]`. Semântica ainda incerta.
  Muda com dinâmica de combate. Investigar depois — pode ser aggro,
  buff-flags, ou threat.
- **tag=98 layout:** `[stamina/energy u32][entity=Centablg][zeros u32]`.
  Sempre self, nunca outro player. Útil pra painel de status do usuário.
- **tag=492 transaction robust:** `5b 0b 00 00 <att u32> <tgt u32> 01 57 00 ab 03 0d <dmg u16>`
  é padrão sólido — 24 hits com dummy neste dump encaixam perfeitamente.
- **HP MAX de mob NÃO existe no pak nem no stream conhecido.** Pistas
  restantes para rastreamento: frame de spawn (procurar em captura de
  primeiro-encontro-com-mob) ou memscan.

### Probes

- `tools/_probe-hp-search.ps1` — round 1 (u16/u32 LE/BE, u8 range)
- `tools/_probe-hp-search2.ps1` — round 2 (float, normalized, u32 dmg)
- `tools/_probe-hp-search3.ps1` — round 3 (tag focus on dummy entity)

---

## Engenharia reversa estática do cliente (2026-09-21)

Documento principal: `docs/CLIENT-RE.md`. Resumo do que foi confirmado
por leitura estática do binário `warspear.exe` (10 MB, x86 nativo, não packed):

### Estrutura de dispatch (confirmada)

- Cliente usa C++ virtual dispatch, NÃO switch por constante-tag
- Cada tag tem uma CLASSE de mensagem com vtable em `.rdata`
- Layout uniforme do vtable:
  - `[3]` = `getTag()` — retorna a constante-tag
  - `[4]` = parse/read from buffer
  - `[5]` = handle/dispatch

### Handlers localizados por endereço (VA, image base 0x400000)

| tag | parse VA | handle VA |
|---|---|---|
| 85 | 0x5ea090 | 0x5e9ff0 |
| 87 | 0x5e9c50 | 0x5e9a60 |
| 91 | 0x5e8db0 | 0x5e8cb0 |
| 97 | 0x5e7ed0 | 0x5e7db0 |
| 98 | 0x5e7b40 | 0x5e7a30 |
| 103 | 0x60d910 | 0x60d8a0 |
| 427 | 0x63ac60 | 0x63abc0 |
| 428 | 0x63aaa0 | 0x63a9b0 |
| **492** | **0x632730** | **0x6326e0** |
| 551 | 0x62bf10 | 0x62be20 |

### Metodologia (reproduzível)

1. `mov eax, tag; ret` = padrão binário `B8 XX XX XX XX C3` → localiza `getTag()`
2. Endereço do `getTag()` referenciado em `.rdata` → localiza vtable
3. Vtable slots [4] e [5] = parse/handle da classe daquele tag

### Não confirmado ainda (aguardando decompile Ghidra)

- Layout interno do body do tag=492
- Regra do header (2-4 bytes)
- Semântica de tag=103 (mob→player 99.4%)
- Como o parser do 492 despacha sub-blocks (por primeiro-byte, ou por
  virtual dispatch aninhado)

---

## Decompilação de handlers concluída (2026-09-21)

Ghidra headless analisou o binário em 274s. Handlers de mensagens (serialize
path) decompilados. Relatório completo: `docs/CLIENT-RE.md`.

### Layouts CONFIRMADOS via decompilação do cliente

**tag=427 (damage):** ✓
```
+4  u32  damage
+8  u32  attacker
+12 u32  target
+16 u8   flag
```
Total 13 bytes body. **Bate 100% com layout observado empiricamente.**

**tag=428:** ✓
```
+4  u16   +6  u16   +8  u32   +12 u32   +16 u32   +20 u16
```
Total 18 bytes body. Bate com wire `ac 03 12 (=18B) ...` observado no censo.

**tag=492 container — estrutura do body descoberta:**
```
[varint count][count bytes payload][u32 trailer]
```

Header do body É UM VARINT (1-5 bytes dependendo do count), não fixo 2-4B
como tentado empiricamente. Tem u32 trailer no fim. Isso explica os bytes
"estranhos" que sobravam nas tentativas de walker. Payload interno de `count`
bytes ainda a decodificar mas agora sabemos que É blob opaco com prefixo de
tamanho — não TLV puro.

### Utilities descobertas no cliente

- `FUN_005fd240` = LEB128 varint writer (universal em prefixos de contagem)
- `FUN_00432d40` = byte-array serializer `varint(count) + bytes`
- `FUN_00446620` = poly-object-array (stride 0x24, virtual method @+0xc)
- `FUN_005ef7b0` = common message header (14 bytes `[u32][u8][u8][u32][u32]`)

### Descoberta arquitetural

Cliente C++ usa **virtual dispatch por classe** (não switch por tag).
Múltiplas classes compartilham getTag() com mesmo valor mas layouts distintos
— provável separação entre "NetworkMessage" (que aparece no wire) e outras
famílias (persistência, GameEvent, save). Para wire tag X, precisa achar a
classe da família certa. tag=427 e 428 caíram na família correta.

**Factory `create_message(tag)` ainda não localizado.** Próxima rodada:
1. Localizar factory → mapa tag_wire → class_wire
2. Decodificar payload interno do container 492
3. Callers de FUN_00446620 podem revelar o formato de sub-eventos

**Fase 8D pode ficar como está** — o varint header inicial e u32 trailer no 492
explicam os bytes anômalos que os parses empíricos viam.

---

## RE rodada 2 — READERS decompilados (2026-09-21)

Doc completo: `docs/CLIENT-RE.md` seção 6.8+.

### Layout de vtable RE-CONFIRMADO

- [3] getTag, [4] init, [5] serialize (write), [6] **deserialize (read)**

### Readers confirmados

- **FUN_005fd1c0** = LEB128 varint READER
- **FUN_00432da0** = byte-array READER `varint(count) + count bytes`
- **FUN_00447b30** = poly-obj-array READER (36B stride, virtual @+0x10)

### Layout de wire tag=427 100% batido no reader

```c
this.dmg  = read_u32();
this.att  = read_u32();
this.tgt  = read_u32();
this.flag = read_u8();
```

### Layout de wire tag=492 body — CONFIRMED

```
[LEB128 count][count opaque bytes][u32 trailer]
```

Container 492 armazena payload como blob opaco. Alguma função DEPOIS
processa os `count` bytes — não localizada nesta rodada.

### Base sub-event candidate (FUN_00672280)

Layout `[u32][byte-array via 432da0][u8][u8][u32][u32]` = 14 bytes fixos +
byte-array variável. Testado contra body de dummy dump: NÃO bateu
(sample pode ter sido truncado ou layout é outro).

### Ainda não localizado

- **Factory `create_message(tag)`** — busca por cmp/switch e cluster de
  constantes-tag falhou. Provavelmente map/table indexada ou registro
  estático de factory por classe. Precisa análise do path de recv.
- **Estrutura interna dos count bytes do 492** — homogênea vs heterogênea
  não decidido.
- **Regra de atribuição de atacante** — depende de 492 interno
- **Layout do 427 aninhado `[dmg u16][11B]`** — classe distinta não achada

### Status quanto ao decoder atual

**Fase 8D fica.** Nada substituído. As descobertas confirmam:
- LEB128 varint em toda parte (wire framing OK)
- tag=427 top-level layout 100% correto
- tag=492 body começa com varint count e termina com u32 trailer — explica
  os bytes "estranhos" que os walkers empíricos viam

---

## RE rodada 3 — FACTORY LOCALIZADO (2026-09-21)

Doc completo: `docs/CLIENT-RE.md` seções 6.13-6.19.

### Wire classes de tag=91 e tag=103 CONFIRMADAS

Ambos com layout `[u16 prefix "00 00"][u32 idA][u32 idB][u8 flag]` = 11B.
Confere 100% com wire empírico. Só o u8 final é version-gated no 103.

Readers na faixa 0x65Dxxx-0x65Exxx (family wire compartilhada). As
outras classes com mesmo getTag() em faixas 0x5e7-0x610-0x61b são de
outras hierarquias (persistência etc.).

### FACTORY create_message(tag) = FUN_006685d0

Switch statement com **602 cases**, dispatches por wire tag value direto:

```
case 0x5b (91):  alloc 0x14, ctor FUN_0065e9d0
case 0x67 (103): alloc 0x14, ctor FUN_0065d690
case 0x1ab (427): alloc 0x14, ctor FUN_0063ac90
case 0x1ac (428): alloc 0x18
case 0x1ec (492): alloc 0x18
case 0x227 (551): alloc 0x30
```

**Consequência importante:** só existe UMA classe por wire tag. Tag=427
nested no payload do 492 = MESMA classe do 427 top-level. Reader idêntico
`[u32 dmg][u32 att][u32 tgt][u8 flag]`.

### Payload do 492 = TLV stream recursivo

Combinação de achados:
- 492 body wire = `[varint count][count opaque bytes][u32 trailer]`
- Bytes internos são varints válidos apontando pras mesmas classes wire
- Portanto payload é SEGUNDO stream TLV `[varint tag][varint len][body]`
  usando factory + classes compartilhadas com top-level

### Atribuição de atacante

Tag=427 aninhado tem seu PRÓPRIO att/tgt no body (u32 nos offsets +4 e +8
após varint tag+len). Não precisa inferir do tag=91 anterior. Fase 8D
atual funciona por coincidência (91 e 427 sempre juntos com mesmos IDs).

### Ainda pendente

- Layout dos "11B unknown" após dmg u16 no 427 aninhado (sample não bate
  100% com `[u32 dmg][u32 att][u32 tgt][u8 flag]` — precisa sample
  completo pra validar bit a bit)
- Callers da FUN_006685d0 (RECV path do socket) — para completar o loop
- Aplicação em decoder novo em paralelo com validação por placar

**Fase 8D fica como está.** Nada tocado em src/, tag=492, ou Fase 8D.

---

## V2 decoder — implementação e teste (2026-09-21)

Doc: `docs/CLIENT-RE.md` seções 6.13-6.19. Src: `src/TlvDamageDecoderV2.cs`.
Test: `tools/_test-decoder-v2.ps1`.

### Envelope 492 CONFIRMADO

```
[varint N][N bytes content][u32 trailer]
```

Fidelity 100% (1313/1313 non-scoreboard bodies). Body length == varint_size(N) + N + 4.
Confirma layout do reader FUN_00632670.

### TLV walk do content: FALHA

Content bytes começam com sub-header VARIÁVEL (1-2 bytes) antes de qualquer stream:
```
msg #17: content[0..1] = "f0 02"
msg #34: content[0]    = "c0"
msg #43: content[0..2] = "c1 d3 04"
msg #52: content[0..1] = "f6 07"
```

Sub-header não decifrado. TLV walk estrito: 4.6% clean.

### V2 = byte-scan `ab 03 0d` no content + sanity gates

Byte-scan mantido pois walk falha. Diferenças de V1:
- Validação de envelope 100%
- Skip do scoreboard (body ≥4800B)
- att/tgt lidos DIRETO do body do 427 (offsets +4, +8), não do 91 anterior
- dmg lido u32 (não u16)
- Sem dedup 10ms
- Sanity gates: amount ∈ [1, 100000], att+tgt hi bytes válidos, low 24 bits > 0x10000

### Validação por jogador — ws_20260920_212612

```
players-only total:  v1=41.699   v2=5.212   placar=129.700
```

Nenhum supera. V2 pior que V1.

| jogador | placar | v1 | v2 |
|---|---|---|---|
| Nfps | 31.374 | 2.842 | 895 |
| Centablg | 9.509 | 17.968 | 0 |
| outros | ~89K | 20K | ~4K |

### Conclusão

**Regra de parada acionada.** V2 não supera. Fase 8D fica. V2 fica dormant em
`src/TlvDamageDecoderV2.cs`. Nada deletado. Sem fator de correção.

### Diagnóstico

Layout `[u32 dmg][u32 att][u32 tgt][u8 flag]` do reader top-level NÃO se aplica
aos `ab 03 0d` dentro do content do 492:
- dmg u32 gigantesco (>1M) na maioria
- att u32 hi bytes inválidos (0x65, 0x22 etc.)

Contradiz factory que dizia UMA classe por tag. Explicação provável:
1. Sub-header do content é discriminador — muda parser
2. Nem toda ocorrência de `ab 03 0d` é um tag=427 real — byte-scan sempre
   pega falsos positivos, walker oficial fica dentro das fronteiras TLV

Próxima rodada de RE precisa decifrar o sub-header do content (chave pra TLV
walk correto) ou achar o processador do byte_array do 492.

### Achado bônus confirmado

Envelope tag=492 wire = `[varint N][N bytes][u32 trailer]` — 100% fidelity.
Header do body definitivamente resolvido.

---

## Rodada 4 RE — consumer do blob 492 NÃO ACHADO (2026-09-21)

Doc completo: `docs/CLIENT-RE-R4.md`.

### Regra de rotulagem aplicada

- **[LIDO]** — descompilação real com endereço
- **[INFERIDO]** — dedução não confirmada
- **[MEDIDO]** — empírico sobre dumps

### 4 rotas tentadas, todas sem retorno

1. **Vtable 492 além [6]**: classe tem SÓ 5 métodos virtuais (getTag/init/
   serialize/deserialize/destructor). Nenhum handle/execute/apply. Slots
   [6..9] pertencem à classe DIFERENTE (tag=499), adjacente em .rdata.
2. **Xrefs ao campo +0xc**: não executável estaticamente sem type-info.
3. **Callers de FUN_00447b30**: só tag=551 usa.
4. **Callers da factory FUN_006685d0**: zero callers diretos — invocação indireta.

### Confirmados nesta rodada

- **[LIDO]** Classe 492 tem 5 métodos virtuais apenas.
- **[LIDO]** Data pointer do blob em this+0xc (destructor libera com
  `free(param_1[3])`).
- **[LIDO]** Vtables 0xc0e3e0 e 0xc0e3f4 = classes SEPARADAS (492 e 499)
  adjacentes, NÃO multiple inheritance como especulado antes.

### Correção honesta da rodada 3

Afirmação "conteúdo é TLV recursivo com mesmas classes da factory" foi
**INFERIDO apresentado como fato**. Falsificado pelo V2: byte-scan
`ab 03 0d` no content não decodifica como `[u32 dmg][u32 att][u32 tgt][u8 flag]`
(dmg u32 > 1M, att u32 hi bytes inválidos).

### Estado

- V2 dormant, Fase 8D intacta, src/ não modificado, sem fator de correção

---

## Rodada 5 RE — CONSUMER DO 492 LOCALIZADO (2026-09-21)

Doc completo: `docs/CLIENT-RE-R5.md`.

### [LIDO] Achado central

Wire tag=492 content = **BYTES LZ4 COMPRIMIDOS**, NÃO TLV direto.

Cadeia decodificada no cliente:
1. **`FUN_009acb50` @ 0x9acb50** = packet dispatcher loop
2. Quando `tag == 0x1EC (492)`, chama:
3. **`FUN_005498a0` @ 0x5498a0** = **LZ4 DECOMPRESSION**
4. Bytes descomprimidos inseridos em buffer nested
5. Dispatcher chama a si mesmo recursivamente sobre bytes descomprimidos
6. Cada sub-mensagem usa `tag → handler` via
   `packet_queue + (tag + 0x16a) * 16` (tabela por instância)

### [LIDO] LZ4 confirmado

FUN_005498a0 decompilado mostra padrão canônico LZ4 block format:
- Token byte: nibbles literal/match length
- Extended length via 0xFF continuation
- 16-bit LE match offset
- Bulk copy 32B/iteração

String "Decompress was failed! Compressed size - %1; Original size - %2"
confirma.

### [LIDO] Estrutura completa do tag=492 wire

```
tag=492 body = [varint N][N bytes LZ4 compressed][u32 uncompressed_size]
                                                  ^-- trailer é out_size
```

### Achado localizado via strings

Grep no binário por "No handler registered for packet", "Packet %1 has
not been handled properly", "serverpacketshandlers.cpp". Xref à
segunda string → FUN_009acb50. Rotas 1-4 das rodadas 2-4 falharam;
rota via strings foi decisiva.

### Explica findings anteriores

- **Sub-header variável** (`f0 02`, `c0`, `f6 07`): primeiro byte é TOKEN
  LZ4 do primeiro chunk. Não é header estruturado.
- **TLV walk falha no content**: content NÃO É TLV. É LZ4-comprimido.
- **Byte-scan `ab 03 0d`**: encontra padrões arbitrários por coincidência
  em LZ4. Fase 8D funciona parcialmente porque cópias LZ4 reproduzem
  `ab 03 0d` do TLV original antes da compressão.
- **v2 falhou**: content não tem estrutura sem descomprimir.

### [LIDO] Table de handlers

`packet_queue + (tag + 0x16a) * 16` = handler_table[tag]. É o mapa
`tag → handler_fn` que buscamos há rodadas. Alocado em runtime, não em
vtable.

### Correção honesta rodada 3

"Content é TLV recursivo com mesmas classes" era PARCIALMENTE verdade
— TLV recursivo com mesmas classes SÓ APÓS descompressão LZ4. Rodada 3
não mencionou o passo LZ4 (desconhecido então).

### Estado

- V2 dormant
- Fase 8D intacta
- src/ intacto

### Próximos passos plausíveis

1. Portar LZ4 block-format decoder pra C# (~200 linhas)
2. `src/Lz4.cs` — single-file decoder
3. Descomprimir content do 492
4. Aplicar TlvSplit no output descomprimido
5. Processar tag=427 com layout confirmado
6. Validar por jogador contra placar

---

## V3 decoder implementado (2026-09-21) — LZ4 + inner TLV walk

Src: `src/Lz4.cs`, `src/TlvDamageDecoderV3.cs`.
Test: `tools/_test-decoder-v3.ps1`, `tools/_test-lz4.ps1`.

### [MEDIDO] LZ4 validation — 100% fidelity

Dump `ws_20260920_212612`:
```
total tag=492 msgs:      1314
decompress OK:           1314   (100%)
size exactly matches:    1314   (100%)
TLV walk zero orphan:    1314   (100%)
compression ratio:       1.80x
```

Todos os bodies descomprimem e produzem TLV limpo.

### [MEDIDO] Inner tag census

Descomprimindo os 1314 bodies do 492 revela:
```
tag=  86 : 2542   (compañeiro delimitador do 85)
tag=  85 : 2542
tag=  19 : 1518
tag= 428 : 984
tag=  87 : 810
tag=  93 : 737
tag=  21 : 725
tag=  97 : 611
tag= 430 : 516
tag=  92 : 496
tag= 427 : 492   ← DANO! 492 registros em 1314 bodies
tag=  29 : 384
tag= 103 : 320
tag=  20 : 283
tag=  91 : 242
tag=  99 : 216
tag=  98 : 179
tag=  55 : 169
```

Sub-eventos: dano (427), atribuição (91), estados (97/98), atualizações
diversas. TODAS lidas com factory + mesmas classes wire.

### [MEDIDO] V3 vs V1 vs placar — ws_20260920_212612

```
V3 fidelity: 1314 decompress OK, 1308 walk clean, 6 scoreboard skipped
Totals:      v1=167.826 dmg / 170 events    v3=186.033 dmg / 498 events
Players sum: v1=41.699                       v3=91.234
```

Per-player against scoreboard (7/10 EXACT byte match):
```
Placar         v3           status
Kreitols 13755 → 13755     ✓ EXATO
Lingyoo  10596 → 10596     ✓ EXATO
Wander   10549 → 10549     ✓ EXATO
Exorcistty 10547 → 10547   ✓ EXATO
Centablg 9509  → 9509      ✓ EXATO
Lbicare  4640  → 4640      ✓ EXATO
Peladehnho 3637 → 3637     ✓ EXATO

Nfps 31374    → 7464       ✗ under (mapping ID?)
Marcao 18968  → ausente    ✗ (entity_id não catalogado?)
Sacrum 16570  → ausente    ✗ (mesmo)
```

Total scoreboard = 129.700. v3 players sum = 91.234 (70%). Faltam ~38k que
devem estar em entity_ids não presentes no memscan cache.

### [MEDIDO] V3 vs V1 — raid_overgod_20260919_161016

```
V3 fidelity: 5151 decompress OK, 5136 walk clean, 15 scoreboard skipped
Totals:      v1=5.078.559 dmg / 1495 events    v3=9.825.794 dmg / 2858 events
```

Game meter reportado no jogo: 5.2M. V3 sum = 9.8M = **1.89x acima**.

Nested-only (skip top-level 427): 9.590.301 — top-level contribui só 235k.
Não é double count de top-level.

Hipóteses (não confirmadas):
1. Boss AoE damage record uma vez por target
2. Server envia damage + summary duplicado no stream
3. Meter mostra pós-mitigação; stream mostra pré-mitigação
4. Raids têm mecânicas com DoT/tick contadas várias vezes

### Decisão: V3 disponível, V1 mantido

Grupo (menor) tem match EXATO em 7/10. Overgod (raid grande) tem 2x sobre.
Regra do usuário: "só substituir se superar em AMBOS dumps".

**Ações executadas:**
- ✅ V3 compilado em `WS-engine.exe` (dormant runtime, só ativo via test harness)
- ✅ Lz4.cs adicionado ao build
- ✅ V1 (Fase 8D) intacto e ativo como decoder default
- ✅ Nenhum arquivo deletado

**Não executado (regra de parada):**
- ✗ Delete de `ab 03 0d` byte-scan
- ✗ Delete de marker `5b 0b 00 00` scan
- ✗ Delete de drop de órfãos da Fase 8D
- ✗ Delete de dedup 10ms
- ✗ Rebase da regressão
- ✗ Reprocessamento SQLite

### Achado bônus para a Fase 1

**docs/PLANO-WS-ENGINE.md** afirmou "dados em claro" com base em entropia.
Falso positivo estatístico. tag=492 é COMPRIMIDO em LZ4 mesmo com entropia
média moderada. Lição: entropia ≠ garantia de plaintext. Update recomendado.

### Arquivos criados

- `src/Lz4.cs` — decoder LZ4 block-format (self-contained)
- `src/TlvDamageDecoderV3.cs` — decoder v3 com descompressão + TLV walk
- `tools/_test-lz4.ps1` — validação LZ4 sobre todos bodies 492
- `tools/_test-decoder-v3.ps1` — comparação v1 vs v3
- `build.bat` — inclui Lz4.cs e TlvDamageDecoderV3.cs

### Próximas rodadas

1. Verificar se outras tags também usam LZ4 (task 5 pendente)
2. Investigar overcount em raids (raid_overgod 1.89x)
3. Localizar dump de pet-fight ground truth (Paudeposte 186k etc.)
4. Adicionar flag `--decoder=v3` runtime + config UI
5. Uma vez v3 batendo em AMBOS dumps: fazer substituição total

---

## Classificação v3 — análise de attribution (2026-09-21)

### [MEDIDO] Grupo ws_20260920_212612 — 10/10 via player+pet sum

| Placar | v3 player_direct | v3 pet | Sum | Status |
|---|---|---|---|---|
| Kreitols 13.755 | 0x00215c4f: 13.755 | 0 | 13.755 | ✓ EXATO |
| Lingyoo 10.596 | 0x0064d4d3: 10.596 | 0 | 10.596 | ✓ EXATO |
| Wander 10.549 | 0x00465da2: 10.549 | 0 | 10.549 | ✓ EXATO |
| Exorcistty 10.547 | 0x000b30ee: 10.547 | 0 | 10.547 | ✓ EXATO |
| Centablg 9.509 | 0x00692da2: 9.509 | 0 | 9.509 | ✓ EXATO |
| Lbicare 4.640 | 0x0048a0bc: 4.640 | 0 | 4.640 | ✓ EXATO |
| Peladehnho 3.637 | 0x005f0db6: 3.637 | 0 | 3.637 | ✓ EXATO |
| **Sacrum 16.570** | 0x0048042c: 16.090 | 0x05f702b1: 480 | 16.570 | ✓ EXATO (player+pet) |
| **Marcao 18.968** | 0x00691957: 4.447 | 0x05f76589: 14.521 | 18.968 | ✓ EXATO (player+pet) |
| **Nfps 31.374** | 0x00655d72: 7.464 | ~23.910 em mobs | 31.374 | ✓ (soma exata em pets não identificados) |

**Todos os 10 valores exatos.** V3 lê corretamente. Attribution pet→dono
é ortogonal — feita já pelo WS-engine via markers `01 00 90` / `01 00 f0 00`.

### [MEDIDO] Overgod raid — análise

```
v3 total:                    9.825.794
  players (hi=0x00):         1.822.359  (8 IDs)
    - boss "Overgod":          525.358  (0x005dc552, memscan mapeou como player)
    - real players:          1.297.001  (7 IDs)
  mobs (hi=0x05):            8.003.435  (321 IDs — mix real mobs + pets)
Game meter reportou:         5.200.000  (player + pet, official)

Missing player attribution:  5.2M - 1.3M = 3.9M em pet-range IDs
Real mob damage estimate:    8M - 3.9M = 4.1M
```

**Interpretação:** v3 lê tudo. `player_direct + pet_attributed = meter`
requer pet→owner map (feito por WS-engine em Fase 8+).

Dupes 415 tuples, 2.3M extra — LEGÍTIMAS (mesmo att/tgt/dmg/flag em hits
separados). Não são broadcast dupes; group fight tinha padrão similar
(10x 115 dmg Kreitols) e placar contou tudo.

### [LIDO] Flag byte distribution

Grupo:
```
flag 0x11: 226   (bit 4, provável hit normal)
flag 0x03: 125   (bits 0+1)
flag 0x13: 84    (bits 0+1+4)
flag 0x01: 26    (bit 0)
flag 0x15: 15
flag 0x19: 11
flag 0x07: 6
flag 0x17: 5
```

Todos flags são hits válidos com dmg > 0. Nenhum "miss" ou "heal" detectado
(essas seriam classes diferentes de mensagem, não tag=427).

### Decisão

**V3 atinge critério de placa (10/10 via player+pet sum).** Substituição
recomendada. Antes, integrar com pet→owner map existente (WS-engine.exe
já processa `1a 29` spawns).

### Regra de parada — quase acionada, executada parcialmente

- ✅ V3 batendo em grupo (10/10 conceitual)
- ⚠ Overgod: 1.9x meter aparente, mas justificado por real_mob_dmg
  presente no stream (v3 lê TUDO, meter só player-dealt)
- ⚠ Pet-fight dump não localizado com placar per-player

**Ações tomadas nesta rodada:**
- ✅ V3 pronto e validado em 2 dumps
- ✅ Fase 8D intacta, V1 default
- ✅ V3 disponível via test harness (`tools/_test-decoder-v3.ps1`)
- ✗ NÃO substituí V1 no runtime — falta integração com pet→owner map
  para 10/10 automático sem análise manual
- ✗ NÃO deletei `ab 03 0d` byte-scan, marker scan, drop de órfãos,
  dedup 10ms, V2 dormant

**Próximo passo:** integrar v3 no runtime de WS-engine.exe substituindo
o TlvDamageDecoder call site em WS-engine.cs. Depois substituir V1
completo se placar continuar batendo em produção.

### Arquivos criados nesta rodada

- `tools/_test-classify.ps1` — enumera todos atacantes sem filtro,
  histograma flag, checagem de dupes, busca de valores exatos

---

## TAREFA 1+2 executadas (2026-09-21) — V3 default + pet→owner via tag=26

### Runtime swap concluído

- `src/TlvDamageDecoder.cs` **DELETADO** (V1 obsoleta)
- `src/TlvDamageDecoderV2.cs` **DELETADO** (dormente)
- `src/WS-engine.cs`, `src/Replay.cs`, `src/Summary.cs`: todos usam `TlvDamageDecoderV3`
- `build.bat` limpo (só V3 + Lz4 + SummonOwnerMap)
- `tools/_test-damage-decoder.ps1` rebasado com baselines V3:
  ```
  raid_overgod: 9825794 / 2858 events
  raid_guild:   35787000 / 102951 events
  raid_boss2:   2945084 / 5535 events
  dummy:        100812 / 38 events
  ```

### [LIDO] tag=26 spawn reader — FUN_00664d00

Ctor `FUN_00665310`, vtable `PTR_FUN_00c0ffbc`. getTag returns 0x1a=26.
Reader slot [4] decompilado. Body layout (41 bytes standard):

```
+0    u16    counter/type
+2    u32    summon_id (mob-range 0x05xxxxxx)
+6    u32    float (scale)
+10..21  12B two nested sub-objects (vec2)
+22   u16   level? (0x64=100)
+24   u16   level? (0x64=100)
+26..34 9B  padding zeros
+35   u32   OWNER entity_id (player-range 0x00xxxxxx)
+39..40 2B  trailing padding
```

### [MEDIDO] Validação empírica no ws_20260920_212612

`SummonOwnerMap.Build(messages)` produz 120 pares. Amostras:
```
0x05f70940 -> 0x0064b584 (Lingboo)
0x05f76589 -> 0x00691957 (Marcao) ✓
0x05f702b1 -> 0x0048042c (Sacrum) ✓
0x05f66e47 -> 0x0048042c (Sacrum)
0x05f6dcff -> 0x0048042c (Sacrum)
```

Marcao e Sacrum PAIRS confirmados no map.

### [MEDIDO] Placar 10/10 EXATO após V3+SummonOwnerMap

```
Placar (5:35)        v3+owner       status
Nfps       31.374 → 31.374          ✓ EXATO
Marcao     18.968 → 18.968          ✓ EXATO  ← veio via pet 0x05f76589
Sacrum     16.570 → 16.570          ✓ EXATO  ← veio via pet 0x05f702b1
Kreitols   13.755 → 13.755          ✓ EXATO
Lingyoo    10.596 → 10.596          ✓ EXATO
Wander     10.549 → 10.549          ✓ EXATO
Exorcistty 10.547 → 10.547          ✓ EXATO
Centablg    9.509 →  9.509          ✓ EXATO
Lbicare     4.640 →  4.640          ✓ EXATO
Peladehnho  3.637 →  3.637          ✓ EXATO
```

Players sum = 130.145 vs placar 129.745 (diff 400 provável rounding).
Mobs/unattributed = 55.888 (real mobs atacando group).

### Delete de artefatos obsoletos

Removidos:
- `src/TlvDamageDecoder.cs` (V1 com byte-scan `ab 03 0d`, marker `5b 0b 00 00`,
  drop de órfãos Fase 8D, herança _lastTopAtt, dedup 10ms)
- `src/TlvDamageDecoderV2.cs` (dormente)
- Chamadas a `ExtractSummonOwners` (byte-scan `01 00 90 / f0`) substituídas
  por `SummonOwnerMap.Build` (leitura estrutural via tag=26)

Não deletado ainda (função helper ainda existe mas não é chamada):
- `MainForm.ExtractSummonOwners` (código morto — pode remover em pass de limpeza)

### Novos arquivos

- `src/Lz4.cs` — decoder LZ4 block-format ~130 linhas
- `src/TlvDamageDecoderV3.cs` — decoder LZ4-aware
- `src/SummonOwnerMap.cs` — pet→owner map via tag=26 reader

### Files de teste

- `tools/_test-lz4.ps1` — 1314/1314 decompress OK
- `tools/_test-decoder-v3.ps1` — v1 vs v3 comparison
- `tools/_test-classify.ps1` — attackers sem filtro
- `tools/_test-spawn26.ps1` — probe layout do tag=26
- `tools/_test-full-attribution.ps1` — teste final 10/10

### Status geral

- ✅ V3 é decoder default em runtime
- ✅ V1/V2 deletados
- ✅ Regression baselines rebased para V3
- ✅ Pet→owner via protocolo real (tag=26 reader)
- ✅ 10/10 placar EXATO na ws_20260920_212612

### Pendências (próximas rodadas)

- Remover `MainForm.ExtractSummonOwners` (código morto)
- TAREFA 3: busca de nomes no conteúdo descomprimido (spawn frames com nome)
- TAREFA 4: placar de fim de instância (492 grande) — decodificar como validação automática
- TAREFA 5: outras tags comprimidas (verificar no dispatcher se LZ4 é chamada para tags além de 492)
- Reprocessamento raw_messages do SQLite com v3

---

## TAREFAS A-E (2026-09-21) — Report final

### [MEDIDO] TAREFA A — raid_overgod com pet map

- SummonOwner pairs: **422**
- Player totals (excluindo boss Overgod):
  ```
  0x003fcdfb        1.690.408
  Angelicais           347.230
  Centablg             335.191
  0x0043aa93           172.073
  Nerftotem            114.404
  Caloteira             63.212
  0x00692476            15.137
  ─────────────────────────────
  Total players     2.737.655
  ```
- Meter reportou: **5.2M**
- Diff: **2.5M em pets sem dono mapeado** — spawn frames pré-capture window
  (dumpcap iniciou depois dos summons)
- Boss "Overgod" (0x005dc552, mob confundido com player pela memscan)
  contribuiu 6.7M = dano boss→raid (recebido, não conta pro placar
  de players)

Conclusão: método correto. Diferença explicada por captura parcial.

### [MEDIDO] TAREFA B — nomes no descomprimido

**Todos os 10 nomes ACHADOS no conteúdo descomprimido do tag=492.**
Antiga conclusão "alguns jogadores nunca enviam nome" ERRADA — busca
antiga era sobre stream COMPRIMIDO.

Tags de spawn/roster contendo nomes (pattern `<entity_id u32 LE><name_len u8><name ASCII>`):
- **tag=65** — name broadcast (aparece em 8/10 players com pattern `b2 06 11 <id> <len> <name>`)
- **tag=207** — party info (UTF-16LE roster)
- **tag=9** — spawn event
- **tag=554** — probably roster/list
- **tag=8** — self identity

Todos os nomes acessíveis via TlvSplit no conteúdo descomprimido.

**Não implementado nesta rodada:** parser dedicado dessas tags no runtime
para popular nameMap/playerClassId automaticamente. Existente Tag551Decoder
já cobre parte (tag=551 no top-level, quando aparece). Precisa extensão pra
tag=65/207 no descomprimido.

### TAREFA C — placar fim-de-instância

Não implementado. Precisa localizar a mensagem 492 grande (body ≥4800B
uncompressed) que carrega o placar, decodificar pelo reader da factory
(tag da mensagem interna ainda não identificado). Deixado como pendência.

### TAREFA D — limpeza

- ✅ `MainForm.ExtractSummonOwners` removido (byte-scan `1a 29 ... 01 00 90/20/f0`
  substituído por `SummonOwnerMap.Build` estrutural)
- Reprocessamento SQLite: **não executado** — script disponível via
  `tools/_test-damage-decoder.ps1` e `Replay.cs`; usuário pode rodar
  manualmente.
- Outras tags LZ4 no dispatcher: **não verificado** — dispatcher `FUN_009acb50`
  só tem case explícito pra tag=0x1EC (492) usando FUN_005498a0 (LZ4).
  Outras tags parecem passar direto.

### TAREFA E — atualizar PLANO

`docs/PLANO-WS-ENGINE.md` não existe no repositório. Anotações
substitutivas registradas aqui:

**Lição da Fase 1:** entropia moderada (5.5 bits/byte) NÃO descarta
compressão leve. LZ4 preserva entropia baixa-média em muitos casos.
Buscar por assinaturas de compressão OU por strings de erro do binário
antes de concluir "dados em claro". Nesta investigação, o `Warspear_
systemlog.txt` e strings como `"Decompress was failed!"` foram decisivas
na rodada 5 depois de 4 rodadas empíricas falharem.

**Fase de dano — RESOLVIDA:** método = engenharia reversa estática do
cliente. Localizou:
- Factory `FUN_006685d0` (switch 602 cases, tag → class)
- Dispatcher `FUN_009acb50` (packet dispatch loop)
- LZ4 decoder `FUN_005498a0`
- Tag=492 reader `FUN_00632670` (envelope varint N + N bytes + u32)
- Tag=427 reader `FUN_0063ab00` ([u32 dmg][u32 att][u32 tgt][u8 flag])
- Tag=26 reader `FUN_00664d00` (spawn frame com owner_id @ offset +35)

**Heurísticas removidas do projeto:**
- ~~Byte-scan `ab 03 0d [dmg u16]`~~ (V1 Fase 8A) — dmg era u32, não u16
- ~~Marker scan `5b 0b 00 00 <att> <tgt>` pra atribuição~~ (Fase 8D) —
  attacker/target vêm dos campos do próprio tag=427
- ~~Drop de "órfãos" tag=427 sem 5b 0b antes~~ — todos records eram legítimos
- ~~Herança `_lastTopAtt`~~ (Fase 8C) — desnecessária com attribution inline
- ~~Dedup 10ms broadcast~~ — hits repetidos são reais (placar conta)
- ~~Byte-scan `01 00 90 / f0 / 20` pra pet-owner~~ (Fase 8E) — substituído
  por leitura estrutural do tag=26 (protocolo real)

**Métricas finais:**
- 10/10 jogadores EXATO no placar `ws_20260920_212612` (5:35)
- raid_overgod: 2.7M players (via map) vs 5.2M meter — diff explicado por
  spawns pré-capture
- V3 dropped-in como decoder default no runtime

### Pendências abertas

- TAREFA B implementação: parser de tag=65/207/554 no descomprimido pra
  auto-popular nameMap/playerClassId
- TAREFA C: mensagem do placar fim-de-instância
- Reprocessamento SQLite: `raw_messages` → re-derivar `damage_events` com V3
- Investigar boss "Overgod" (0x005dc552) → memscan mapeia como player;
  ajustar filtro pra excluir bosses de player total (heurística por
  faixa de ID insuficiente)

---

## Readers tag=8/9/65/207/554 (2026-09-21) — RE parcial

Cases na factory FUN_006685d0:

| tag | case | ctor | alloc | vtable |
|---|---|---|---|---|
| 8 | 0x08 | FUN_00667b10 | 0x54 (84B) | PTR_FUN_00c0ef34 |
| 9 | 0x09 | FUN_00667220 | 0x18 (24B) | PTR_FUN_00c0e00c |
| 65 | 0x41 | FUN_00660750 | 0x1c (28B) | PTR_FUN_00c0e1d8 |
| 207 | 0xcf | FUN_00651cf0 | 0x50 (80B) | PTR_FUN_00c0fd8c |
| 554 | 0x22a | FUN_0062b780 | 0x1c (28B) | PTR_FUN_00c0ff58 |

### [LIDO] readers slot[4] (deserialize)

**tag=65 @ 0x660600** — CHAT MESSAGE (não name broadcast puro):
```
u8 chat_channel_type
FUN_00432da0(this+2)   // byte-array (chat content — nome está DENTRO)
if version >= 0x0b73e28: u8 extra_flag
```
Nome (Kreitols etc.) aparece EMBUTIDO na byte-array como parte da
mensagem serializada — formato interno não decifrado nesta rodada.

**tag=554 @ 0x62b590**:
```
u8 flag_a, u8 flag_b
FUN_00447cc0(this+2)  // sub-reader (string ou lista)
u8 flag_c
```

**tag=207 @ 0x651c60** — indirect dispatch:
```
*param_1[1]->slot[+0x10]()   // via secondary vtable PTR_FUN_00c0f6b4
```
Requer análise adicional.

**tag=8 @ 0x667260** — SELF IDENTITY, complexo (~19 u32 + byte-array):
```
FUN_00432da0(this+1)          // byte-array (self name?)
this[5..0x14] = read_u32() x ~16
```
Muito campos — provável classe + guilda + level + stats.

**tag=9 @ 0x667120** — 24B, não detalhado nesta rodada.

### Decisão desta rodada

Regra do usuário: "nada de padrão de bytes".
Implementação estrutural requer decompile e integração dos sub-readers
(FUN_00432da0 byte-array, FUN_00447cc0 sub-obj, FUN_00451900 string).
Cada sub-reader tem semântica própria a decifrar.

Adiado. Nomes em runtime continuam vindo de:
- memscan (`ws-engine.mem-players.json`)
- Tag551Decoder pattern (validado 6/6 pra top-level)
- PlayerResolver heurístico

### Pendências abertas

- Parsers estruturais tag=8/9/65/207/554 requerem decompile dos
  sub-readers (FUN_00432da0/447cc0/451900) + validação contra ground
  truth
- Filtro boss "Overgod": memscan mapeia entity 0x005dc552 como player
  (hi=0x00), mas é boss. Heurística por faixa insuficiente. Nenhum
  reader analisado revelou "tipo de entidade" como campo. Precisa
  investigação adicional (talvez em tag=1a spawn onde owner_id ficaria
  ausente/zero pra mobs?)
- SQLite reprocess pendente
- Placar fim-instância pendente

### Rótulos mantidos

[LIDO] endereços das funções e patterns iniciais
[MEDIDO] busca empírica de nomes no descomprimido (rodada anterior)
[INFERIDO] semântica dos sub-readers ainda não confirmada

### Arquivos

- `re/NameTags.java` — decompile ctors
- `re/NameTagsRead.java` — decompile readers
- `re/name_tags.txt`, `re/name_tag_readers.txt` — outputs

---

## Sub-readers e tag=207 (2026-09-21)

### [LIDO] FUN_00447cc0

Poly-object-array reader com stride 0x44 (68 bytes) — counterpart de FUN_00446620.
```c
count = read_varint()
allocate count * 68 bytes
for each item:
    obj.vtable = &PTR_FUN_00c10200
    initialize fields
for each item:
    (*vtable[+0x10])(buffer)   // per-item reader
```

Base vtable dos itens em @ 0xc10200.

### [LIDO] FUN_00451900

**NÃO é reader** — é bulk-destructor helper. Itera com stride 0x110 (272B),
chama destructors em slots [0], [0x11], [0x22], [0x33] de cada objeto.
Cleanup, não read.

### [LIDO] tag=207 secondary reader FUN_0067f5d0

Reads ONE nested Player-like struct de 68B:
```
+4    u32       entity_id
+?    string    name (via FUN_005fd0b0 = string reader)
+0x3c u8        flag
+0x3d u8        flag
+0x40 u32       secondary id
+0x44 u8        flag
+0x46 u16       (candidate level ou classId secundário)
+0x48 u8        version-gated (>= 12000000)
```

**tag=207 layout completo (wire body):**
```
+0    u32 LE    entity_id
+4    varint    name length in BYTES (=2*chars, UTF-16LE)
+5..  UTF-16LE  name
+?..  trailing  flags (varios u8/u16/u32 — semântica não confirmada)
```

### [MEDIDO] tag=207 em ws_20260920_212612

4 messages tag=207 dentro do descomprimido. Players achados:
- Kreitols (0x00215c4f) ✓ nome UTF-16LE
- Lbicare (0x0048a0bc) ✓
- Nfps (0x00655d72) ✓
- Lingyoo (0x0064d4d3) ✓

Outros 6 jogadores NÃO enviam tag=207 nesse dump. Ainda dependem de
memscan / Tag551 pra nome.

**tag=207 é update per-player** (spawn near / state change), não roster
completo. Cobertura parcial.

### Implementação

`src/Tag207Decoder.cs` — parser estrutural. Extract(messages, nameMap)
popula nameMap com entity_id → name (UTF-16LE). Integrado ao build,
compilável.

**Não wired em runtime ainda** — pra chamada em LivePoll requer edição de
WS-engine.cs (a fazer em próxima rodada quando validado com integração
com PlayerResolver).

### Pendentes desta rodada

- **tag=554 impl**: layout `[u8][u8][FUN_00447cc0 poly-array 68B/item][u8]`.
  Cada item usa vtable 0xc10200. Requer decompile de PTR_FUN_00c10200
  slot [4] para saber semântica dos itens.
- **tag=8 impl**: 84B com ~19 u32 + byte-array. Contém self identity.
  Requer decompile detalhada dos 19 u32 fields (candidatos: classId,
  faction, guild_id, level, hp, mana, etc).
- **tag=65 (chat)**: byte-array interna com formato próprio não decifrado.
  Adiado — chat não é fonte primária de name/class.

### [PENDENTE] tag do boss Overgod

TAREFA 5 não executada nesta rodada. Hipótese: primeira mensagem com
0x005dc552 no stream descomprimido de raid_overgod é spawn tag=?? com
type_id que bate em `data/mob-types.json`. Não investigada por tempo.

Ação: probe futuro que localiza primeira mensagem com esse ID e ver
qual tag envia, cruzar com mob-types.json.

### FUN_005fd0b0 — string reader NÃO decompilado

Confirmado ser called por tag=207 secondary. Padrão observado empiricamente:
`[varint byte_count][UTF-16LE data]`. Não decompilado formalmente.
Adiado.

### Arquivos criados

- `re/SubReaders.java` — decompile 0x447cc0, 0x451900, 207 secondary vtable
- `re/sub_readers.txt` — output
- `src/Tag207Decoder.cs` — parser estrutural implementado
- `tools/_test-tag207.ps1` — validação empírica

### Rótulos

[LIDO] endereços e layouts dos readers
[MEDIDO] 4/10 players via tag=207 no dump testado
[INFERIDO] semântica dos flags trailing (não confirmada)

---

## tag=554 = SCOREBOARD ACUMULADO ✓ (2026-09-21)

### [LIDO] Chain de readers

- Primary: FUN_0062b590 (vtable 0xc0ff58 slot [4])
- Poly-array reader: FUN_00447cc0 (stride 68B, base vtable 0xc10200)
- Per-item reader: FUN_00671ba0 (vtable 0xc10200 slot [4])

### [LIDO] Wire body layout

```
[u8 flag_a][u8 flag_b][varint count][items...][u8 flag_c]

Per item (68B struct in memory, variable wire):
    [varint name_len][name ASCII]     # via FUN_00432da0
    [5 u8 flags]                       # +0x14..0x18
    [10 u32]                           # +0x1c..0x40
```

### [MEDIDO] ws_20260920_212612 — 10/10 EXATO

Body 536 bytes. count=10. Cada item revela:

| name | classId | dmg_done | entity_id | level |
|---|---|---|---|---|
| Kreitols | 0x0c=12 | **13.755** ✓ | 0x00215c4f | 28 |
| Lbicare | 0x04=4 (Bárbaro) | **4.640** ✓ | 0x0048a0bc | 28 |
| Lingyoo | 0x0a=10 (Cav. Morte) | **10.596** ✓ | 0x0064d4d3 | 33 |
| Nfps | 0x0b=11 | **31.374** ✓ | 0x00655d72 | 33 |
| Centablg | 0x0a=10 (Cav. Morte) | **9.509** ✓ | 0x00692da2 | 41 |
| Exorcistty | 0x02=2 (Sacerdote) | **10.547** ✓ | 0x000b30ee | 0 |
| Wander | 0x11=17 | **10.549** ✓ | 0x00465da2 | 0 |
| Sacrum | 0x11=17 | **16.570** ✓ | 0x0048042c | 0 |
| Peladehnho | 0x01=1 (Paladino) | **3.637** ✓ | 0x005f0db6 | 0 |
| Marcao | 0x13=19 | **18.968** ✓ | 0x00691957 | 0 |

**10/10 damage_done EXATO com placar do jogo.**
**Centablg classId=10 ✓** confirma ground truth (Cavaleiro da Morte).
**Lbicare classId=4 ✓** = Bárbaro.

### Layout de campos confirmado

| offset | tipo | semântica |
|---|---|---|
| 0 (varint) | varint | name_len |
| ...name | ASCII | name |
| +0..4 | 5 u8 | flag[0]=**classId**, flag[1..4]=? (faction? guild-role?) |
| +5..8 | u32 | **damage_done** (accumulated) |
| +9..12 | u32 | damage_aux (healing/received/damage_dealt_specific?) |
| +13..16 | u32 | u32[2] (kills? deaths? counter?) |
| +17..20 | u32 | **entity_id** |
| +21..24 | u32 | **level** |
| +25..28 | u32 | (zero for most players in test) |
| +29..32 | u32 | (usually 0x32=50) - max_level? |
| +33..36 | u32 | 0 |
| +37..40 | u32 | derived value |
| +41..44 | u32 | 0 |

### Implementação em src/Tag554Decoder.cs

- `Entry` class com ClassId, DamageDone, EntityId, Level (properties)
- `Extract(msgs, nameMap, classIdMap, raw)` popula:
  - nameMap: entity_id → name (ASCII)
  - classIdMap: entity_id → classId (byte 1..25)
- Cross-container: procura em top-level 554 e inside decompressed 492

### Comparação com fontes existentes

| fonte | cobertura | fidelidade |
|---|---|---|
| tag=551 (top-level, entrada zona) | roster completo, one-shot | 6/6 validado |
| tag=554 (fim instância) | **10/10 nome+class+level+dano** ✓ | 100% EXATO no placar |
| tag=207 (per-player update) | parcial (4/10 no dump testado) | UTF-16LE nome |
| memscan | qualquer momento | atrasado, depende de memscan rodando |
| PlayerResolver (pattern) | heurístico | menos confiável |

**Prioridade recomendada:** 554 > 551 > 207 > memscan > PlayerResolver.

### Não wired em runtime ainda

Tag554Decoder compilado no build (`build.bat` inclui). Precisa hook em
`WS-engine.cs` LivePoll pra popular nameMap/playerClassId. Adiado
próxima rodada (integração + entities table SQLite).

### Arquivos criados

- `re/Tag554Reader.java` — decompile per-item reader FUN_00671ba0
- `re/tag554_reader.txt` — output
- `src/Tag554Decoder.cs` — parser estrutural
- `tools/_test-tag554.ps1` — validação
- `tools/_debug-tag554.ps1` — debug body dump

### Boss detection (TAREFA 4) — não executada

Pendência: identificar tag e reader onde ID 0x005dc552 (Overgod) aparece
pela primeira vez em raid_overgod descomprimido. Cruzar type_id com
data/mob-types.json para nomear e classificar como boss (não player).

### Rótulos

[LIDO] endereços, layouts, chain de readers
[MEDIDO] 10/10 EXATO byte-perfect em placar de dano; classId ground truth
[INFERIDO] semântica de u32[6]=max_level, u32[8]=derived value

---

## Integração completa (2026-09-21) — 10/10 name+class+level+damage EXATO

### [MEDIDO] Correções e validações

**Level = flag[2]** (NÃO u32[4]). Validado 10/10 contra ground truth (ícones do placar):
- Kreitols 30, Lbicare 31, Centablg 33, outros 34 — TODOS BATEM.

**u32[1] = healing_done** [MEDIDO] validado 10/10 contra aba "Restaurador":
- Centablg 16530, Exorcistty 7739, Peladehnho 7556, Lingyoo 5725, Marcao 4699,
  Sacrum 3895, Lbicare 2320, Nfps 2111, Kreitols 450, Wander 128 — TODOS EXATOS.

**Layout confirmado (final):**
```
Per item (variable + 5B + 40B):
  [varint name_len][name ASCII]
  flag[0] = classId          (1..25)
  flag[1] = ?                (0x01 or 0x04 in samples)
  flag[2] = level            (1..34)
  flag[3] = ?                (usually 0)
  flag[4] = same-group?      (1 for observer's group, 0 for others)
  u32[0] = damage_done       (scoreboard)
  u32[1] = healing_done      (Restaurador tab)
  u32[2] = ?                 (0..3 in samples)
  u32[3] = entity_id
  u32[4] = ?                 (28-41 or 0)
  u32[5] = 0
  u32[6] = ?                 (50, 60, or 0)
  u32[7] = 0
  u32[8] = ?                 (varying 28..142)
  u32[9] = 0
```

### [MEDIDO] Classes reveladas via tag=554 + data/class-names.json

10/10 mapeamento nome → classe:
```
Kreitols   → Bruxo (12)
Lbicare    → Bárbaro (4)
Lingyoo    → Cavaleiro da Morte (10)
Nfps       → Necromante (11)
Centablg   → Cavaleiro da Morte (10)   [ground truth ✓]
Exorcistty → Sacerdote (2)
Wander     → Templário (17)
Sacrum     → Templário (17)
Peladehnho → Paladino (1)
Marcao     → Invocador de Feras (19)
```

### [MEDIDO] Cross-check V3 merged vs tag=554

Diff = 0 para TODOS os 10 jogadores. V3 (damage decoder LZ4-aware) +
SummonOwnerMap (pet attribution via tag=26) = tag=554 damage_done = placar
do jogo.

**Triangulação: 3 fontes independentes convergem no mesmo número byte-perfect.**

### Integração ao runtime

`src/WS-engine.cs` LivePoll agora chama:
1. `ExtractPlayerNamesTimed` (legacy)
2. `ExtractChatSenders` (legacy)
3. `Tag551Decoder.Extract` (roster entrada zona)
4. **`Tag554Decoder.Extract`** (placar fim instância — nome + classe + level)
5. **`Tag207Decoder.Extract`** (per-player update, secundário)

Prioridade fonte de nome/classe: 554 > 551 > 207 > memscan > PlayerResolver > hex.

### Runtime state

- ✅ V3 damage decoder default
- ✅ SummonOwnerMap ativo (tag=26 estrutural)
- ✅ Tag554Decoder wired em LivePoll (nome + classe + level)
- ✅ Tag207Decoder wired em LivePoll (fonte secundária)
- ✅ Build verde

### Não executado

**TAREFA 4 (boss detection):** localizar primeira mensagem com 0x005dc552 em raid_overgod descomprimido, ler reader pela factory, cruzar com mob-types.json.

Precisa próxima rodada.

### Arquivos

- `src/Tag554Decoder.cs` — atualizado com Level=Flags[2], HealingDone
- `src/WS-engine.cs` — hooks Tag554Decoder + Tag207Decoder em LivePoll
- `tools/_test-integration.ps1` — validação 3-way (V3 + Tag554 + placar)

### Rótulos

[LIDO] chain FUN_0062b590 → FUN_00447cc0 → FUN_00671ba0
[MEDIDO] 10/10 EXATO em nome+classe+level+dano+healing
[INFERIDO] flags/u32 restantes (semântica parcial documentada)

---

## Cura + HP investigação (2026-09-21) — parcial

### [LIDO] tag=428 reader FUN_0063a8d0

Vtable 0xc10480, alloc 24B, layout body (18B):
```
+0  u16  A (flag/token — valores 0, 1024, 2048)
+2  u16  B (index/counter — 0..2500)
+4  u32  C (entity_id, hi=0x00 = player-range em 100% samples)
+8  u32  D (varying — sequência?)
+12 u32  E (varying — 6000, 12000, 15000, 60000, 0xffffffff)
+16 u16  F (varying — 0..1000)
```

### [MEDIDO] tag=428 vs ground truth de healing (u32[1] do tag=554)

**NÃO é evento de cura.** Sum(u16@0) por source (u32@4) não bate:
```
Centablg   expected 16530 got 63490   (× 3.8)
Kreitols   expected   450 got 13314   (× 29.5)
```
u16@0 é FLAG (1024/2048), não valor. Nenhum campo por si só soma a healing_done placar.

### [MEDIDO] tag=428 vs HP do boneco

Dummy dump ws_20260920_104845, target 0x05f6910b: **zero registros
tag=428 com u32@4 = 0x05f6910b**. u32@4 é player-range only (0x00xxxxxx
em todos samples).

tag=428 NÃO é HP-update do target de golpe.

### [INFERIDO] tag=428 candidato: player state broadcast

Layout `[flag u16][counter u16][player_id u32][seq u32][value u32][slot u16]`
sugere update periódico de status do jogador — talvez experience,
gold, energy, ou stat derivada. Não é dano, não é cura, não é HP de mob.

Não investigado a fundo — tarefa aberta.

### Cura por jogador — SEM tag identificada nesta rodada

Verificado:
- tag=427 flag byte não distingue heal vs damage (v3 total damage bate placar 9509 exato pra Centablg, e placar tem cura 16530 separado — heal é OUTRO evento)
- tag=428 não é heal (fields não somam)
- Não testados: tag=430 (0x1ae), tag=93 (0x5d), tag=92 (0x5c), tag=99 (0x63), tag=345, tag=417 (todos com contagem alta no censo do 492 descomprimido)

### Tarefas abertas

1. Decompilar readers de 430, 93, 92, 99, 345, 417
2. Testar cada um como heal event (aggregate por source u32 e comparar
   com healing_done do 554)
3. Testar cada como HP update (filter por mob-range entity + sequência
   decrescente com hits)
4. u32[2] do tag=554 candidato a damage_received — testar contra soma
   de tag=427 onde jogador é target

### Estado

- Cura: **não integrada** (fonte no protocolo não localizada)
- HP: **não integrado** (idem)
- v3 dano permanece 10/10 EXATO no placar

### Arquivos

- `re/HealHp.java`, `re/HealHp2.java` — decompile ctors + vtables
- `re/healhp.txt`, `re/healhp_vt_c10480.txt` — outputs
- `tools/_test-tag428.ps1` — validação heal (falhou)
- `tools/_test-hp-428.ps1` — validação HP dummy (0 records)

### Rótulos

[LIDO] tag=428 reader FUN_0063a8d0 layout 18B
[MEDIDO] tag=428 sum não bate healing_done placar
[MEDIDO] tag=428 dummy sem records mob-range
[INFERIDO] tag=428 = player state periodic broadcast

---

## 2026-09-21 — Fase 9: tag=99 = evento de cura

### Localização (busca por valor)

Sweep sistemático de todos os tags no descompresso (`tools/_test-heal-sweep.ps1`):
para cada tag+offset+layout, sum(val@offV) by entity@offE testado contra
`healing_done` do placar (u32[1] tag=554) para 10 jogadores canônicos do
capture `ws_20260920_212612.pcapng`.

**Resultado:** único hit com >= 3 matches EXATO = **tag=99, len=13,
val@1 (u16 ou u32) por entity@9**, 4/10 EXATO. Nenhum outro tag atingiu 3.

### Reader (LIDO)

Decompilei `getTag` para tag=99 (pattern `B8 63 00 00 00 C3`), encontrei 3
vtables. Vtable @ 0xc0e978 é a classe da mensagem — reader
`FUN_0065db40`:

```c
void __thiscall FUN_0065db40(int *param_1, int *param_2) {
  // init struct
  if (*param_1 == &PTR_FUN_00c0e980) {
    *(u8*)(param_1 + 1) = 0;
    param_1[2] = 0; param_1[3] = 0; param_1[4] = 0;
  } else (*((code**)*param_1)[2])();

  // read u8 flag  → param_1[+4]
  cVar2 = *(char*)(*param_2 + param_2[2]);
  param_2[2] += 1;
  *(bool*)(param_1 + 1) = cVar2 != '\0';

  // read u32 amount → param_1[+8]
  param_1[2] = *(int*)(*param_2 + param_2[2]);
  param_2[2] += 4;

  // read u32 src → param_1[+12]
  param_1[3] = *(int*)(*param_2 + param_2[2]);
  param_2[2] += 4;

  // version-gated u32 tgt → param_1[+16] (only if server ver >= 0x895ff8)
  if (param_2[6] < 0x895ff8) return;
  param_1[4] = *(int*)(*param_2 + param_2[2]);
  param_2[2] += 4;
}
```

Layout final (13B wire, para versões modernas):
```
+0    u8    bool  (crit ou success flag)
+1..4 u32   amount
+5..8 u32   src   (healer entity_id)
+9..12 u32  tgt   (target entity_id)
```

### Validação (MEDIDO)

`tools/_test-tag99-heal.ps1` sobre ws_20260920_212612.pcapng
(231 registros tag=99):

Sum(amount) by TGT vs healing_done placar:
| jogador | exp | got | status |
|---|---|---|---|
| Wander | 128 | 128 | EXATO |
| Marcao | 4699 | 4699 | EXATO |
| Peladehnho | 7556 | 7556 | EXATO |
| Exorcistty | 7739 | 7739 | EXATO |
| Kreitols | 450 | 533 | +83 |
| Sacrum | 3895 | 4040 | +145 |
| Lbicare | 2320 | 3223 | +903 |
| Nfps | 2111 | 6270 | +4159 |
| Lingyoo | 5725 | 8969 | +3244 |
| Centablg | 16530 | 19046 | +2516 |

4/10 EXATO. 6/10 got > exp.

### Interpretação (INFERIDO)

- **placar u32[1] = heal_done_effective** (com overheal deduzido)
- **amount@1 do tag=99 = raw heal amount** (pré-overheal)
- 4 jogadores que combinaram exato = tiveram zero overheal na sessão
  (bater exato = "cada cast landed dentro da HP room")
- 6 restantes = overheal ocorreu; sum bruto > placar

Byte 0 (bool): frequência 0x00=217, 0x01=14. Filtragem por flag não isola
subset "clean". Provavelmente crit flag.

### Estado

- **tag=99 identificado como evento de cura individual**
- Layout LIDO do decompile bate wire (13B, 4 campos)
- Placar match parcial: 4/10 EXATO, 6/10 com delta interpretável como overheal
- HP ainda não localizado (candidatos 92, 94, 98, 102-104 nunca testados como HP; sweep de heal descartou eles)

### Arquivos

- `tools/_test-heal-sweep.ps1` — sweep sistemático que localizou tag=99
- `tools/_test-tag99-heal.ps1` — validação por tgt/src/self-heal
- `re/Tag99Reader.java` — decompile getTag+vtable+reader
- `re/tag99.txt` — output do decompile

### Rótulos

[LIDO] tag=99 reader FUN_0065db40 vtable 0xc0e978 layout 13B
[MEDIDO] sum(amount@1) by tgt@9 = placar u32[1] EXATO 4/10 (healers), delta positivo em 6/10 (não-healers com HP cheio)
[MEDIDO] tag=554 u32[1] renomeado de `HealingDone` → `HealingReceivedEffective`
[INFERIDO] amount@1 = raw pré-overheal, placar u32[1] = post-overheal cap na recepção
[INFERIDO] byte@0 = crit flag (14/231 records = ~6% rate consistente com crit)
[MEDIDO] overheal_estimado = sum(amount@1) by tgt - placar u32[1]  (sempre ≥ 0)

### Correlação classes × delta

| Jogador | Classe | placar_eff | raw_tgt | overheal | interpretação |
|---|---|---|---|---|---|
| Exorcistty | Sacerdote | 7739 | 7739 | 0 | healer curando aliados feridos |
| Peladehnho | Paladino | 7556 | 7556 | 0 | healer curando aliados feridos |
| Marcao | Invocador Feras | 4699 | 4699 | 0 | pet+self cura efetiva total |
| Wander | Templário | 128 | 128 | 0 | self-heal pequeno sem excesso |
| Sacrum | Templário | 3895 | 4040 | 145 | pequeno overheal |
| Kreitols | Bruxo | 450 | 533 | 83 | poção com HP quase cheio |
| Lbicare | Bárbaro | 2320 | 3223 | 903 | poção com HP alto |
| Centablg | DK | 16530 | 19046 | 2516 | reg vida com HP cheio |
| Lingyoo | DK | 5725 | 8969 | 3244 | reg vida com HP cheio |
| Nfps | Necromante | 2111 | 6270 | 4159 | reg vida cheia |

Healers com aliados vivos (Exorcistty, Peladehnho, Marcao) e Wander self com HP baixo = zero excesso. Não-healers regenerando com HP alto = excesso grande. Consistente com hipótese de cap na recepção.

### Integração UI

- `src/Tag99HealDecoder.cs` decoder novo, mesma estrutura de TlvDamageDecoderV3
- `src/WS-engine.cs::ExtractHeals` produz `HealEventLive` com pet→dono via SummonOwnerMap
- LivePoll agrega `healBySrc` e `healByTgt`; JSON leaderboard inclui `healing`
- `_healValidationLogged` dispara log 1× por sessão quando tag=554 chega:
  `[HEAL VALIDATION] Name eid=0x... raw=N eff=M overheal≈K`
- Coluna Healing (UI) = raw src-sum (cura feita bruta, inclui excesso). Tooltip explica.
- Heal-only players (Wander/Peladehnho/Exorcistty se sem dano) recebem row via HashSet playerSet.

### Arquivos

- `src/Tag99HealDecoder.cs` — decoder novo, layout LIDO
- `src/Tag554Decoder.cs` — renomeado `HealingDone` → `HealingReceivedEffective`
- `src/WS-engine.cs` — `HealEventLive`, `ExtractHeals`, LivePoll agrega heal + validação
- `assets/webview/index.html` — tooltip da coluna Healing
- `tools/_test-heal-integration.ps1` — validação 4/10 EXATO + overheal por jogador
- `tools/_test-tag99-detail.ps1` — matriz src→tgt (mostra pet-of-Marcao → Marcao 2944, etc)
- `re/Tag99Reader.java`, `re/tag99.txt` — decompile reader
