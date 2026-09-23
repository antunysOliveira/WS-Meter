# Protocol map — Warspear TLV wire

Fonte: `docs/PROTOCOL-CENSUS.md` + `re/bulk-tag-readers.log` (Ghidra dumps).

## Como usar

- Censo completo por tag em `docs/PROTOCOL-CENSUS.md` (3 tabelas ordenadas por
  volume de bytes: s2c top-level, s2c inner-492, c2s).
- Reader decompilado por tag em `re/bulk-tag-readers.log` — construtor +
  método `vtable[4]` (parse) por endereço.
- Regeneração: `WS-engine.exe --protocol-census pcap1 pcap2 ...` para o censo;
  `re/run-reader.ps1 -Script BulkTagReaders` para o dump.

## Priorização (por volume de bytes)

### S2C inner (dentro de tag=492 descomprimido) — top 20

| tag | count | bytes | body | status | interesse |
|-----|-------|-------|------|--------|-----------|
| 427 | 157k | 2.05 MB | 13 | **DECODED** damage | — |
| 430 | 53k  | 1.06 MB | 20 | reader `FUN_63a780` — layout parecido com 428 mas 20B | possivelmente buff refresh/apply variante |
| 428 | 58k  | 1.06 MB | 18 | **DECODED** buff status | — |
| 19  | 91k  | 825 KB  | 9  | **[LIDO]** `FUN_665c10`: `[u32 field][u8 flag][u32 sub]` — movement/tick? | ver abaixo |
| 595 | 1.3k | 796 KB  | var | reader disponível — BIG bodies | provável dump full de zona/mob template |
| 20  | 56k  | 740 KB  | 13 | reader disponível | tick per-entity |
| 97  | 85k  | 687 KB  | 8  | reader disponível | HP/energy update? |
| 91  | 50k  | 559 KB  | 11 | reader disponível | ? |
| 99  | 39k  | 507 KB  | 13 | **DECODED** heal | — |
| 92  | 26k  | 316 KB  | 12 | reader disponível | ? |
| 26  | 7k   | 291 KB  | 41 | **DECODED** mob/pet spawn | — |
| 94  | 18k  | 205 KB  | 11 | reader disponível | ? |
| 98  | 14k  | 176 KB  | 12 | reader disponível | HP/energy? |
| 597 | 412  | 165 KB  | var | reader disponível — BIG bodies | provavelmente detalhe de zona |
| 21  | 26k  | 160 KB  | 6  | reader disponível | tiny per-entity flag |
| 103 | 13k  | 144 KB  | 11 | reader disponível | ? |
| 55  | 17k  | 138 KB  | 8  | reader disponível | ? |
| 104 | 13k  | 133 KB  | 10 | reader disponível | ? |
| 135 | 18k  | 109 KB  | 6  | reader disponível | tiny per-entity |
| 508 | 8k   | 104 KB  | 12 | reader disponível | ? |

### S2C top-level — top 10

| tag | count | bytes | body | status |
|-----|-------|-------|------|--------|
| 492 | 31k | 10.5 MB | var | container LZ4 — **DECODED** |
| 19  | 31k | 282 KB  | 9   | mesmo reader do inner |
| 20  | 2.7k| 36 KB   | 13  | idem |
| 65  | 772 | 35 KB   | 12..97 | **DECODED** chat |
| 97  | 4.2k| 34 KB   | 8   | idem |
| 98  | 2k  | 24 KB   | 12  | idem |
| 5   | 5.8k| 23 KB   | 4   | small periodic |
| 561 | 61  | 13 KB   | 30..306 | reader disponível — BIG |
| 4   | 3k  | 12 KB   | 4   | small |
| 21  | 1.9k| 12 KB   | 6   | idem |

### C2S — top 8

| tag | count | bytes | body | status |
|-----|-------|-------|------|--------|
| 248 | 435 | 411 KB  | 944 | **[LIDO reader disponível]** BIG upload periódico |
| 5   | 735 | 26 KB   | 13..241 | skill-cast batch (stride 12) |
| 3   | 5.8k| 23 KB   | 4   | heartbeat |
| 2   | 5k  | 20 KB   | 4   | frequent state |
| 12  | 556 | 9 KB    | 17  | reader disponível |
| 280 | 1.3k| 5 KB    | 4   | tiny periodic |
| 216 | 1.3k| 5 KB    | 4   | tiny periodic |
| 8   | 691 | 5 KB    | 7   | position sync |

## Notas [LIDO] por tag

### tag=19 — parse @ `FUN_665c10` (body 9B)

```c
sub_object_a.init();                    // 0B read (via param_1[5])
sub_object_b.read(buf);                 // calls param_1[1][0x10] — likely 0B
param_1[3] = read_u32(buf);              // 4B  → entity_id?
param_1[4] = read_u8(buf);               // 1B  → flag/type
sub_object.read(buf);                    // 4B via param_1[5][0x10]
```

Body 9B total = 4 + 1 + 4 = 9B. Sub-objects at start/end may
delegate the actual byte reads. Empirically each tag=19 body carries
one player/mob id near byte offset 2..5. Semantic uncertain
(damage-related tick given co-firing with tag=427 in 492).

### tag=20 — parse @ `FUN_6659d0` (body 13B)

```c
sub_object_a.init();                    // 0B
sub_object_b.read(buf);                  // 4B via param_1[1][0x10]
param_1[3] = read_u32(buf);              // 4B
param_1[4] = read_u32(buf);              // 4B
param_1[5] = read_u8(buf);               // 1B
sub_object.read(buf);                    // 0B via param_1[6][0x10] (tail)
```

Body 13B = 4 + 4 + 4 + 1 = 13B ✓. **Same shape as tag=427 damage
(13B `[dmg u32][att u32][tgt u32][flag u8]`)**. tag=20 is likely a
damage variant — maybe healing-received / mitigation display /
crit-flag.

### tag=97 — parse via scalar_deleting_destructor (body 8B)

Ctor uses vtable `PTR__scalar_deleting_destructor__00c0e0fc` which
doesn't fit the standard vtable[4] pattern used by other readers.
Parser sits elsewhere; not resolvable via the current bulk script.

Empirical layout of the 8-byte body (from
captures/ws_20260922_185624.dump-tag97.txt earlier):
```
[u32 value][u32 entity_id]
```
Examples:
- `04 f2 01 00 99 0c 6b 00` → value=0x0001F204=127492, id=0x006B0C99
- `e3 69 0e 00 a1 f1 6b 00` → value=0x000E69E3=944611, id=0x006BF1A1

Values in the 100K–1M range — very likely **HP** (Warspear player
HP peaks ~10k+, boss HP into 100M). Confirms tag=97 = HP update per
entity, but semantics uncertain (current HP? damage-taken delta?
value range doesn't rule either).

### tag=98 — parse @ `FUN_65dd40` (body 12B) [LIDO]

```c
param_1[1] = read_u32(buf);              // 4B
param_1[2] = read_u32(buf);              // 4B
param_1[3] = read_u32(buf);              // 4B
```

Body 12B = 4+4+4 ✓. Three u32 fields. Empirical (from prior dumps):
```
14 00 00 00 5f 76 18 00 00 00 00 00  → f1=20  id=0x0018765F  f3=0
32 00 00 00 42 2f 5c 00 00 00 00 00  → f1=50  id=0x005C2F42  f3=0
00 00 00 00 5f 76 18 00 a4 00 00 00  → f1=0   id=0x0018765F  f3=164
```

Fields: `[u32 quantidade][u32 entity_id][u32 flags/valor]`. Field1
range 0..~200 e field3 range 0..~200 → não é level (max 34) nem HP
crudo. Provável **regen/dmg-taken tick** ou **status effect
counter**. Sem correlação ground-truth, semântica exata inconclusiva.

### tag=595 — parse @ `FUN_626d10` (body 146..710B, variável)

```c
param_1[1] = read_u32(buf);              // 4B  (some header/id)
FUN_00448450(param_1 + 2);               // collection read (loop)
```

FUN_00448450 é reader de coleção genérico. Body começa com u32
seguido de array. Amostra (569B, msg#9 raid_overgod):
```
eb 00 00 00                              header u32 = 235
04 0a 01 00 00 00                        block prefix (04=type, 0a=count=10, 01=flag)
01 cd cc 4c 3e 00 00 00 00 00           record 1: [01=idx][float 0.2][pad]
02 00 00 00 01 cd cc 4c 3e 00 00 00 00 00 record 2: [02][01 flag][float 0.2][pad]
03 00 00 00 02 00 00 c0 41 00 00 00 00 00 record 3: [03][02][float 24.0][pad]
... (up to 0a=10, repeats for next block)
```

Records são `[u8 idx 1..10][u8 type][float value 4B][pad ~4-6B]`.
Blocos de 10 records. 4 blocos × 10 records = 40 entries por body.

Valores em float pequeno (0.2, 0.3, 0.7, 10.0, 24.0). Formato de
**stat tables** — provavelmente cooldowns/timers de skill ou
resistances por elemento. **NÃO é lista de players com nome+classe**
como esperado. Ruled out para o objetivo classe.

### tag=597 — parse @ `FUN_6269d0` (body 10..714B, variável)

```c
param_1[1] = read_u32(buf);              // 4B
param_1[2] = read_u32(buf);              // 4B
FUN_004485e0(param_1 + 3);               // collection read
```

Similar ao 595 mas com 2 u32 header em vez de 1. Provavelmente stat
table variante.

### tag=207 — parse @ `FUN_67f5d0` (já em Tag207Decoder.cs)

### tag=207 — parse @ `FUN_67f5d0` (já em Tag207Decoder.cs)

```c
[u32 entity_id → struct+0x04]
[UTF-16 name via FUN_005fd0b0]
[u8 level → struct+0x3c]
[u8 CLASS  → struct+0x3d]   ← fonte confirmada
[u32       → struct+0x40]
[u8 flags  → struct+0x44]
[u16       → struct+0x46]
[u8 (ver-guarded) → struct+0x48]
```

Validado 4/4 vs tag=554 no `--validate-class`.

### tag=388 — parse @ `FUN_0063e0d0` (equipment)

```c
[u32 entity_id → struct+0x04]
[u8 flag → struct+0x08]
[varint count]
loop count× sub_reader(record 0x30 bytes) — item slot data
```

Sub-records = itens equipados. Sem classe. **Ruled out.**

### tag=11 — dead code em `src/Tag11PlayerDetailDecoder.cs`

Byte @18 fica em faixa 1..20 por coincidência mas **6/6 mismatch com tag=554**.
Não usar. Kept para referência de layout 47B.

### tag=25 — roster / delta

`[count u8][count × u32 LE entity_id]`. count≥30 = full roster (CLEAR+INSERT).
Menor = delta ADD. **Decoded em `EntityState.cs`.** LEAVE não isolada.

### tag=26 — mob/pet spawn [LIDO]

+2 = summon_id (mob range 0x05xxxxxx), +35 = owner (player range).
+22/+24 = level? (semântica incerta). SummonOwnerMap valida 120 pares.

### tag=427 — damage [LIDO]

Body 13B: `[dmg u32][att u32][tgt u32][flag u8]`. TlvDamageDecoderV3.

### tag=99 — heal [LIDO]

Body 13B: `[crit u8][amount u32][src u32][tgt u32]`. Tag99HealDecoder.

### tag=429 — consumable buff apply [LIDO — 3/3 test items]

Body 20B: `[op=0x00040000][target u32][infl u32][dur ms u32][pad u16][item_id u16]`.

### tag=554 — end-of-instance scoreboard [LIDO]

`[name_len u8][name ASCII][class u8][level u8][...more fields per player]`
Repete N vezes. Fonte AUTORITATIVA de classe (100% acerto no overlap).

### tag=551 — instance roster + class [DECODED]

Similar ao 554 mas roster de entrada. Mesma qualidade.

## Não decodificados / candidatos importantes

### tag=595 (bodies 146..710B, 1.3k msgs)  ← **investigado — não é player list**

Reader lido acima ([LIDO]). Body = `[u32 header][coleção de blocos de 10
records de floats]`. Valores 0.2/0.3/0.7/10.0/24.0. Provável tabela de
timers/cooldowns/resistances por entidade. **NÃO carrega nome nem class.**
Ruled out.

### tag=597 (bodies 10..714B, 412 msgs)

Similar ao 595 mas variável desde 10B. Provável info específica sob demanda.

### tag=561 (bodies 22..322B, 362 msgs)

Variável, no inner 492. Layout desconhecido — reader disponível.

### tag=205 (bodies ~3.3KB, 8 msgs)

BIG. Raro. Provável snapshot esporádico (login/zone-load).

### tag=248 c2s (body=944, 435 msgs)

Upload frequente do cliente. Content unknown — reader disponível.

## Onde a classe VEM (recap)

| Fonte | Cobertura | Confiança |
|-------|-----------|-----------|
| tag=554 | Instance scoreboard (roster de instância no fim) | 100% |
| tag=551 | Instance roster (start) | 100% |
| tag=207 | Per-player update (raro, dispara em state change) | 4/4 validado |
| memscan | Nearby players (render range) | Cross-checked |
| PlayerResolver | On-demand memory lookup | Cross-checked |

**Fora de instância, na cidade / world-open, sem state change ativo**: única
fonte é memscan/PlayerResolver, que só acha players com struct em memória
(nearby-rendered). Painel "Local" do jogo mostra ~50 nomes com classe, o
que sugere que o cliente TEM classe de todos — mas o wire tag que carrega
essa informação ainda não foi isolado. **Candidates ruled-out**:

| tag | body | fields | não é class porque |
|-----|------|--------|-------------------|
| 11  | 47B  | equipment amp bytes | 6/6 mismatch vs tag=554 |
| 20  | 13B  | dmg-like `[u32][u32][u32][u8]` | shape de damage variant |
| 97  | 8B   | `[value][entity_id]` | value=HP grande |
| 98  | 12B  | `[qty][entity_id][flags]` | qty 0..200 |
| 201 | 5B/big | guild profile request/response | não tem classId |
| 388 | var  | equipment slots | zero campo de classe |
| 555 | 133B | 10 IDs stride 8 | party roster (só IDs) |
| 595 | var  | float stat table | timers/cooldowns |
| 597 | var  | float stat table variant | idem |

**Correção 2026-09-22 — tag=10 achado e validado**

Análise dos 14 readers ainda não interpretados revelou **tag=10 como a
fonte class open-world**. Body 12B:
```
[u32 entity_id @0][u8 CLASS @4][u8 weapon?][u8 flag=01][u8 flag][u16][u16]
```

Validação empírica cruzada com tag=554 de ws_20260920_212612 (7 players
com class conhecida):
```
Lbicare(4)     bc a0 48 00  04  02 01 01 48 00 0d 00  → class@4=4  ✓
Nfps(11)       72 5d 65 00  0b  04 01 00 a6 00 19 00  → class@4=11 ✓
Kreitols(12)   4f 5c 21 00  0c  04 01 01 82 00 03 00  → class@4=12 ✓
Exorcistty(2)  ee 30 0b 00  02  01 01 00 66 01 04 00  → class@4=2  ✓
Wander(17)     a2 5d 46 00  11  01 01 01 36 00 22 00  → class@4=17 ✓
Sacrum(17)     2c 04 48 00  11  01 01 01 0d 00 11 00  → class@4=17 ✓
Peladehnho(1)  b6 0d 5f 00  01  01 01 01 79 00 12 00  → class@4=1  ✓
```
**7/7 hit, 0 miss.** Centablg/Lingyoo/Marcao ausentes do tag=10 nessa
janela (Centablg = observer, servidor não envia dados do próprio player).

Cobertura em raid_overgod: **147 unique tag=10 IDs** (vs 22 via memscan).

Decoder integrado em `src/Tag10PlayerClassDecoder.cs`. Wired em LivePoll
com overwrite sobre memscan/resolver.

O painel "Local" do jogo lê o cache local. Não precisa nova rede
request. Isso explica também por que capturar "abrindo painel Local"
não produz nova mensagem — o dado já foi recebido em outra ocasião
(spawn, chat, scoreboard) OU derivado do modelo visual do char.

Próxima janela de investigação (fora de escopo desta rodada):
- readers ainda sem [LIDO] campo-a-campo: 561
- big variable bodies: 561 (30..306B) pode carregar player list em raro cenário
- c2s 248 (944B upload constante) — se cliente ENVIA state grande periodicamente pro server, servidor pode espelhar por wire em resposta

## Notas [LIDO] — rodada 14 readers pendentes (2026-09-22)

### tag=13 — LEAVE / DESPAWN [MEDIDO]

Body 4B: `[u32 entity_id]`. Fires quando entidade sai da área visível.
Validação cruzada vs rosters em raid_guild_20260919_094131:
- janela 1290..1586s: ratio LEFT/STAYED = **5.76x**
- janela 1590..1836s: ratio LEFT/STAYED = **6.60x**

IDs mix player-range (0x00) e mob/pet range (0x05). Simétrico ao
tag=25 single-id ENTER. Decoder wired em `EntityState.cs`. Contagem
área caiu 120→65 players (alvo user 55-60). Fecha o gap do LEAVE.

### tag=91 [LIDO]

Body 11B `[u16=0][u32 player_id 0x00][u32 mob_id 0x05][u8 flag 0x01|0x02]`.
50k msgs. Pair-link jogador↔mob com toggle flag. Provável **combat
engage / aggro state**. NÃO carrega class nem é LEAVE.

### tag=92 [LIDO]

Body 12B `[u32][u32][u32]`. 26k msgs. 3 u32 puros sem discriminator.
Não amostrado ainda para semântica exata. Provável tick per-entity.

### tag=93 [LIDO]

Body 12B `[u32][u32][u32]`. 6.5k msgs. Mesmo shape do tag=92.

### tag=94 [LIDO]

Body 11B `[u16=3][u32 mob_id][u32 mob_id][u8=0]`. 18k msgs. Mob-to-mob
link (aggro entre mobs?). u16=3 constante. NÃO carrega class.

### tag=103 [LIDO]

Body 11B `[u16][u32][u32][u8]` — mesmo shape do 91/94. Com version gate
0x98a623 no reader (u8 final opcional). 13k msgs. Attribute/state
variant. NÃO carrega class.

### tag=104 [LIDO]

Body 10B `[u16][u32][u32]`. Versão sem u8 do tag=103. 13k msgs.

### tag=105 [LIDO]

Body 8B `[u32 mob_id][u32 mob_id]`. Sempre dois IDs mob-range 0x05.
6.2k msgs. Sample:
```
39 87 f6 05  a3 79 f6 05
fd 11 f7 05  a3 79 f6 05
```
Segundo u32 estável (a3 79 f6 05) enquanto primeiro varia — **pet/mob
followers** or **target-lock** apontando para mesma raid. Ctor-only
(scalar_deleting_destructor), parse method não isolável via bulk.

### tag=106 [LIDO]

Body 6B `[u16][u32]`. 7.3k msgs. u16 counter + entity_id (mix
player+mob). Ctor-only.

### tag=134 [LIDO]

Body 6B `[u16 counter][u32 entity_id]`. 11k msgs. Mix player+mob.
Samples repetem u16=0xab pareado com mesmo entity — tick per-entity.
Ctor-only.

### tag=135 [LIDO]

Body 6B mesmo shape 134 `[u16][u32]`. 18k msgs. Samples repetem
u16=0x1c/0x1b para mesmo player. Provável **animation/state tick**.
Ctor-only.

### tag=138 [LIDO]

Body 8B. Reader lê apenas 2× u8 (parent parser lê os 6B iniciais).
Sample: `[u16 field=0x0246][u32=0][u8][u8]`. u16 constante, u32=0.
Só 2 bytes dinâmicos. Provável **UI/window state**. 4.6k msgs.

### tag=139 [LIDO]

Body 8B. **Mesmo parser que tag=138** (FUN_00601320 compartilhado —
twin tags). Sample: `[u16=0x30 ou 0x2f][u32 mob ou 0][u8][u8]`.
Contexto diferente do 138 mas layout idêntico. 8.2k msgs.

### tag=345 [LIDO]

Body 16B variável com version gates:
```
[u16][u16][u16][u16]  = 8B header base
[u16][u16]            = 4B extra (ver<0x989e50)
[u32]                 = 4B extra (ver>0x7a21a0)
[u16]                 = 2B extra (ver>0x895ff7)
[u16]                 = 2B tail (ver>=0x989e50)
```
Multi-field com gates de versão de protocolo. Semântica não isolada
mas complexo — provável spell/skill update com params variáveis.
2.7k msgs.

### tag=383 [LIDO]

Body 8B `[u32 entity_id][u32 speed_or_flag]`. 7.3k msgs.
- Para mob-range (0x05): 2º u32 = 0 sempre.
- Para player-range (0x00): 2º u32 = float pequeno (0.14, 0.26, 0.47).

Provável **movement speed update** — mobs static (0), players ganham
multiplicador quando muda. Ctor-only.

### tag=430 [LIDO]

Body 20B = **tag=428 layout + u16 extra**. Reader delega FUN_63a8d0
(o parser do tag=428) então lê +2B. Layout:
```
[u16 flag=0x0400][u16 attr_type][u32 entity_id][u32 v1][u32 v2][u16 tail][u16 extra]
```
Sample: flag sempre 0x0400, attr_type varia (0x010d, 0x04c3, 0x0060,
0x0018), entity mix player+mob, v1/v2 attribute values, extra u16
causality/source hint. 53k msgs. **NÃO é LEAVE** (multi-field attr).

### tag=508 [LIDO]

Body 12B `[u32 entity_id][u32 counter][u32 value]`. 8.6k msgs. Sample:
```
c6 46 f6 05  27 00 00 00  b3 1b 00 00   → entity=0x05f646c6 ctr=39 val=7091
c6 46 f6 05  29 00 00 00  cb 1c 00 00   → entity=same       ctr=41 val=7371  (val +280)
c6 46 f6 05  2b 00 00 00  b3 1b 00 00   → entity=same       ctr=43 val=7091  (val back)
```
counter monotônico, value flutua. Provável **HP tick per-mob** ou
resource per-entity update.

## Consolidação LEAVE

**Único LEAVE do protocolo:** tag=13, body 4B, u32 entity_id.
Nenhum dos 14 readers analisados (nem os menores 4-6B) carrega
`[u32 entity_id_puro]` isoladamente. tag=13 permanece sole source.

## Rodada 2 — tags do censo por volume (2026-09-22)

### tag=4 [MEDIDO]

4B top-level `[u32 counter]`. 3117 hits. Valores incrementais
0x03b9ac42 → 0x03b9b088 → 0x03b9b4dd. **Timestamp/sequence
heartbeat** server→client.

### tag=5 [MEDIDO]

Top-level multi-shape:
- 4B `[u32=0]` puro — heartbeat/keepalive
- 13B `[u32 mob_id][u32=0][u32=0][u8]` — mob-related tick

Discriminator = body length. Total 5824 hits.

### tag=19 [MEDIDO — refinado]

Body 9B `[u32 packed][u32 entity_with_prefix][u8]`. 91k msgs. Segundo
u32 tem mob-range 0x05f6 embutido no meio — **movement / position
update per-entity com coords packed**. Reader antigo estimava
`[u32][u8][u32]`, real é mais complexo (coords compactadas).

### tag=20 [MEDIDO — refinado]

Body 13B `[u32 packed][u32 entity][u32 vec][u8]` — mesmo shape que
tag=427 damage mas semanticamente é **movement tick com speed
vector** (co-fires com tag=19 no mesmo timestamp para mesmos IDs).
Não é damage variant como suposto antes. 56k msgs.

### tag=21 [MEDIDO]

Body 6B `[u32 mob_id][u16]`. 26k msgs. Mob-only per-entity tick.
Provável **animation/state per-mob**.

### tag=34 [MEDIDO]

Body 11B `[u32 entity][u32 flag][u8]`. Mesmo player 0x0049cb57
repetido com flags variando (0x0007, 0x0006, 0x0000). **Skill
state / animation phase** per-player.

### tag=49 [MEDIDO]

Body 15B `[u32=0xb0936464][u32=0x00020044][u32=0x0f806f69][u8][u16]`.
Todos os campos CONSTANTES entre samples. **Config/version broadcast**
periódico. 112 msgs, low volume.

### tag=55 [MEDIDO]

Body 8B `[u32 entity_id][float multiplier]`. Float valores
0x3f800000=1.0, 0x3f866666=1.05. Player+mob mix. **Scale/speed
rate multiplier** update. 867 top-level + 17k inner = 17.8k total.

### tag=64 [MEDIDO]

Body 12..66B (variável). Sample 18B: first u32 = observer's own ID
(0x00692da2 Centablg) sempre, restante constante. **Self-state
broadcast** — apenas para o próprio player. 109 msgs.

### tag=92 [MEDIDO]

Body 12B `[i32 signed_delta][u32 entity_id][u32 value_or_0]`.
Sample: `[-20][0x006386d2][0]`, `[-28][0x0049cb57][0]`, `[0][player][38]`.
Signed first field sugere **HP/stat delta** — negativo=perda,
positivo=ganho, 0=snapshot. 26k msgs.

### tag=93 [MEDIDO]

Body 12B `[u32=0][u32 entity_id][u32 counter]`. Same player repeated,
counter monotônico (0xde→0xde→0xdf). **Attribute counter tick**
per-entity. 6.5k msgs.

### tag=102 [MEDIDO]

Body 7B `[u16][u32 entity_id][u8]`. Mesmo shape do tag=135 mas 1B
extra. 8.8k msgs.

### tag=206 [MEDIDO] ← **DESCOBERTA**

Body variável 16-32B com **strings UTF-16 embutidas**. Samples
decodificados:
```
28B: [0x10ad][utf16 "Lbicare"][02 00 07 00]
20B: [0x0199][utf16 "KRIKA"][02 00 08 00]
24B: [0x01ea][utf16 "MULMABSO"][01 00 0b 00]
```
Primeiro u16 = short-ID/handle (não é entity_id de 4B). Nome UTF-16
variável. Tail `[u16 kind][u16]`.

Tanto players (Lbicare) quanto guildas (KRIKA, MULMABSO) aparecem.
**Party/friend/guild memberlist broadcast?** — semântica exata
merece follow-up com ground truth. 28 msgs.

### tag=270 [MEDIDO]

Body 9B `[u32][u32][u8]`. Valores pequenos `[0x385][0x834]`,
`[0x496][0x708]`, `[0x7f5][0x5dc]` — não são entity_ids (mask=0x00).
Provável **coord pair** (x,y) para movimento server-broadcast.
35 msgs.

### tag=493 [MEDIDO]

Body 8B `[u32 entity_id][u32 counter 0..2]`. Mesmo mob
`0x0063b346` repetido, counter cicla 0→1→2. **State machine tick**
per-entity. 129 msgs.

### tag=511 [MEDIDO]

Body 8B `[u32 entity_id][u32=3 always]`. Mix player+mob. Segundo
sempre 3. **Flag setter** — provável "entity became targetable"
ou "phase 3 entered". 58 msgs.

### tag=549 [MEDIDO]

Body variável 6-16B — múltiplas formas. Small ints (0..8) sem
entity_id. **UI notification / event config** transmitido em várias
formas. 163 msgs.

## Rodada 3 — big bodies + c2s (2026-09-22)

### tag=205 [MEDIDO — friend/roster list]

Body ~3.3KB. 8 msgs no censo (rare, zone-load only). Contém 50+
records serializados:
```
[u32 entity_id][u8 name_len_bytes][utf16 name][u8=0x22 sep]
[u8][u32=42 level?][u16=0x06][u16 flag][u32 secondary_id]
```
Nomes vistos: Akkk, Anemos, Antty, Bibobi, Celesta, Dkk, Guagua,
Honggee, Huopao, Kixin, Liangzzi, Lingyoo, Lskylinel, Mantou,
Mobyuno, Molan, Moyu, Novodk, Omno, Sherry, Sherrygin, Susubeast,
Swordnew, Swqs, Vol, Wdmushroom, Wsp, Wutian, Xama, ...

Layout exato de cada record precisa reader Ghidra pra confirmar
alinhamento — sample tem prefix byte antes do entity_id que sugere
5B ID ou tag/discriminator. **Provável friend list snapshot** ou
guild roster completo. Fonte potencial de nomes offline.

### tag=248 c2s [MEDIDO — hotkey bar XML]

Body 944B fixo. **Cliente uploads XML config** pro server:
```xml
<Player id="6892962">
  <Hotkey type="0" id="50" />
  <Hotkey type="0" id="48" />
  <Hotkey type="0" id="380" />
  ...
</Player>
```
Envelope: `[u32 account_id][varint len][xml utf8]`. Sync
hotkey/UI persistence. 435 msgs no censo, upload constante.
Não útil pra decode s2c.

### tag=561 [MEDIDO — party/group roster]

Body variável 26-46B, 62 msgs. Party membership broadcast:
```
[u32=0x1e]              // header const (protocol version?)
[u32=0x0a=10]           // max party size
[u8=0x01][u32 leader_id]// fixed leader slot
[u8 count]              // current member count
[count × u32 member_id] // party member ids (grows/shrinks)
[u16 state]             // 0x0256, 0x0257, 0x0258 varying
[u32=0][u16=0]          // pad
```

Sample: leader `0x0006de6d`, party gradually grows 1→2→6 members
(`0x003d3648, 0x001fcb2a, 0x006cbc41, 0x006bbe73, 0x005b2bf1`).

**Fonte AUTORITATIVA de party membership**. Poderia colorir
leaderboard por party mate. Não integrado ainda.

### tag=206 [MEDIDO — ranking/ladder board]

Body variável 16-32B. Já sampleado na rodada 2. Confirmed layout:
```
[u32 short_id 2B effective][u8 name_len_bytes][utf16 name]
[u16 level_or_score][u8 type=01|02]
```

Mistura de players (Lbicare, TheRocks, EmpeRor, Tomorrowld) e
guildas (KRIKA, MULMABSO, PAIN, BANANEIROS, PLAYERS). type
discrimina os dois. Fires em batch (t=310s = 11 msgs simultâneas)
= abertura de painel top-ranking. Short-ID de 2B ≠ entity_id 4B →
NÃO cross-referenciável direto com nomes de damage/spawn.

## Regeneração

```
# Censo
WS-engine.exe --protocol-census captures/*.pcapng captures/_important/*.pcapng

# Reader Ghidra bulk
powershell -File re/run-reader.ps1 -Script BulkTagReaders

# Validação por jogador
WS-engine.exe --validate-class <pcap>            # tag=11 / tag=207 vs tag=554
WS-engine.exe --find-class-near-name <pcap> "Nome:class,..."
```

Não integrar decoder novo sem 100% overlap com ground truth.
