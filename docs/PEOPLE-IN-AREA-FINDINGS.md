# People-in-area — achados empíricos (probe em captura de cidade)

Captura analisada: `captures/ws_20260921_183825.pcapng` — Centablg
saindo de área com poucas pessoas para área com 30-50 jogadores.

Ferramenta: `WS-engine.exe --probe-ids <pcap> [ids|--discover]` +
`--dump-tag <pcap> <tag>` (código em `src/ProbeIds.cs`).

## Metodologia

1. **Discover mode** enumerou todos u32 LE em range `[0x00010000..0x00FFFFFF]`
   dentro de bodies TLV top-level e dentro do conteúdo descomprimido de
   `tag=492`. Top 40 IDs por contagem.
2. **Probe-ids** com 15 IDs "prováveis jogadores" (top do discover) →
   agrupa por tag da primeira/última ocorrência.
3. **Dump-tag** para inspecionar layout dos bodies das tags dominantes.

## Resultado cross-ID sobre 15 IDs

```
FIRST-hit tag frequency (spawn candidates):
  tag=25 → 7 ids   ← ROSTER inicial (bulk snapshot)
  tag=26 → 5 ids   ← per-entity state tick
  tag=139 → 1
  tag=92 → 1
  tag=428 → 1

LAST-hit tag frequency (despawn candidates):
  tag=98 → 3 ids
  tag=65 → 3 ids   (chat message → não é despawn, é última fala)
  tag=97 → 3 ids
  tag=139 → 2 ids
```

## tag=25 — revisão [MEDIDO 2026-09-21b]

Amostragem ampliada em 4 capturas revelou fórmula única:

```
body = [count u8][count × u32 LE entity_id]
body_length = 1 + count * 4
```

Tabela de tamanhos observados (todos batem):

| count | body | notas |
|-------|------|-------|
| 1  | 5B  | ENTER isolado |
| 2  | 9B  | par (ver abaixo) |
| 3  | 13B | trio |
| 4  | 17B | 4 IDs |
| 6  | 25B | 6 IDs — não ordenados |
| 10 | 41B | 10 IDs — ordenados |
| 16 | 65B | 16 IDs — ordenados |
| 61 | 245B | roster raid |
| 65 | 261B | roster cidade |
| 66 | 265B | roster raid |
| 69 | 277B | roster raid |

Grandes (≥30 IDs) sempre ordenados ascendente → roster snapshot.

### LEAVE ainda NÃO confirmado

Hipótese anterior "op=0x02 body=9B = LEAVE" veio de 1 sample e é falsa:
em `raid_overgod` várias mensagens body=9B pareiam o próprio ID do
observador (0x005dc552 = Overgod) com um segundo ID — remover o
observador em toda batida é obviamente errado.

O que EU faço agora [MEDIDO conservador]:
- **Toda** mensagem tag=25 adiciona seus IDs à área.
- Batches `count >= 30` (bodies grandes ordenados) fazem CLEAR antes.
- Nenhuma mensagem tag=25 remove IDs. LEAVE precisa ser identificada
  em captura contínua ~10min de cidade com 20+ eventos de gente saindo
  do campo de visão, ainda pendente.

Consequência: contagem tende a crescer entre zonas — resolve quando o
próximo roster chega. Melhor que remover errado (poluiria a UI com
sumiços fantasmas).

### Composição da área — pipeline de classificação

Pipeline atual em `MainForm.ClassifyAreaEntity` + a versão offline no
`--area-count`. Prioridade do mais confiável ao menos:

1. **INVOCAÇÃO** — `SummonOwnerMap.Build()` contém o ID.
   [MEDIDO] via placar do SummonOwnerMap (120 pares pet→dono ok).
2. **JOGADOR** — Aparece em pelo menos uma fonte forte:
   `nameMap` (tag=551/554/207 + chat), `autoNameCache` (memscan),
   `playerClassId` (memscan / tag=551/554/207).
3. **MOB** — Heurística de faixa de ID: `high_byte in {0x03, 0x04,
   0x05, 0x07, 0x09, 0x0C, 0x10, 0x57}` conforme CLAUDE.md.
4. **JOGADOR** (fallback) — ID `0x00xxxxxx` >= 0x00010000 sem outra
   informação: assumido player não-identificado.
5. **OUTRO** — todo o resto (IDs muito pequenos, high bytes exóticos).

Contagem [MEDIDO] com `--area-count`:

- `ws_20260921_183825` (cidade): total 88, players 65, pets 18, mobs 4, outros 1.
- `raid_overgod_20260919_161016` (raid): total 568, players 99, pets 134, mobs 335.

Números fazem sentido pra raid. Cidade ainda mostra 65 players (acima
dos 30-50 relatados) porque LEAVE ainda não decodificado — ver acima.

### Sliding window [INFERIDO — provisório enquanto LEAVE não é decoded]

Toda entidade guarda `LastSeen` atualizado por qualquer tag que a
mencione:
- tag=25 (roster/ENTER): inserção com timestamp
- tag=26 +2: pet spawn/tick
- tag=427 +4/+8: dano atacante/alvo
- tag=99 +5/+9: cura src/tgt
- tag=429 +4: buff target

Filtro por kind:
- player: 60s (parado emite pouco)
- mob/pet: 20s (tick constante enquanto vivo)
- entidade fora da janela → não conta (não é REMOVE definitiva — só
  não aparece no snapshot atual até uma nova mensagem revalidá-la)

Roster completo (tag=25 count≥30) segue fazendo CLEAR + INSERT — se
o servidor reenviar rotina, ele sozinho já re-normaliza.

Card "total*" na UI tem tooltip explicando aproximação.

Números pós-window:
- ws_20260921_183825 (city): 88 seen → 73 live (65 players / 8 pets / 0 mobs / 15 stale)
- ws_20260921_201409 (city late test): 21 seen → 17 live (7 players / 1 pet / 9 mobs / 4 stale)
- raid_overgod (raid): 568 seen → 52 live (16 players / 24 pets / 12 mobs / 516 stale)

## Guilda [BUSCA continua] — proximity DESATIVADA

Ground truth do usuário mostra que a associação por proximidade em
memória produz guildas ERRADAS:
- Mudin → deveria ser Kingdon/Kingdom
- Centablg → YOLO
- Brokeblade → Fallens
- Kaliffado → Nalu

**DESATIVADO em `src/MemScan.cs`:** o scan que procurava um struct
`<GUILDNAME>` nos ±512-1024 bytes ao redor do struct do jogador está
guardado atrás de `if (false)`. `ws-engine.mem-player-guilds.json`
zerado. UI mostra "Sem guilda / desconhecida" pra todos até termos
uma fonte confiável.

**Busca no protocolo (parcial):**

Rodei `--search-string` em 8 capturas com os nomes das guildas em
ASCII, UTF-16LE, UTF-16BE. Zero hits em toda captura de cidade —
inclusive na `ws_20260921_201409` que tem os 4 pares acima.

Único hit real veio de `raid_overgod`: tag=201 body 137B, `t=+510s`,
carrega estrutura de guild broadcast:
```
[0..3]  u32 guild_id = 0x2a
[4]     u8 name_len_bytes = 8
[5..12] UTF-16LE "YOLO"
[13..]  outros campos (líder "Lanbo", stats)
```

tag=201 também tem variante body=5B `[01][id u32]` — chat sender ou
similar. tag=201 body ≥ 100B parece broadcast de perfil de guilda
sob demanda (ex.: quando um jogador da guilda YOLO age, ou algum
cliente pediu detalhes).

**Não há player→guild inline nas capturas normais.** Cliente
provavelmente pede via c2s quando exibe overhead-name/profile, e
mantém cache local que a gente não intercepta.

**Próximo passo:** capturar uma sessão onde o usuário CLICA em Mudin,
Centablg, etc. — deve gerar request c2s e response s2c com o
guild_id e/ou nome da guilda. Rodar `--search-string` na nova
captura pelos nomes das guildas.

Se não bater no protocolo, alternativa: reescrever o memscan pra
seguir um ponteiro/campo DENTRO do struct do jogador (não vizinhança)
— mas isso exige RE do struct de jogador na memória do cliente.

Até lá: UI mostra "Sem guilda / desconhecida" em toda linha.

### Diferenciação NPC / guarda dentro de "player" ou "mob" — pendente

Classify() usa faixa de ID (CLAUDE.md heurística: 0x00xxxxxx=player,
0x03/04/05/07/09/0C/10/57xxxxxx=mob). Não distingue NPC de guarda de
pet. Precisa reader Ghidra da tag responsável pela ficha da entidade
(candidato: mensagem de detalhe após ENTER — a probar).

## tag=25 — legado (original, mantido pra histórico)

Confirmado por dump direto dos bodies.

### Roster (bulk snapshot) — enviado ao entrar em nova zona
- Body size variável (261B e 221B nos dumps).
- Layout: **`[header 5B][sorted array of u32 LE entity_ids, stride 4]`**
- Header primeira byte parece ser um marcador (0x41, 0x37) — significado
  ainda incerto sem reader.
- IDs vêm ordenados ascendentes.
- Dump: 261B = 5 header + 64×4 = 64 IDs. 221B = 5 header + 54×4 = 54 IDs.
- Cadência: enviado nos 2 momentos que Centablg trocou de área na captura
  (t=+39.082s e t=+133.263s). Casa exatamente com transições de zona
  observadas.

### Entity ENTER (single) — quando alguém entra na visão
- Body 5B: **`[0x01][entity_id u32 LE]`**
- Múltiplas ocorrências pós-roster (t=+54.29, 55.81, 57.25, 62.36, ...)

### Entity LEAVE (single) — hipótese [INFERIDO]
- Body 9B: **`[0x02][id u32 LE][u32 LE]`** — 1 única ocorrência na captura
  (t=+131.96s, `02 e1 5c 45 00 8c f8 63 00`).
- Aparece 1.3s antes do segundo roster (troca de zona). Pode ser LEAVE
  agrupado com zone_id, ou dois IDs "removidos juntos".
- **Precisa validação** com captura em zona povoada onde alguém sai da
  área sem trocar de zona.

### Op-code observados (byte 0 do body pequeno)
- `0x01` = ENTER (dezenas de ocorrências)
- `0x02` = LEAVE/? (1 ocorrência, body maior)
- Outros ops possíveis não observados nesta captura.

## tag=26 — RECONCILIAÇÃO [LIDO vs MEDIDO]

Conflito detectado após primeiro commit. Reader `FUN_00664d00`
[LIDO em `src/SummonOwnerMap.cs` + `re/Spawn26*.java`]:

```
+0  u16   counter/type
+2  u32   summon_id  (mob-range 0x05xxxxxx; nunca player)
+6  u32   float (scale)
+10 12B   two vec2 sub-objects
+22 u16   level? (0x64=100 samples)
+24 u16   level? (0x64=100 samples)
+26..34   padding
+35 u32   OWNER entity_id (player 0x00xxxxxx)
```

Validação [MEDIDO] cruzada com o placar: 120 pares pet→dono construídos
por `SummonOwnerMap` batem com in-game meter (Marcao, Sacrum). Placar
não erra.

Portanto:
- **tag=26 é EXCLUSIVAMENTE spawn de mob/pet**, não de jogador.
- **+2 = mob/pet ID**, **+35 = OWNER (jogador)**.
- Jogador aparece no roster via `tag=25` — nunca via tag=26.
- Leitura anterior deste doc que dizia "+35 = entity_id" e "+22/+24 = HP"
  era erro de interpretação (matched os owners repetidamente e tratou u16
  small values como HP).

**HP no tag=26**: revertido. u16 (0..65535) não cabe HP real de jogador
(dezenas de milhares). Semântica de +22/+24 ainda não confirmada —
possivelmente level (mob), maybe (client-inferred) — precisa reader dump
e teste do boneco (HP 100.000 caindo para 56.942 sob dano). Deixado sem
uso na UI.

## tag=26 — layout tick observado (arquivo, ignorar para presença)

- Body fixo **41 bytes**.
- Layout observado:
  ```
  [0..3]   u32 LE — sequência/timestamp (varia toda mensagem)
  [4..7]   u32 LE — contador global (~0x0005f5-0x05f7 na janela) — NÃO é
                    per-entity (mesma entidade recebe valores diferentes)
  [8..11]  u32 LE — flutuante (bytes [10..11] = 0x3f80 ou 0x3fa0 = 1.0-ish)
  [12..15] u32 — coords (x_prev, y_prev ou similar)
  [16..19] u32 — coords (x, y — geralmente igual a [12..15] com low half)
  [20..23] u32 LE — **HP atual** (100=0x64, 500=0x01f4 confirmado)
  [24..27] u32 LE — **HP máximo** (mesmo formato)
  [28..31] u32 — flags/estado (0x00000000 ou 0x00000001)
  [32..34] 3 bytes — zeros na maioria
  [35..38] u32 LE — **ENTITY_ID** (0x006B0C99, 0x006934E8, ...)
  [39..40] 2 bytes — zeros
  ```

- **Confirmado**: entity_id em offset 35 (não alinhado a 4). Peculiar mas
  determinístico — 5 IDs diferentes casaram em offset 35 exatamente.
- Emitido periodicamente enquanto a entidade está visível → é um TICK,
  não spawn. Serve para HP tracking e movimento.
- Como FIRST-hit para 5 IDs: significa que a entidade entrou na visão
  em tempo mais próximo de um tick que de um spawn-broadcast — possível
  quando entra sob dano ou já em movimento.

## Uso para implementar EntityStateTracker

Regra empírica derivada:

```
tag=25 body ≥100B                → CLEAR() + INSERT array of ids  (zone-change roster)
tag=25 body=5B  op=0x01          → INSERT id
tag=25 body=9B  op=0x02          → REMOVE id (hipótese)
tag=26 body=41B                  → UPDATE hp/pos on id at offset 35
```

## Guilda [INFERIDO / A INVESTIGAR]

Não está em `tag=26` (41 bytes não cabe nome de guilda + o campo
`[4..7]` é sequência global, não guild_id).

### tag=206 [MEDIDO] — não é guilda

Único body de tag=206 nesta captura:
```
c1 08 00 00 12 53 00 63 00 61 00 76 00 65 00 6e 00 67 00 65 00 72 00 02 00 02
```
Layout: `[u32 id=0x000008c1][u8 name_len_bytes=0x12=18][UTF-16 LE "Scavenger" 9 chars][03 tail bytes]`

"Scavenger" é palavra em inglês — provavelmente nome de skill/buff/mob,
não guilda. Guilds em Warspear costumam ter nomes em caps criados por
jogadores. tag=206 aparentemente é broadcast de nome (skill/mob type
name) sob demanda.

### Próximos candidatos

- **tag=61** — CLAUDE.md antigo menciona pattern envolvendo guild angle-brackets `<GUILD>`. Rodar `--dump-tag 61`.
- **tag=207** — já decodifica classe + level; verificar se também
  carrega guilda.
- Perfil-on-demand: cliente pode requisitar guilda via c2s. Investigar
  msgs client-to-server.

Reservado para investigação futura — sem probe adicional não dá pra
implementar guilda no protocolo com certeza. Fonte alternativa
(memscan) já popula `ws-engine.mem-player-guilds.json` e a UI usa isso.

## tag=429 close-out (pendências e limites)

**(1) Reader confirmação [PENDENTE Ghidra]** — factory `FUN_006685d0`
case `0x1ad` aloca 0x1c bytes e chama `FUN_0063a8a0`. Reader ainda não
decompilado — `re/all_readers.txt` só cobre tags 85/87/91/97/98/103/427/428/492.
Script pronto em `re/Tag429Reader.java` para o usuário rodar via
`analyzeHeadless`. O que o dump vai confirmar/refinar:
- Opcodes possíveis em +0..3 (só vi `0x00040000` = apply; refresh/remove?).
- Semântica de +16..17 (só vi 00 00).
- Prova de que +18..19 é `item_id` (não amount/stack).
- Como o código usa `influence_id` (+8..11) — pointer para tabela real
  vs id composto vs hash.

**(2) Categoria por dado [DONE]** — `data/consumable-categories.json`
gerado por script Python de `pak-out/consumables.csd` byte @+6 cruzado
com `pak-out/item_types.csd`:
```
0x0b = comida       (item_types entry name_key 0x00014e7c)
0x0c = pergaminho   (name_key 0x00014e79)
0x0d = poção        (name_key 0x00014e78)
```
990 itens categorizados. `Datamine.ParseConsumableCategories()` faz o
mesmo em C# — próximo `ws-datamine.exe` regenera. `ClassifyConsumable`
em `WS-engine.cs` agora usa `GameData.ConsumableCategory(itemId)` como
primária, keyword só como fallback.

Verificado nos 3 itens do teste:
- 23264 → `poção` ✓
- 15030 → `pergaminho` ✓
- 26468 → `comida` ✓

**(3) Fim de buff além do tempo [DONE parcial]**
- **LEAVE / troca de zona / entidade fora da área**: já limpa
  automaticamente. O tracker é rebuild-per-poll: se o alvo não está
  em `areaSnap.Entities` (removido por op=0x02 ou não presente no
  roster novo), o loop de players nem emite os buffs dele.
- **Reapply do mesmo `influence_id`**: `Tag429BuffDecoder.Handle()`
  remove qualquer buff existente com o mesmo `InfluenceId` antes de
  adicionar o novo — nunca duplica.
- **Morte da entidade**: mensagem de morte ainda não decodificada.
  Buffs continuam aparecendo até expiração natural. TODO: identificar
  a tag de morte (candidatos a probar: tag=93×8 de Centablg no
  discovery capture, corpo 12B).
- **Opcode de remoção via tag=429**: nenhum sample com op != apply
  ainda. Decoder ignora silenciosamente qualquer opcode desconhecido —
  ampliar quando aparecer.

**(4) Buffs já ativos na chegada [LIMITAÇÃO documentada]**
Não há evidência de que a mensagem de aparição (tag=25 op=0x01, body
5B = só o ID) traga a lista de buffs. Nenhum campo cabe. O roster
grande (tag=25 ≥100B) também é só array de IDs. tag=26 (mob/pet
spawn) tem body fixo de 41B sem espaço pra lista dinâmica.

Se houver um "detail" packet enviado após spawn com buffs, precisa
outra probe. Enquanto isso: cliente **só vê buffs aplicados enquanto
o jogador estiver no seu campo de visão**. Buff aplicado antes de
entrar na área não aparece. Nota adicionada à aba Jogadores como
tooltip "i buffs".

## tag=429 — consumable buff apply [MEDIDO confirmado]

Captura `ws_20260921_193940.pcapng` — teste controlado do usuário: 1
poção, 1 pergaminho, 1 comida com nomes anotados. Correlacionado com
`consumable-names.json` via `--probe-ids` com os item_ids conhecidos:

| Item | ID (dec) | ID (hex) | Time (s) | tag=32 (consume) | tag=429 (buff) |
|------|----------|----------|----------|------------------|----------------|
| Poção dos Guerreiros Lendários | 23264 | 0x5AE0 | +5.67 | ✓ | ✓ |
| Carta Mágica | 15030 | 0x3AB6 | +16.57 | ✓ | ✓ |
| Rum forte | 26468 | 0x6764 | +28.68 | ✓ | ✓ |

Além de Centablg (0x00692DA2), a mesma captura contém tag=429 para
outros jogadores (0x001364EE, 0x003545B3, 0x00354AA4 etc.) → **cliente
recebe buffs de terceiros** via tag=429.

### Layout tag=429 (20 bytes fixos, dentro de 492)

```
[0..3]   u32 LE  op = 0x00040000 (apply)
[4..7]   u32 LE  target entity_id
[8..11]  u32 LE  influence_id (buff type — não mapeia direto na
                 influence-names.json; possivelmente id composto
                 [category:u16][index:u16] mas não confirmado)
[12..15] u32 LE  duration_ms  (600000 = 10min poção/comida; 300000
                              = 5min pergaminho)
[16..17] u16 LE  padding (00 00)
[18..19] u16 LE  item_id → chave direta em consumable-names.json ✓
```

Durações [MEDIDO] no teste do usuário:
- Poção Guerreiros Lendários → 600.000 ms = 10 min
- Carta Mágica → 300.000 ms = 5 min
- Rum forte → 600.000 ms = 10 min

### Layout tag=32 (17 bytes dentro de 492) — consume event

```
[0..1]   u16 LE  item_id
[2..5]   4 bytes zeros
[6..7]   u16 LE  flags/type (0x0008 poção, 0x0001 outros)
[8..9]   u16 LE  stack_remaining após consumo
[10..11] u16 LE  0x0064 (=100 — 100%? saúde? level?)
[12]     byte    00
[13..16] u32 LE  user_id
```

Precede tag=429 por ~1-4 ms. Marcador do evento de uso. Não decodificado
pelo tracker — tag=429 basta para timeline.

### Wire termination (fim/remoção)

Não observada mensagem explícita de REMOVE em tag=429 nos samples. Expiry
é inferida por `start + duration_ms`. Se aparecerem samples com opcode
!= 0x00040000, atualizar o decoder — atualmente ignora silenciosamente.

## tag=428 — buffs / status ativos [MEDIDO parcial]

Dump em `captures/ws_20260921_183825.dump-tag428.txt` (20 amostras).
Todos os 20 bodies têm 18 bytes fixos.

Layout observado:
```
[0]      u8   = 0x00 sempre
[1]      u8   = 0x00 ou 0x08 (flag — apply/refresh?)
[2..3]   u16 LE — sub-código / opcode: 0x0002, 0x01db, 0x0341, 0x0317, 0x0352, ...
[4..7]   u32 LE — entity_id (target)
[8..11]  u32 LE — sub-value ou buff_id
[12..15] u32 LE — DURAÇÃO em ms (60000 = 1min, 0xFFFFFFFF = permanente)
[16..17] u16 LE — 00 00 (padding)
```

Valores de duração encontrados:
- `0x0000ea60` = 60,000ms (60s) ✓
- `0x0078c66d` ≈ 7.9M ms (~130 min) — buff longo
- `0x00768f48` ≈ 7.77M ms — idem
- `0x0072f2ef` ≈ 7.53M ms
- `0xFFFFFFFF` — permanente ✓

**Limitação observada [MEDIDO]:** todos os 20 samples nesta captura têm
`entity_id = 0x00692DA2` (Centablg, o próprio usuário). Nenhum tag=428
carrega ID de terceiros nesta janela.

Duas hipóteses:
1. Cliente só recebe tag=428 para SELF — jogo mostra buff overlays em
   outros por outro canal (ex.: uma flag no tag=26 tick, ou nada — só
   ícone genérico).
2. Coincidência da janela: ninguém trocou buff com o usuário.

Precisa **captura de teste** onde:
- Usuário usa poção, pergaminho, comida (buffs conhecidos + timestamps).
- Outro jogador na área também consome consumível (verificar se aparece).
- Usuário recebe/dá buff de grupo (heal-over-time, buff de raid).

Sem o reader `FUN_006685d0` para tag=428, os campos +2 e +8 são
palpites — poderiam ser `influence_id` (cruzar com
`defined_influences.csd`, 285 entradas) e `item_id` (cruzar com
`consumables.csd`), mas os valores observados (0x01db=475, 0x0341=833,
0x000113ee=70638) não batem com o range esperado de 285 influences.
Pode ser hash, id composto, ou dois campos diferentes empacotados.

**Próximo passo**: capturar sequência controlada (usuário toma 1 poção,
1 pergaminho, 1 comida com nomes anotados + tempos), rodar
`--dump-tag 428` e correlacionar os +2 e +8 com os itens conhecidos.

## Próximo passo (Ghidra)

Task original pede ler readers pela factory `FUN_006685d0`.
- Já existem scripts em `re/DecompileFactory*.java`.
- Escrever `re/DumpReader25.java` e `re/DumpReader26.java` que sigam o
  ponteiro do switch case para tag 25 e 26 respectivamente e imprima o
  reader decompilado.
- Confirmar semântica dos ops 0x01/0x02 no reader de tag=25.
- Achar tag de guilda no switch: alguma tag com body contendo string
  ASCII/UTF-16 curta.

Fora do escopo desta captura — depende do usuário rodar Ghidra.

## Ground-truth pendente

Contar visualmente jogadores na tela (o usuário disse "30-50" na área
de destino) e comparar com o roster: 64 IDs na primeira transição —
inclui mobs + npcs + pets além dos 30-50 players.

Após implementar o EntityStateTracker com classificação player/mob
baseada em faixa de ID (temporariamente até termos `entity_kind` no
reader), rodar contagem e validar contra a memória visual do usuário.
