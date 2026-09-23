# CLIENT-RE-R7.md — Rodada 7: Tecnópolis (placar, pets, received gaps)

**Data:** 2026-09-21. Escopo: análise de dumps read-only.
Rótulos: **[LIDO]** / **[INFERIDO]** / **[MEDIDO]**.

## Dump de referência

`captures/ws_20260921_131817.pcapng` — sessão em zona "Tecnópolis" (título
do placar diferente do "Resultados da luta"). Ground truth do jogo:

**Dano causado:**
| jogador     | jogo    | programa (tag=427 sum) | diff  | status |
|-------------|---------|------------------------|-------|--------|
| Centablg    | 751.386 | 751.386                | 0     | ✓ EXATO |
| Koryceif    | 393.862 | 389.028                | 4.834 | ✗ GAP  |
| Deatharchh  | 257.043 | 257.043                | 0     | ✓ EXATO |
| Defensoras  | 183.564 | 183.513                | 51    | ~ (arred) |
| Sayablood   |  86.905 |  86.905                | 0     | ✓ EXATO |

**Dano recebido:**
| jogador     | jogo   | programa | diff  |
|-------------|--------|----------|-------|
| Centablg    | 32.206 | 32.206   | 0     |
| Sayablood   | 17.670 | 15.854   | 1.816 |
| Koryceif    |  4.783 |  3.360   | 1.423 |
| Deatharchh  |  1.636 |  1.640   | −4    |
| Defensoras  |    683 |      0   |   683 |

**Cura recebida (efetiva):** ground truth conhecido, tag=99 sum >> gt
para 4 dos 5 (overheal confirmado).

## Tarefa 1 — tipo de placar de Tecnópolis

**[MEDIDO]** `tag=554 count = 0` neste dump. Placar `554` (usado em raid
regular) **não aparece em Tecnópolis**.

Candidatos escaneados (mensagens grandes >200B):
- `tag=492` (LZ4 comprimido — walked): nested tags só 5 valores GT do
  placar aparecem, e apenas 3 distintos (Sayablood-recv-17670,
  Koryceif-heal-6152, Sayablood-heal-2612). Insuficiente pra ser scoreboard.
- `tag=430` (20B): não é damage — layout ATRIBUTO idêntico ao tag=428
  com 2B extra (`[u16 flag][u16 attr][u32 ent][u32 v1][u32 v2][u16 tail1][u16 tail2]`).
- `tag=447` (12B): heartbeat/counter com padrão `[u32=50][u32=const][u32 incrementado]`.
- `tag=87`: body 0B (delimiter conhecido).

**[INFERIDO]** Tecnópolis não broadcasta scoreboard packet — cliente
agrega dmg/heal/recv localmente somando eventos wire. Isso explica
por que valores exatos (751386, 393862 etc.) não aparecem no wire como
u32 literal.

**Consequência**: validação vs ground truth precisa ser feita por SOMA
dos eventos wire, não por leitura de scoreboard. Precisão da UI depende
100% da qualidade do decoder + link pet→dono + captura desde o início.

## Tarefa 2 — Koryceif dmg dealt gap ~4.834 + sem classe

**[MEDIDO]** Nenhum mob-range attacker (0x05xxxxxx) tem dmg total ≈4834.
Top mob attackers: 10312 (boss counter), depois 1715, 1159, 1122, 1119…
Overlap de targets com Koryceif = 0 para todos (mobs atacam jogadores,
Koryceif ataca mobs — domínios diferentes).

**[INFERIDO]** Pet spawnado ANTES da captura → sem `tag=26` de spawn →
sem link pet→dono. Damage do pet cai em atacantes órfãos (mob range) que
não podemos atribuir a Koryceif.

**Ausência de classe**: memscan não pegou Koryceif no processo do jogo
neste momento. Provavelmente Koryceif não estava visível na área quando
memscan.exe rodou último ciclo, ou struct dele não foi encontrada.
[NÃO EXECUTADO] rodar memscan durante sessão pra popular
`ws-engine.mem-player-classes.json`.

**[NÃO EXECUTADO]** Verificar se existe uma mensagem PERIÓDICA que
re-broadcasta pet→dono (independente de spawn). Candidatos a testar:
tag=26 (263 nested — pode estar re-emitindo mesmos pets ativos), tag=29
(319 nested), tag=493 (85 top-level SÓ pra Koryceif — muito específico,
possível "player state" ou pet-list broadcast).

## Tarefa 3 — dmg recebido gaps

**[MEDIDO]** tag=99 sum >>> ground truth (Centablg 26331 raw vs 3046 gt
efetivo) — **overheal na wire CONFIRMADO** pelo excesso; valida o
critério R6 (`efetivo = min(amt, max_hp − hp_atual)`).

**[MEDIDO]** tag=98 layout confirmado pra 5 jogadores — DUAS variantes
alternando:
- variante A: `[u32 stamina<200][u32 ent][u32=0]`
- variante B: `[u32=0][u32 ent][u32 energy<200]`
NÃO carrega dmg absorvido/mitigado.

**[MEDIDO]** tag=430 body 20B = attr update (não damage). Não é fonte
de dmg recebido faltante.

**Coincidência a investigar**: Defensoras `heal_diff = 683` (heal sum
10197 < gt 10880) BATE EXATO com `recv_diff = 683` (recv sum 0 < gt 683).
Mesmos 683 pontos faltando em dois totais distintos. Duas hipóteses:
1. Packets perdidos no início da captura (Defensoras entrou na área
   antes de dumpcap iniciar) — falta o mesmo bloco de eventos em
   ambos.
2. Algum evento único de 683 dmg autoinfligido + heal reflexo, ambos
   perdidos.

**[NÃO EXECUTADO]** testes de hipóteses:
- (a) somar ao dono dmg recebido pelos pets dele — requer link pet→dono
  funcionando; sem pet spawn packet a atribuição não é possível.
- (b) escudo/mitigação em outra tag — nada em tag=98/430 fez match.
  Candidatos ainda não varridos: tag=93 (285 nested), tag=92 (196
  nested), tag=345 (448 nested).
- (c) DoT/reflexo em tag distinta do 427 — mesmo escopo do (b).

**Sobre u32[2] do tag=554**: dump Tecnópolis não tem tag=554, teste
adiado.

## Tarefa 4 — UI HITS removida

`assets/webview/index.html` linha 35 removida (`<th>Hits</th>`).
`assets/webview/app.js` linha 65 removida (cols entry Hits).
Confirmado por commit.

## Achados sólidos

**[LIDO/MEDIDO]**
- Tecnópolis não broadcasta scoreboard packet.
- tag=430 (20B) = attribute update (não damage).
- tag=447 (12B) = heartbeat counter.
- tag=99 wire = overheal-raw (confirma R6 validação).
- tag=98 layout Centablg-style = 2 variantes stamina/energy.

**[INFERIDO / não falsificado]**
- Koryceif pet órfão (spawn perdido) explica ~4834 gap.
- Received gaps podem ser packets iniciais perdidos (Defensoras 683
  bate em heal e recv).

## Arquivos

- `tools/_probe-tecnopolis.ps1` — identifica dump por dmg totals + hist tags
- `tools/_probe-tecno-scoreboard.ps1` — busca valores GT em cada tag
- `tools/_probe-tecno-pets.ps1` — mob-attackers como candidatos a pet
- `tools/_probe-tecno-tag430.ps1` — análise tag=430/447/87
- `tools/_probe-tecno-recv-tags.ps1` — tags mencionando cada player + tag=98/99 sum
