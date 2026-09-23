# CLIENT-RE-R6.md — Rodada 6: HP do alvo e do próprio (busca em wire)

**Data:** 2026-09-21. Escopo: leitura estática read-only + análise de dumps.
Rótulos: **[LIDO]** / **[INFERIDO]** / **[MEDIDO]**.

## Sumário executivo

**[MEDIDO]** Nenhum campo no wire carrega HP do MOB alvo (dummy Manequim)
periodicamente. HP de mob = **client-inferred** por
`HP_current = HP_max - Σ dmg_received`.

**[LIDO]** tag=428 (18B) é evento genérico de update de atributo com layout
`[u16 flag][u16 attr_type][u32 entity][u32 v1][u32 v2][u16 tail]`. Atributos
observados no wire: **>= 30 attr_ids distintos por entidade** — cada attr
é um recurso/stat separado. attr=0x0002 é forte candidato a MP/energy.

**[MEDIDO]** HP próprio ainda **não localizado** — attr=0x0002 não é HP,
e nenhum outro attr foi validado ainda. Espera nova rodada.

## Dump de referência

`captures/ws_20260920_112235.pcapng` — sessão de treino contra Manequim
com ground truth conhecido:
- HP inicial 100000 → final 56942 (delta 43058)
- 27 acertos, seq `121222111121111212212111122` (1=1070, 2=2358)
- Atacante: Centablg `0x00692DA2` — Alvo: Manequim `0x05f5e382`

Validado por `tools/_probe-find-boneco-dump.ps1` — bate exato 16×1070 + 11×2358.

## Tags que mencionam o ID do alvo `0x05f5e382`

Enumeração via `tools/_probe-hp-timeline.ps1` (top-level + descomprimido do 492):

| tag | contagem | local | body | semântica |
|-----|----------|-------|------|-----------|
| 492 | 28       | top   | var  | container LZ4 dos eventos |
| 427 | 27       | nested| 13B  | dano `[dmg u32][att u32][tgt u32][flag u8]` |
| 91  | 27       | nested| 11B  | atribuição `[00 00][att u32][tgt u32][01]` |
| 28  | 2        | 1T+1N | 5B   | visibilidade `[bool u8][ent u32]` — 01 no start, 00 no end |
| 29  | 1        | nested| 5B   | `[flag u8][ent u32]` — flag 0x20 no start (spawn state?) |
| 98  | 2        | 1T+1N | 12B  | `[u32 0][u32 ent][u32 25000]` scoreboard e `[u32 0][u32 ent][u32 18058]` post-combate |

**[MEDIDO]** Nenhuma tag apresenta sequência 100000 → 56942 nem valor
absoluto de HP para o dummy. Nenhuma queda proporcional aos danos.

### tag=98 pós-combate (25000 → 18058)

Aparece 2× APÓS combate encerrar (t=110s scoreboard, t=115s pós). Delta
6942 ≠ 43058. Layout casa com `[u32 stamina_or_energy][u32 entity][u32 valor]`
já observado antes (rodada anterior: layout tag=98 com Centablg).

Neste dump o entity é o Manequim (não Centablg) — 25000/18058 é provavelmente
o **stamina/energy do Manequim no scoreboard**, não HP.

## HP de MOB no cliente — modelo assumido

**[INFERIDO]** Cliente mantém `Map<entity_id, {hp_cur, hp_max}>`:
- `hp_max` vem de `data/mob-types.json` (indexado por type_id do spawn) —
  **mas o pak não tem esse campo** (verificado na Fase 6). Pode estar em
  outro `.dat` ou vir por wire no spawn (não localizado ainda).
- `hp_cur` decrementa por soma dos `tag=427.dmg` com `tgt==entity_id`.
- No boneco session: 100000 (HP config específico do dummy) - 43058 = 56942 ✓.

**Consequência**: pra painel de alvo/boss com barra de vida:
1. HP máx por tipo precisa vir de uma fonte:
   - **[NÃO EXECUTADO]** re-scan de `.dat`/`.csd` do pak procurando campo HP
     na tabela de mobs
   - OU: derivar de dano cumulativo observado ao longo de sessões (upper bound)
   - OU: capturar tag=428 attr=X do MOB no momento do spawn se existir
2. HP atual = HP máx - Σ dmg em `damage_events` filtrados por `tgt=entity_id`.
3. Persistir HP máx por `type_id` no SQLite (o pak/data não tem essa tabela).

## HP próprio — investigação parcial

**Ground truth extraído dos dumps**:
- healing dump ws_20260920_212612: dmg recebido = 17192, heal recebido = 19046
- raid_overgod: dmg recebido = 24319, heal recebido = 17270

**tag=98 (Centablg)** — DUAS variantes alternando:
- variante A: `[u32 A][ent][u32 = 0]` com A ∈ {14..49}
- variante B: `[u32 = 0][ent][u32 B]` com B ∈ {18, 58, 70, 116, 146}
- Valores todos < 200 → **stamina e energy** (dois recursos separados
  broadcasted na mesma tag com posição alternada). **NÃO é HP**.

**tag=428 attr=0x0002 (Centablg)** — v2 constante = 60000 (**MAX HP
confirmado**), v1 varia 62917..62993 e 69144..69206 (não correlaciona
com dmg/heal recebido). Aparece em BATCH SNAPSHOT no spawn/zone-enter
(15 attrs juntos com mesmo timestamp), não streaming. v1 pode ser
COINS ou XP counter.

**tag=428 attr=0x0065 (Centablg)** — v1 monótono crescente 62924..63125
(counter), v2 range 1774..10100 (looks like percentual × 100, i.e.
basis points de 0-100%). Broadcast a cada ~13s no raid_overgod.
Candidato a **HP% ou energy%**, precisa validação por queda com dmg
recebido.

**tag=428 attr=0x0034 e attr=0x0033** — v2 nas casas dos milhões
(1.5M..1.6M, 2.7M..2.8M) — provavelmente **item durability** ou
**equipamento stats agregado**, NÃO HP.

**[MEDIDO]** HP próprio absoluto: **não localizado em wire**. Candidatos
testados: tag=98 (é stamina/energy), tag=428 attr=0x0002 (v2 é max HP
mas v1 não é current HP), attr=0x0034/0x0033 (equipamento).

**[NÃO EXECUTADO]**
- Validar attr=0x0065 como HP%: filtrar dump onde Centablg toma
  dano suficiente pra descer HP < 100% e verificar se v2 desce
  proporcional.
- Testar tags menos frequentes: tag=93 (12B), tag=92 (12B), tag=417,
  tag=345, tag=430 — nunca testadas como HP.
- Decompilar reader `FUN_0063aad0` (tag=428) para semântica exata
  dos 0x0800/0x0400/0x0000/0x0c00 flags.

## Critério de validação de HP — cura efetiva vs placar (tag=554)

**[LIDO da mecânica do jogo]** Cura (inclusive vampirismo) com HP cheio
= ZERO efetiva. `tag=99` traz `amount` bruto; placar `tag=554`
conta `heal_done_effective = min(amount, max_hp − hp_atual_no_momento)`.

**Critério objetivo** para candidato HP:
1. Alimentar tracker HP com `(max_hp, dmg_received, heal_received)` por
   entidade ao longo da timeline.
2. Para cada evento tag=99 com `tgt = E`:
   `efetivo(E) = min(amount, max_hp(E) − hp_atual(E, t))`
3. Somar `efetivo` por tgt.
4. Comparar com `heal_done_effective` do placar tag=554.

Se **10/10 jogadores batem exato** → HP correto [MEDIDO].
Se algum player difere → HP errado; overheal `[INFERIDO]` fica não
falsificado, precisa refinar hipótese HP.

Dump alvo p/ teste: `captures/ws_20260920_212612.pcapng` (231 tag=99, 10
players com placar 554 disponível).

Isso substitui a Tarefa 4 do plano original: overheal não vira `[MEDIDO]`
por observação direta — vira `[MEDIDO]` quando o cálculo `min()` bater
o placar 10/10.

## tag=428 — layout confirmado (18B)

**[LIDO]** Factory `FUN_006685d0` case `0x1ac` (428) aloca 24B, body 18B
(CLIENT-RE 6.14). Layout empírico:

```c
struct Tag428Body {
    u16 flag;         // 0x0000 baseline, 0x0800 delta
    u16 attr_type;    // 0x0002, 0x0065, 0x0162, ... (>= 30 attrs observados)
    u32 entity_id;
    u32 v1;           // atributo primário (semântica depende de attr_type)
    u32 v2;           // atributo secundário (frequente = max ou cap)
    u16 tail;         // muitos zeros; nem sempre
}
```

Reader oficial ainda não decompilado (endereço via factory = FUN_0063aad0).

### Padrão flag observado

- `flag=0x0000` — snapshot inicial ou "estado atual pré-mudança"
- `flag=0x0800` — evento de mudança/delta (v2 reduzido por consumo,
  ou v1 alterado)

**[INFERIDO]** flag pode ser bitfield indicando se v1/v2/tail estão
"changed" nesta mensagem.

## Não executado nesta rodada

1. Decompilar `FUN_0063aad0` (reader do tag=428) — confirma semântica
   dos flags e dos campos.
2. Enumerar tabela de attr_type — quantos IDs realmente existem, e mapa
   pra nome legível (força, agi, HP, MP, etc.). Provável mesma tabela
   consumida por `data/ui-strings-pt.json` (chaves tipo "attr.hp").
3. Localizar tag/campo que carrega HP inicial de mob no spawn (tag=207/551
   parciais já vistos, mas HP não).
4. Dump com combate onde Centablg toma dano → identificar HP próprio.
5. Sanity check em `re/handlers.txt` de FUN_009acb50 para atributos
   HP-específicos.

## Ações concretas para integração (Tarefa 5)

- Adicionar `Dictionary<uint, HpState>` em `WSEngine.MainForm` (ou serviço
  dedicado):
  - `HpState.MaxHp`, `HpState.CurHp`, `HpState.LastUpdate`.
  - `CurHp = MaxHp - Σ dmg recebido`.
- `MaxHp` inicial:
  - Se entity é player: `max_hp_default` até tag=428 attr=HP chegar.
  - Se entity é mob: buscar em SQLite `mob_hp` (a criar) por `type_id`;
    fallback: max dmg total já observado.
- Persistência SQLite:
  - Tabela `mob_hp(type_id INT PRIMARY KEY, hp_max INT, last_seen TS)`.
  - Atualizada quando: 1) tag=428 attr=HP chega pra mob; 2) inferência
    por damage total >= hp_max_registrado.
- UI: `assets/webview/index.html` painel "TARGET/BOSS" com barra vida
  `<div class="hp-bar">` — recebe push do backend via `WebViewHost.PushHp`.

**Nada aplicado ao src/ nesta rodada.** Rodada é investigação apenas.

## Arquivos

- `tools/_probe-find-boneco-dump.ps1` — localiza dump com dmg 1070/2358
- `tools/_probe-hp-tags-boneco.ps1` — enumera tags mencionando dummy id
- `tools/_probe-hp-timeline.ps1` — timeline detalhada de eventos com dummy id
- `tools/_probe-hp-tag98-scan.ps1` — scan de tag=98/428 por entidade
- `tools/_probe-hp-tag428-attr.ps1` — série temporal por (entidade, attr_type)
- `tools/_probe-hp-self.ps1` — dmg/heal recebido + tag=98/428 timeline para Centablg
