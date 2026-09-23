# pak-inventory.md — Warspear v13.4.3 pak-out/ mapping

Fonte: `pak-out/` (91.441 arquivos extraídos de `warspear.pak` via `pakextract`).
Data: 2026-09-20.

**Status atual:** **63.754 entries em 53 JSONs em data/**.

Progressão:
- Baseline: 23.520 (4 tabelas iniciais)
- Rodada 1: +1.632 (bonus, class skills, zones, sectors, talents) → 25.152
- Rodada 2: +11.135 (weapons, armors, consumables) → 34.661 (era o número anterior)
- Rodada 3 autônoma: **+29.093** (items expandidos, territories, achievements, quests, influences, factions, jewelry, iaobjects, npcs, hints, etc.) → **63.754**

## 1. Distribuição por extensão

| ext | count | notas |
|---|---|---|
| `.imgp` | 35.229 | texturas/sprites — **ignorar** (não é dado tabular) |
| `(sem ext)` | 44.136 | quests: `quests/{bi,de,en,es,kr,pl,pt,ru,zh}/<id>` — INI UTF-16 |
| `.map` | 5.501 | dados de mapa binários (world/) — não investigado |
| `.dt` | 4.204 | binário compacto — não investigado |
| `.dat` | 1.509 | dados tabulares binários — **prioritário**, alguns parseados |
| `.wav` | 329 | áudio — ignorar |
| `.ini` | 329 | text config UTF-16 |
| `.csd` | 104 | data tables com magic 2-3B + name_key → strings_pt — **prioritário**, alguns parseados |
| `.fnt` | 34 | fonts — ignorar |
| `.ogg` | 33 | áudio — ignorar |
| `.cfg` | 18 | configs cliente |
| `.xml` | 8 | XML |
| `.txt` | 5 | text (badwords, banlist, version) |
| `.pem` | 1 | chave pública TLS |
| `.log` | 1 | log |

## 2. Distribuição por diretório

```
44136 quests/       — quest text por idioma (INI UTF-16)
15813 icons/        — icons de skills/items/buffs (imgp)
10975 monsters/     — sprites/anim de mobs (imgp + dt)
 8065 ia_objects/   — objetos interativos/coletáveis (imgp)
 6239 world/        — mapas (.map binário)
 3830 sets/         — vestuários por classe (imgp)
  883 man/          — help/manual pages
  362 sounds/       — wav/ogg
  332 gui_layouts/  — layouts UI (XML)
  269 fxs/          — efeitos visuais (imgp + dat)
  229 (raiz)        — tabelas de referência do jogo — CENTRAL PARA RE
   53 gui_240x284/  — GUI para device 240x284
   44 fonts_240x284/
   38 gui_common/
   37 gui_176x208/
   32 fonts_176x208/
   26 local/        — kbd layouts por idioma
   21 ingame/       — ingame.dt + projectile.dt + imgps
   20 smiles/       — emotes
   19 config/       — config_N.cfg + public.pem
   13 gui_widescreen/
    3 hostcfg/
    2 help/
```

**Prioridade máxima:** `pak-out/*.{csd,dat}` (raiz, 229 arquivos). Toda tabela
de referência do jogo está aqui.

## 3. Formatos identificados

### `.dat` (binários tabulares — raiz)

Dois subformatos empíricos observados:

**Formato A — string table**: `[id:u32 LE][UTF-16 LE null-terminated string]` * N.
Usado em `strings_pt.dat`, `client_ui_strings_pt.dat`, `countries_pt.dat`.

**Formato B — fixed-size records**: header opcional (12B em `monsters.dat`,
zero em `bonuses.dat`) seguido de N registros de tamanho fixo. Cada registro
contém `[id][flags?][name_key u32 → strings_pt]`.

Parser em `src/Datamine.cs` já cobre ambos.

### `.csd` (data tables — raiz)

Registros de tamanho variável ou fixo, cada um iniciado por um MAGIC de 2-3
bytes específico do arquivo. Após o magic: `[id:u32][name_key:u32][mais campos]`.

Magics identificados:

| arquivo | magic | tamanho record | records |
|---|---|---|---|
| `classes.csd` | `2a 1c` | 30 B fixo | 20 |
| `guild_skills.csd` | `02 83 01` | 134 B fixo | 24 |
| `skills.csd` | `08 b7 02` | variável (263, 314, 669, 749…) | 322 skills |
| `zones.csd` | `2d 2f` / `2d 0b` | variável | ~15 |
| `sectors.csd` | `26 08` | 10 B fixo | 14 |
| `talents.csd` | `23 20` | 34 B fixo | 1175 |
| `weapons.csd` | `30 3e` | variável | 3632 named (item_id @+2, name_key @+12) |
| `armors.csd` | `31 40` | variável | 6505 named (mesma layout do weapons) |
| `consumables.csd` | `38 3f` | variável | 998 named (mesma layout) |

Outros arquivos raiz com estrutura similar mas ainda **não parseados**:

`achievements.csd` `access_groups.csd` `amplifier_items.csd` `armors.csd`
`castle_*.csd` `catacombs_reward_categories.csd` `consumables.csd`
`control_points.csd` `craft_*.csd` `crystal_items.csd` `rune_items.csd`
`sands_entrance.csd` `simple_service_*.csd` `skill_amplifier_*.csd`
`skill_book_items.csd` `skill_consumable.csd` `skill_matrix.csd`
`smile_packs.csd` `spawn_object_items.csd` `stamina.csd`
`summon_items.csd` `summon_skills.csd` `summon_skill_usage_types.csd`
`talents_by_class.csd` `talents_milestones.csd` `talents_subtrees.csd`
`talents_tree.csd` `talents_tree_v2.csd` `territories.csd`
`title_guild_achievements.csd` `tutor_data.csd` `tutor_text.csd`
`weapons.csd` `web_payments.csd`

### `.dt`

`ingame/ingame.dt`, `ingame/projectile.dt`, `monsters/<mob>.dt` (~4200 files).
Formato binário compacto — não investigado nesta rodada. Provavelmente
sprite/frame data, não tabelas.

### quests (sem extensão)

INI UTF-16 LE. Formato:

```
[quest]
name=Elixir da ira
id=100
type=0

[analytics]
type=0
event=0
localization_status=1

[stage1]
text=Colha 4 cogumelos-da-lua
text_complete=Fale novamente com Kaaf
counter1=Cogumelos-da-lua colhidos

[dialogs]
dlg1=Droga! Minha poção nova não vai...
```

4904 quest files em `quests/pt/`. Não parseado ainda — potencial pra decodificar
eventos de quest no protocolo, além de fornecer texto de NPC completo.

### `.ini`, `.xml`, `.cfg`

Configurações do cliente (channel.cfg, config_N.cfg). Não relevante pra RE do
protocolo diretamente.

## 4. Já parseado (data/*.json)

| JSON | source | entries | uso em WS-engine |
|---|---|---|---|
| `class-names.json` | `classes.csd` | 20 | GameData.ClassName |
| `mob-types.json` | `monsters.dat` | 19.119 | GameData.MobName / Classify |
| `ui-strings-pt.json` | `client_ui_strings_pt.dat` | 2.707 | GameData.UiString |
| `skill-names.json` | `guild_skills.csd` | 24 | GameData.SkillName |
| **`bonus-names.json`** | `bonuses.dat` | **114** | GameData.BonusName (novo) |
| **`class-skill-names.json`** | `skills.csd` | **318** | GameData.ClassSkillName (novo) |
| **`zone-names.json`** | `zones.csd` | **12** | GameData.ZoneName (novo) |
| **`sector-names.json`** | `sectors.csd` | **13** | GameData.SectorName (novo) |
| **`talent-names.json`** | `talents.csd` | **1175** | GameData.TalentName (novo) |
| **`weapon-names.json`** | `weapons.csd` | **3632** | GameData.WeaponName (rodada 2) |
| **`armor-names.json`** | `armors.csd` | **6505** | GameData.ArmorName (rodada 2) |
| **`consumable-names.json`** | `consumables.csd` | **998** | GameData.ConsumableName (rodada 2) |

**Total dados de referência:** 34.657 entries.

## 5. Alvos prioritários — status

### Rodada 1 (extração inicial)

| # | alvo | status | resultado |
|---|---|---|---|
| 1 | BUFFS / EFEITOS / AURAS | **✓ FEITO** | 114 bonuses via `bonuses.dat` |
| 2 | SKILLS POR CLASSE | **✓ nome só** | 318 skills via `skills.csd` (só nome — valores de dano/cooldown estão em sub-registros de nível não parseados) |
| 3 | ITENS / EQUIPAMENTOS | **✓ FEITO (rodada 2)** | 11.135 items em 3 categorias |
| 4 | MAPAS / ZONAS | **✓ FEITO** | 12 zones (regiões) + 13 sectors via `zones.csd` + `sectors.csd`. `territories.csd` pendente. |
| 5 | DEFINIÇÃO DE PROTOCOLO | **NÃO EXISTE** | Nenhum arquivo com nome sugestivo (`packet`, `message`, `opcode`, `net`, `proto`). Warspear não embarca schema de rede. |

### Rodada 3 autônoma (2026-09-20 late-night)

Execução do plano `EXTRACAO-AUTONOMA-PAK.md`. Loop identificação → parse →
JSON → GameData → validação → registro, sem intervenção humana.

**Descobertas de layout:** todos os `.csd` de items compartilham layout
`[magic 2B][item_id u32 @+2][flags u16][sub_id u32][name_key u32 @+12]`.
Parser genérico `ParseItemFile`. Layouts alternativos (`ParseCustom`) tratam
offsets diferentes para achievements/territories/etc.

**Novas tabelas nesta rodada:**

| tabela | count | fonte | offset |
|---|---|---|---|
| quest-item-names | 5.443 | quest_items.csd | m=33 24, +12 |
| quest-names | 4.866 | quests/pt/*.ini | UTF-16 [quest] |
| npc-doll-names | 4.620 | npc_dolls.csd | m=62 33, +6 |
| jewelry-names | 3.404 | jewelry.csd | m=32 3a, +12 |
| iaobject-names | 2.096 | iaobjects.csd | m=28 1d, +8 |
| territory-names | 1.415 | territories.csd | m=25 13, +6 |
| guts-item-names | 1.301 | guts_items.csd | m=36 20, +12 |
| outfit-item-names | 1.133 | outfit_items.csd | m=3b 36, +12 |
| achievement-names | 1.116 | achievements.csd | m=14 1f, +14 |
| service-item-names | 559 | simple_service_items.csd | m=3d 20, +12 |
| envelope-item-names | 550 | envelope_items.csd | m=42 24, +12 |
| smile-pack-names | 546 | smiles_packs.csd | m=48 24, +12 |
| influence-names | 285 | defined_influences.csd | m=18 12, +10 (**BUFFS**) |
| skill-book-names | 257 | skill_book_items.csd | m=44 28, +12 |
| achievement-goal-names | 214 | achievements_goal.csd | m=16 13, +12 |
| dummy-item-names | 201 | dummy_items.csd | m=2e 20, +12 |
| crystal-item-names | 194 | crystal_items.csd | m=3a 28, +12 |
| skill-amplifier-names | 173 | skill_amplifier_items.csd | m=37 20, +12 |
| haircut-pack-names | 130 | haircut_pack_items.csd | m=47 24, +12 |
| item-set-names | 90 | item_sets.csd | m=3c 10, +10 |
| hint-names | 73 | hints.csd | m=2b 0f, +6 |
| rune-item-names | 67 | rune_items.csd | m=39 28, +12 |
| craft-item-names | 66 | craft_items.csd | m=34 20, +12 |
| craft-job-names | 54 | craft_job_info.csd | m=0d 31, +6 |
| castle-building-level-names | 45 | castle_building_levels.csd | m=1f 37, +10 |
| faction-names | 40 | factions.csd | m=06 14, +8 |
| resource-item-names | 23 | resource_items.csd | m=35 20, +12 |
| summon-skill-names | 22 | summon_skills.csd | m=54 68, +10 |
| castle-building-names | 20 | castle_buildings.csd | m=1e 0c, +6 |
| spawn-object-names | 15 | spawn_object_items.csd | m=5b 63, +12 |
| amplifier-item-names | 12 | amplifier_items.csd | m=41 22, +12 |
| catacomb-reward-names | 11 | catacombs_reward_categories.csd | m=61 10, +10 |
| achievement-group-names | 11 | achievements_group.csd | m=15 11, +6 |
| currency-names | 10 | currencies.csd | m=2c 10, +10 |
| item-pack-names | 9 | item_packs.csd | m=3f 5e, +12 |
| talent-milestone-names | 9 | talents_milestones.csd | m=56 10, +6 |
| title-guild-achievement-names | 7 | title_guild_achievements.csd | m=4c 12, +6 |
| expansion-item-names | 6 | expansion_items.csd | m=40 22, +12 |
| castle-building-type-names | 5 | castle_building_types.csd | m=1d 14, +6 |
| castle-names | 5 | castles.csd | m=1b 16, +6 |
| chestkey-item-names | 4 | simple_service_chestkey_items.csd | m=3e 24, +12 |

**+29.093 entries** somando tudo.

### Rodada 2 (2026-09-20 noite — foco em decoder)

| # | alvo | status | resultado |
|---|---|---|---|
| 1 | **HP máximo de mobs** | **BLOQUEADO** | Ground truth: Manequim = 100.000 HP. Único 100000 (u32 LE) em `monsters.dat` bate por coincidência com `strings_pt` id 100000 = "Acrobata Mata-moscas" (name_key). Nenhum mob-dummy tem 100000 no seu record. Nenhum outro arquivo do pak contém 100000 associado a mobs. **HP provavelmente formulaico (base * level) ou server-only, não trafega no pak.** |
| 2 | **Sub-registros skills.csd** | **BLOQUEADO** | Format é TLV aninhado com magic pai `08 84 02` e filho `08 db 03`. Registros variam 263-40000 bytes. Complexidade não decifrada nesta rodada. |
| 3a | **Formato .map** | **identificado** | Arquivos `AxBxC.map` em `world/zone_N/`, sempre 1572 bytes. Grid de células (~28x28 = 784 cells * 2B). Header `03 00` ou `01 00`. Não é dado de spawn/entidade — é máscara de walkability/tipo de terreno. Não útil pra decoder de protocolo. |
| 3b | **Formato .dt** | **identificado** | Todos `.dt` (4.204 files) começam com magic `06 00 00 00`. Sprite/animation frame table. Sem dado tabular. Ignora. |
| 4 | **Itens (weapons/armors/consumables)** | **✓ FEITO** | 11.135 items. Layout uniforme: `[magic 2B][item_id u32 @+2][flags u16][sub_id u32][name_key u32 @+12]...`. Parser genérico `ParseItemFile` em Datamine.cs. |

## 6. Pendências

### Status ALVOs autonomous run

| ALVO | prioridade | status | notas |
|---|---|---|---|
| 1 HP máx mobs | 🔴 MAX | **BLOQUEADO — não trafega no pak** | Buscado em todos os arquivos .csd/.dat com 100000 (u32 LE + BE). Único match em monsters.dat = coincidência com name_key 100000 = "Acrobata Mata-moscas". `monster/{id}.dt` = sprite/anim (magic 06 00 00 00), sem HP. Conclusão: HP calculada server-side ou formulaica. |
| 2 skill sub-records | 🔴 | **BLOQUEADO — TLV aninhado complexo** | Magic pai `08 84 02`, filho `08 db 03`. Tamanhos 263-40000B. Não decifrado. Próxima tentativa: ground truth de UMA skill com dano conhecido + busca de valor no body dessa skill. |
| 3 .map | ⚙️ | **identificado — não é dado** | Tile grid 28x28 (1572B fixo), header `03 00`/`01 00`, células `00 01`/`00 00`. Máscara de walkability. |
| 4 .dt | ⚙️ | **identificado — sprite frames** | Magic `06 00 00 00`. Animation/frame table. Não tabular. |
| 5 buffs/efeitos | 🔴 | **✓ FEITO — defined_influences.csd** | 285 buff descriptions (Aumenta em X% ...). |
| 6 items | ⚙️ | **✓ FEITO EM ESCALA** | 20+ arquivos de items, 20.000+ names. |
| 7 quests | ⚙️ | **✓ FEITO** | 4866 quests via INI UTF-16 parser. |
| 8 varredura | 🔍 | **✓ FEITO** | 160 files sobrantes identificados. Parseáveis restantes marcados; resto é sprite/áudio/config. |

### Pendências específicas

- **HP de mobs** — não encontrado. Hipóteses:
  - HP calculada por formula server-side (base * level^k)
  - HP nunca é enviada como valor; cliente lê via update de HP no stream
  - Alternativa: procurar em `monster/{id}.dt` (sprite files) OU no server-side
    (não distribuído no pak)
  - Próxima tentativa: captar pcap ao spawnar Manequim e ver se HP inicial
    trafega no protocolo (não no pak)
- **Sub-registros skills.csd** — TLV aninhado, magic pai `08 84 02`, filho
  `08 db 03`, level sub-blobs de tamanho variável dentro. Vale próxima rodada
  se prioridade continuar alta. Padrão de investigação: pegar UMA skill com
  ground truth (ex.: uma skill que faz 500 dmg no nível 1), procurar 500 u16
  dentro do body dessa skill, mapear offset.
- **`monster_data_v2.dat`** — 418.620 bytes idênticos em tamanho a `monsters.dat`
  mas com um u16 diferente por record (byte 6-7 do 20B record). Valores 0-13,
  não é HP. Possível "categoria de spawn" ou "family flag". Não priorizado.
- **`territories.csd`** (não parseado) — pequeno, provável mesmo padrão dos
  zones/sectors. Rápido de adicionar quando precisar.
- **Items menores** (`craft_items.csd`, `rune_items.csd`, `crystal_items.csd`,
  `summon_items.csd`, `skill_book_items.csd`, `skill_amplifier_items.csd`,
  `spawn_object_items.csd`) — mesmo padrão, mesma função `ParseItemFile` só
  precisa do par de bytes magic de cada. Baixa prioridade — não afeta decoder.
- **Quests** (4.904 INI UTF-16 em `quests/pt/`) — parser INI + resolver
  quest_id → nome. Útil pra eventos de quest no protocolo mas fora do escopo
  atual (rastreamento por HP).

## 7. Como regenerar

```
build-datamine.bat
ws-datamine.exe --in pak-out --out data
```

## 8. Extensão futura do Datamine.cs

Modelo pra próxima adição:

```csharp
// Add parser:
static Dictionary<string,string> ParseX(string path, Dictionary<int,string> strings) {
    // 1. hexdump primeiros 32B pra achar magic
    // 2. procurar name_keys válidos (u32 in strings dict) em offsets fixos
    // 3. testar tamanho de record = filesize/N
}

// Add to Main:
Console.WriteLine("[datamine] Parsing X ...");
var x = ParseX(Path.Combine(pakDir, "X.csd"), strings);
WriteJson(Path.Combine(outDir, "x-names.json"), x);

// Expose via GameData.cs:
static readonly Dictionary<int,string> _x = new Dictionary<int,string>();
LoadFlatStringMap("x-names.json", ...);
public static string XName(int id) { ... }
```
