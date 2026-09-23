# People-in-area — plano de investigação

Objetivo: substituir a contagem heurística atual (tag=25 + janela de 60s
+ faixa de ID) por estado real de entidades — spawn insere, despawn
remove, troca-de-zona limpa. Vale para jogadores E mobs.

## Estado atual

Contagem atual:
- Alimentada por `tag=25` observado no top-level.
- Janela deslizante de 60s: se um ID reapareceu nos últimos 60s, conta.
- Faixa de ID (`0x00xxxxxx` = player, resto = mob) para classificar.

Problemas:
- Janela temporal esconde saída real de jogador (fica contando 60s a mais).
- Faixa de ID falha em `0x03/07/09/0C/10/57xxxxxx` (mobs de raid).
- Nada limpa ao trocar de zona.
- Provavelmente as mensagens de spawn/despawn moraram dentro do `tag=492`
  descomprimido, como os nomes moraram antes de Fase 8B.

## O que precisamos descobrir

1. **Tag de spawn** — mensagem que aparece quando uma entidade entra
   na área do observador. Deve conter o `entity_id`.
2. **Tag de despawn** — mensagem que aparece quando uma entidade sai
   da área. Também com `entity_id`.
3. **Tag de troca de zona** — mensagem que zera a lista (o servidor
   sabe que o cliente vai limpar tudo).
4. **Reader** de cada tag (Ghidra na factory `FUN_006685d0`):
   - Tipo de entidade (player/mob/pet/NPC) — se existir, substitui a
     heurística de faixa de ID em TODO o programa.
   - `type_id` de mob → ponte para `data/mob-types.json` → nome.
   - HP atual/máximo (para overheal fica exato).

## Ferramenta pronta

`WS-engine.exe --probe-ids <pcap> <id_hex_csv>` — código em
`src/ProbeIds.cs`.

Uso (rodar num shell elevado, exe requer admin):
```
WS-engine.exe --probe-ids captures\ws_2026xxxx.pcapng 0x00692DA2,0x006ABCDE,0x006F1234
```

Saída (arquivo `<pcap>.probe-ids.txt` + stdout):
```
ID 0x00692da2  (147 hits)
  FIRST:  t=+12.345s  tag=25  top-level  msg#147  bodyOff=8  bodyLen=5
  LAST :  t=+1834.6s  tag=427 492-body   msg#8102 bodyOff=8  bodyLen=13
  tags: tag=25×43  tag=427×12  tag=99×8  ...
  body-lens (top 5 tags): tag=25 [5,5,5,...] tag=427 [13,13,...]  ...
--- cross-ID FIRST-hit tag frequency (spawn candidates) ---
  tag=25 → 4 ids
  tag=X  → 1 ids
--- cross-ID LAST-hit tag frequency (despawn candidates) ---
  tag=Y → 3 ids
  tag=25 → 2 ids
```

O relatório é ruidoso — u32 casa por acaso em floats/coords. Mas quando
você roda com 3-5 IDs, a mesma tag aparece como FIRST-hit em todos eles.
Essa é a tag de spawn. Idem para LAST-hit = despawn.

## Passos para o usuário

1. **Preparar captura**:
   - Parar todas as capturas.
   - Iniciar captura vazia.
   - Entrar numa cidade movimentada (Nadir, por exemplo).
   - Ficar parado 60-120s deixando gente entrar/sair da área.
   - Andar 5-10 tiles pra forçar spawn/despawn extra.
   - Trocar de zona (portal ou teleporte).
   - Parar captura.

2. **Escolher IDs** (SQLite `ws-engine.db`):
   ```
   sqlite3 ws-engine.db "SELECT DISTINCT src_entity_id FROM damage_events WHERE session_id = <ultima> LIMIT 10;"
   ```
   Ou `ws-engine.mem-players.json` (dump memscan).

3. **Rodar probe**:
   ```
   WS-engine.exe --probe-ids captures\<arquivo>.pcapng 0xID1,0xID2,0xID3,0xID4,0xID5
   ```

4. **Enviar `.probe-ids.txt` de volta** — com esse arquivo eu identifico
   as tags de spawn/despawn/zona.

## Depois de identificado

Fluxo esperado (a implementar):

- `src/EntityStateTracker.cs` (novo): consome eventos TLV; mantém
  `Dictionary<uint, EntityInfo>` da área do observador.
  - `Insert(id, kind, typeId, hp, maxHp)` no spawn.
  - `Remove(id)` no despawn.
  - `Clear()` na troca de zona.
- `EntityInfo.Kind` substitui a heurística de faixa de ID em
  `WS-engine.cs` (busca por `IsWarspearId`, `0x00xxxxxx`, `Classify`).
- `Database` armazena eventos spawn/despawn por sessão para replay.
- UI: dois números novos no topo — **N jogadores** / **N mobs**.

## Ghidra — factory `FUN_006685d0`

Deixado para depois — dependendo da tag identificada, extrair o reader
correspondente. Scripts em `re/`:
- `re/DecompileFactory.java` — já existe, decompila a factory inteira.
- Após identificar tag=X, escrever `re/DumpReader<X>.java` que segue o
  ponteiro do switch case correspondente e imprime o reader.

Documentação usará marcadores `[LIDO]` (extraído da factory),
`[INFERIDO]` (deduzido de comportamento) e `[MEDIDO]` (via captura).
Sem padrão de bytes, sem fator de correção.
