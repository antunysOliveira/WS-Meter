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

## O que é transmitido

**Enviado ao backend:**
- Por entidade (`entities` table): `entity_id`, `nick`, `class_id`, `client_id`, `updated_at`
- Por presença (`clients` table): `client_id`, `observer_char_id` (SEU char), `observer_nick`, `version`, `last_seen_at`

**NÃO enviado:**
- Chat, PMs, damage events, buffs, movimentação
- IPs, MAC addresses, hostname
- Conteúdo de pacotes brutos

Se você não quer expor seu char/nick como observador ativo, apague `ws-engine.me.txt`
antes de rodar. Isso força fallback pra GUID anônimo e o `observer_char_id`/`observer_nick`
ficam vazios no heartbeat.
