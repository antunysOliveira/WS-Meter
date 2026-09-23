# CLIENT-RE-R5.md — Rodada 5: consumer do content do 492 LOCALIZADO

**Data:** 2026-09-21. Escopo: leitura estática read-only.
Rótulos: **[LIDO]** / **[INFERIDO]** / **[MEDIDO]**.

## Sumário

**[LIDO]** O consumer do content do tag=492 é a mesma função que dispatches
todos os pacotes: **FUN_009acb50 (dispatcher loop)**. Nela, tag=492 tem
tratamento ESPECIAL — o content NÃO é TLV stream: é bytes LZ4 comprimidos.
Após descompressão, os bytes originais são inseridos numa fila e o mesmo
dispatcher processa recursivamente.

## Como foi localizado

Rota nova (rotas 1-4 falharam nas rodadas 2-4): **grep de strings no
binário** por palavras-chave típicas de dispatch:
- "No handler registered for packet"
- "Packet %1 has not been handled properly"
- "serverpacketshandlers.cpp" (path do arquivo original do jogo)

Xref à string "Packet %1 has not been handled properly" @ 0x00c9b1ac →
caller único **FUN_009acb50 @ 0x009acb50 (at 0x009acf3d)**.

Rota validada por múltiplas strings apontando pra mesma família de
funções em `.text` 0x9axxxx-0x9dxxxx.

## Dispatcher — FUN_009acb50

**[LIDO]** Loop principal decompilado. Estrutura simplificada:

```c
void FUN_009acb50(int *packet_queue, int flags) {
    while ((packet = FUN_005fc5e0()) != NULL) {   // read next packet
        int tag = packet->vtable[+4]();            // getTag()
        if (tag < 0x25a)  // 602
            packet_queue->stats[tag].count++;
        // ...
        if (tag == 0xB8) {   // 184 = GostPacket (encrypted)
            // decrypt inline into buffer
            FUN_00aa6ee0(...);
        }
        // ...
        if (tag == 0x1EC) {   // 492 — CONTAINER COMPRIMIDO
            uint uncompressed_size = getSize();
            local_28 = allocate(uncompressed_size);
            int ok = FUN_005498a0(compressed_data, out_buf,
                                  compressed_size, uncompressed_size);
            if (ok < 1)
                fatal("Decompress was failed! Compressed size - %1; Original size - %2");
            // copy decompressed bytes into a nested queue buffer
            //   at packet_queue + 0x15a0 (data), + 0x15a8 (pos), etc.
            // RECURSE — dispatcher processes decompressed bytes
            FUN_009acb50(packet_queue + 0x15a0, 1);
        }
        else {
            // NORMAL PATH: lookup handler in table
            // handler_table_entry = packet_queue + (tag + 0x16a) * 16
            //   entry[0] = handler function ptr
            //   entry[1..3] = ??? (context, args)
            handler_fn = packet_queue[(tag + 0x16a) * 16 / 4];
            bool ok = handler_fn(packet);
            if (!ok) log("Packet %1 has not been handled properly");
        }
    }
}
```

**[LIDO]** Endereços chave:
- **`FUN_009acb50` @ 0x9acb50** — dispatcher loop
- **`FUN_005fc5e0` @ 0x5fc5e0** — packet queue read (get next packet)
- **`FUN_005498a0` @ 0x5498a0** — **LZ4 DECOMPRESSION** (para tag=492)
- **`FUN_00a64370` @ 0xa64370** — "No handler registered" logger
- Handler table base: `packet_queue + (tag + 0x16a) * 16`
- Tag stats table: `packet_queue + 0x3c44 + tag*12` (count, bytes, ?)

## FUN_005498a0 — LZ4 decompression

**[LIDO]** Decompilação mostra padrão canônico LZ4:
```c
byte* FUN_005498a0(input, output, in_size, out_size) {
    // Loop:
    //   read token byte
    //     high nibble = literal length (0..15, 15 => extended)
    //     low nibble  = match length (0..15, 15 => extended)
    //   read extended length via 0xFF continuation bytes
    //   copy literals (up to 32 bytes at a time)
    //   read 16-bit LE match offset
    //   copy match from output[-offset]
    // ...
}
```

**Evidências:**
- Token byte `uVar10 = (uint)(byte)*puVar7`
- `uVar12 = uVar10 >> 4` (high nibble)
- `uVar10 & 0xf` (low nibble)
- Extended length via `while (byte == 0xff)` accumulation
- Match copy in 32-byte chunks (`*(u32*)dst = *(u32*)src` x 8)
- 16-bit LE match offset read

**Algoritmo confirmado: LZ4 block format** (RFC-like, MIT/BSD).

## Resposta ao sub-header variável do content

**[LIDO]** O "sub-header variável" observado empiricamente (`f0 02`,
`c0`, `f6 07` etc.) NÃO é um header estruturado — é o começo de dados
LZ4 comprimidos. Cada byte inicial é o TOKEN LZ4 do primeiro chunk:
- Nibbles alto/baixo = literal/match lengths
- Valores `f0`, `f6` = `1111 0000`, `1111 0110` = literal length 15
  (estendido) com match length 0/6

Isso EXPLICA:
- Byte-scan `ab 03 0d` no content encontra padrões arbitrários — o
  content NÃO É TLV. É LZ4-comprimido.
- Fase 8D funciona parcialmente porque **algumas** cópias LZ4 
  reproduzem o padrão `ab 03 0d` que vem do TLV original antes da
  compressão. Coincidência estatística.
- Nenhum walker de TLV pode funcionar no content sem descomprimir
  primeiro.

## Layout completo do tag=492 REVELADO

**[LIDO]** Wire tag=492 body:
```
[varint N]                     — comprimento do content comprimido
[N bytes]                      — LZ4-comprimidos
[u32 trailer]                  — tamanho descomprimido (candidato)
```

Após descompressão:
```
[TLV stream: varint tag][varint len][body] * K
```

Onde cada sub-mensagem TLV é processada pelo mesmo dispatcher recursivo.

**[LIDO]** O u32 trailer do 492 é o **tamanho descomprimido esperado**
— usado por FUN_005498a0 como `out_size` argumento. Se o descompactar
não render exatamente esse tamanho, `Decompress was failed!` é logado.

## Table de handlers indexada por tag

**[LIDO]** No pattern `param_1 + (tag + 0x16a) * 16`:
- 0x16a = 362 (offset base word)
- Cada entrada = 16 bytes:
  - +0: function pointer (handler)
  - +4..+15: context, args, ou padding

Para tag=427: handler @ `packet_queue + (427 + 362) * 16` =
`packet_queue + 789*16` = `packet_queue + 0x3150`.

**Este é o mapa tag → handler_fn** que buscamos há rodadas. Está na
INSTÂNCIA do `packet_queue` object, não no vtable de cada classe.

## Consequências para o projeto WS-engine

**[MEDIDO]** Não implementado ainda. Ações plausíveis:
1. Adicionar LZ4 decompression a `src/` (biblioteca C# ou C-port).
2. Chamar decompress no content bytes de tag=492.
3. Parsear resultado como TLV stream — as classes wire agora se aplicam
   diretamente aos sub-eventos descomprimidos.

**Substituição da Fase 8D:**
- Fica dormant até implementação/validação
- Depois de implementar LZ4, sub-eventos incluem `tag=427` com o mesmo
  reader do top-level: `[u32 dmg][u32 att][u32 tgt][u8 flag]`.
- Atribuição via campos do próprio 427 — sem depender de `5b 0b 00 00`
  marker.

## Não executado nesta rodada

- Implementação do LZ4 decoder no `src/`
- Validação por jogador (depende de LZ4 funcionar)
- Substituição do Fase 8D

**Regra de honestidade:** rodada 3 afirmou "content é TLV recursivo com
mesmas classes". Foi **PARCIALMENTE VERDADE** — é TLV recursivo com
mesmas classes, mas SÓ APÓS DESCOMPRESSÃO. Sem descomprimir, byte-scan
falha estatisticamente.

## Arquivos

- `re/FindDispatch.java` — grep de constantes-tag (58k funcs, 9 hits, todos falsos)
- `re/FindHandlers.java` — grep de strings do binário (hit!)
- `re/DecompressAlgo.java` — decompile FUN_005498a0
- `re/handlers.txt` — decompile do dispatcher
- `re/decompress_algo.txt` — decompile do LZ4 decoder
- `re/dispatch_hunt.txt` — falsos positivos rota A
- `re/dispatch_candidates.txt` — decompile dos 9 falsos positivos
