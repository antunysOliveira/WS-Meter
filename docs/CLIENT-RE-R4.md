# CLIENT-RE-R4.md — Rodada 4: busca do consumer do blob do tag=492

**Data:** 2026-09-21. Escopo: leitura estática read-only.

## Objetivo declarado

Achar a função do cliente que CONSOME os `count` bytes armazenados pelo
reader do tag=492 (FUN_00632670).

## Correção de premissa da rodada 3

A rodada 3 afirmou "conteúdo é TLV recursivo com mesmas classes da factory".
[INFERIDO] não confirmado pelo código. Falsificado pelo teste V2 nesta rodada.

## Regras de rotulagem

- **[LIDO NO CÓDIGO]** — descompilação com endereço da função
- **[INFERIDO]** — dedução não confirmada
- **[MEDIDO]** — resultado empírico sobre dumps

---

## Rota 1: vtable do 492 além do slot [6]

**[LIDO NO CÓDIGO]** vtable @ 0xc0e3e0, script `re/Consumer492.java`:

Layout (endereços absolutos da .rdata):
```
0xc0e3d4 [-3] = 0x636d20 (not func)
0xc0e3d8 [-2] = 0x636ce0 destructor
0xc0e3dc [-1] = 0x636c90 destructor
0xc0e3e0 [0]  = 0x440960 base helper
0xc0e3e4 [1]  = 0x632660 getTag (returns 492)
0xc0e3e8 [2]  = 0x632730 init
0xc0e3ec [3]  = 0x6326e0 serialize
0xc0e3f0 [4]  = 0x632670 deserialize
0xc0e3f4 [5]  = 0x440a00 destructor
```

Slots [6..9] retornam à OUTRA classe (tag=499) cuja vtable começa em
0xc0e3f8. Adjacência em .rdata, mas classe separada:
- slot [6] = 0x631cd0 → getTag returns 499
- slot [7] = 0x631ec0 → init variant
- slot [8] = 0x631e60 → poly-array serializer stride 76B
- slot [9] = 0x631ce0 → poly-array deserializer stride 76B

**[LIDO]** A classe do tag=492 tem SÓ 5 slots virtuais (getTag/init/serialize/
deserialize/destructor). NÃO existe `handle()`, `execute()`, `onReceive()`
ou `apply()` como método virtual da classe.

**Conclusão da rota 1:** consumer do blob não é método virtual da classe 492.

## Rota 2: xrefs ao campo byte-array da classe

**[LIDO]** Reader FUN_00632670 chama `FUN_00432da0(param_1 + 1)` (this+4).
FUN_00432da0 armazena data pointer em `target+8` = this+0xc.

Layout inferido do objeto 492 (24B alocado por factory):
```
+0    vtable ptr
+4    (byte-array struct base)
+8    (byte-array size)
+0xc  data pointer  ← BLOB stored here
+0x10 (byte-array capacity)
+0x14 u32 trailer
```

**[NÃO EXECUTADO]** Xrefs ao offset +0xc de um objeto 492 requerem
type-info que Ghidra não possui. Grep manual seria caro sem indexação
por type. Rota abortada.

## Rota 3: callers de FUN_00447b30 (poly-obj-array reader)

**[LIDO]** ReferenceIterator no Ghidra retornou apenas:
```
caller: FUN_0062bcf0 (tag=551 class deserialize) x 2
```

Nada relacionado ao 492. **Rota descartada.**

## Rota 4: callers da factory FUN_006685d0

**[LIDO]** ReferenceIterator retornou **zero callers diretos**. Factory
é invocada via function pointer / vtable indireta que Ghidra não
consegue rastrear estaticamente.

Também busquei callers de FUN_005fd1c0 (varint reader). Retornou 30+
callers, todos são funções utilitárias em faixa 0x432xxx-0x442xxx
(helpers de leitura por tipo). O CALLER DE ALTO NÍVEL do factory
(recv path do socket) não fica visível por essa rota.

**Rota 4 sem retorno útil.**

## Rota 4B: callers de FUN_00432d40/FUN_00432da0 (byte-array writer/reader)

**[LIDO]** FUN_00432da0 (reader) tem ~30 callers, todos em classes de
mensagem específicas — cada uma que armazena um byte-array. Não é o
consumer que buscamos.

FUN_00432d40 (writer) tem callers similares.

## Ctor do 492 e função afim

**[LIDO]** FUN_00632770 — ctor default:
```c
undefined4* FUN_00632770(undefined4 *param_1) {
    *param_1 = &PTR_FUN_00c0e3e0;
    param_1[2] = 0;
    param_1[3] = 0;
    param_1[1] = param_1[3];   // = 0
    param_1[4] = 0;
    param_1[5] = 0;
    return param_1;
}
```

**[LIDO]** FUN_00632750 — destructor helper:
```c
void FUN_00632750(undefined4 *param_1) {
    *param_1 = &PTR_FUN_00c0e3e0;
    FID_conflict__free((void *)param_1[3]);   // frees byte-array data
    *param_1 = &PTR__scalar_deleting_destructor__00c0b3e4;
    return;
}
```

Destructor libera `param_1[3]` = this+0xc = data pointer. Confirma que
data ptr é armazenada no offset +0xc.

## Sumário — rotas tentadas nesta rodada

| rota | resultado |
|---|---|
| 1: slots vtable 492 além [6] | classe 492 tem apenas 5 métodos virtuais, nenhum handle/execute/apply |
| 2: xrefs ao campo +0xc do objeto 492 | não executável estaticamente sem type-info |
| 3: callers FUN_00447b30 (poly-array) | só usado por tag=551 class |
| 4: callers factory FUN_006685d0 | zero callers diretos (invocação indireta) |
| 4B: callers FUN_00432d40/da0 | trivialmente todos os byte-array holders |

## Sub-header do content — hipóteses testáveis (não fechadas)

Amostras coletadas de wire tag=492 bodies (rodada 3, `re/dump_492_body`):

```
msg #17 content[0..1] = "f0 02"    varint = 2<<7 | 0x70 = 368
msg #52 content[0..1] = "f6 07"    varint = 7<<7 | 0x76 = 1014
msg #34 content[0..1] = "c0 55"    varint = 85<<7 | 0x40 = 10944
                                   OU c0 é 1 byte com bit continuação
msg #43 content[0..2] = "c1 d3 04" varint = 4<<7 | 0x53 = ... complicado
```

**[NÃO CONFIRMADO]** Se cada content começa com um varint header:
- msg #52: 1014 — não é tamanho do conteúdo (104) nem count observado
- msg #34: 10944 — bem maior que content len 318
- msg #17: 368 — próximo do content len 103? não

Nenhuma correspondência clara com valores estruturais. Hipótese "é um
varint discriminador" precisa validação de código.

## Regra de parada

Consumer do blob **não localizado** por 4 rotas. Rota 2 requer type-info
não disponível estaticamente. Rota 4 requer análise dinâmica (chamadas
indiretas via function pointer).

**Ações tomadas:**
- V2 continua dormant em `src/TlvDamageDecoderV2.cs`
- Fase 8D permanece intacta
- Src/ não modificado
- Sem fator de correção aplicado

**Próximas rodadas plausíveis (não executadas):**

1. **Análise dinâmica via LOG do próprio jogo:** o log em
   `C:\Users\antun\AppData\Local\Warspear Online\Warspear_systemlog.txt`
   pode conter traces de processamento — verificar sem correr jogo
2. **Grep textual em Ghidra por strings de erro** nas funções de
   parsing — mensagens tipo "invalid tag" ou similar
3. **Tabela de xrefs de STRING de recurso** — se algum log/exception
   text estiver associado ao consumer, referência textual traz até ele
4. **Import table analysis** — quais funções chamam WSARecv? Trace pra
   frente do recv até o dispatch

Rotas 1-4 originais falharam por razões estruturais (chamadas indiretas,
type erasure no decompile). Novas rotas precisam de infraestrutura
diferente.

## Achados sólidos preservados desta rodada

**[LIDO]** Classe do 492 tem 5 métodos virtuais. Nenhum é handle/apply.
**[LIDO]** Data pointer do blob armazenado em this+0xc do objeto 492.
**[LIDO]** Destructor libera the data pointer — objeto tem OWNERSHIP.
**[LIDO]** Factory tem invocação indireta — impossível trace estático
sem indexação de function pointers.
**[LIDO]** Vtable 0xc0e3e0 vs 0xc0e3f4 = classes SEPARADAS (tag 492 vs 499)
adjacentes no .rdata. Não é multiple inheritance.

## Arquivos

- `re/Consumer492.java` (script rota 1+3+4)
- `re/Consumer492b.java` (script rota 1B com secundária)
- `re/consumer492.txt` (output)
- `re/consumer492b.txt` (output)
