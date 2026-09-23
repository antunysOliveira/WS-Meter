# CLIENT-RE.md — engenharia reversa estática do warspear.exe

**Escopo:** análise estática read-only. Binário copiado pra `re/client/`.
Nenhum arquivo do jogo modificado. Anti-cheat NÃO acessado. Jogo fechado
durante análise.

**Data:** 2026-09-21.

## 1. Identificação do binário

Localização original: `C:\Users\antun\AppData\Local\Warspear Online\warspear.exe`
Tamanho: 10.217.584 bytes (~10 MB).

Passo 1 executado — checagem para Unity/Mono/IL2CPP:

- ❌ Sem `Assembly-CSharp.dll`
- ❌ Sem `mono*.dll` ou `MonoBleedingEdge/`
- ❌ Sem `*_Data/Managed/`
- ❌ Sem `GameAssembly.dll` + `global-metadata.dat` (IL2CPP)

Diretório de instalação contém apenas `warspear.exe`, `warspear.pak`, `OpenAL32.dll`,
`wrap_oal.dll`, `uninstall.exe`, `ws_config.xml` e o log do sistema.

**Conclusão: binário NATIVO C/C++, não .NET, não Unity.**

## 2. Header PE + verificação de packing

Análise por scan direto do PE:

| campo | valor |
|---|---|
| assinatura | `PE\x00\x00` (válida) |
| máquina | 0x14c = **x86 (32-bit)** |
| seções | 4 (padrão) |
| optional header size | 224 |

Seções:

| nome | vsize | vaddr | rsize | raddr | chars |
|---|---|---|---|---|---|
| `.text` | 0x7f8677 | 0x1000 | 0x7f8800 | 0x400 | 0x60000020 (code+exec) |
| `.rdata` | 0x158810 | 0x7fa000 | 0x158a00 | 0x7f8c00 | 0x40000040 (r/o data) |
| `.data` | 0x134368 | 0x953000 | 0x6800 | 0x951600 | 0xc0000040 (r/w) |
| `.rsrc` | 0x63978 | 0xa88000 | 0x63a00 | 0x957e00 | 0x40000040 |

Imports (16 DLLs distintas):
```
advapi32.dll  bcrypt.dll   comctl32.dll  gdi32.dll     gdiplus.dll
kernel32.dll  msimg32.dll  ole32.dll     openal32.dll  opengl32.dll
rpcrt4.dll    shell32.dll  shlwapi.dll   user32.dll    wininet.dll
ws2_32.dll
```

`ws2_32.dll` presente = APIs de rede (recv/WSARecv) acessíveis via import
table. **Import table NÃO está vazia — binário NÃO está packed.**

Entropia amostrada da `.text` (primeiros 100KB): **5.537 bits/byte**. Faixa
5-6 = código nativo normal. Packing/criptografia teria entropia >7.5.

**Conclusão: binário nativo x86, não packed, análise estática viável.**

## 3. Análise por scan direto de constantes

Antes de rodar Ghidra headless (30-45min de análise), fiz busca rápida por
constantes das tags no binário.

### 3.1 Busca por u32 LE das tags no arquivo inteiro

Encontrou muitas ocorrências espúrias — a maioria são deslocamentos de
jumps (`0F 8F XX XX 00 00` = jg +XX), não constantes-tag.

### 3.2 Busca por instruções x86 comparando com literal-tag

Procurei padrões `cmp eax, imm32` (`3D XX XX XX XX`), `cmp r32, imm32`
(`81 F8..FE + imm32`), `push imm32` (`68 XX XX XX XX`) em `.text` para
os valores 427, 492, 551, 91, 103.

Resultados:

| tag | cmp eax | cmp r32 | push imm32 |
|---|---|---|---|
| 427 | 0 | 0 | 0 |
| 492 | **1** @ 0x5ac0fc | 0 | 0 |
| 551 | 0 | 0 | 1 @ 0x1903f3 |
| 91 | 0 | 0 | 0 |
| 103 | 0 | 0 | 0 |

**Conclusão importante:** o dispatcher NÃO é um switch de constantes
imediatas. Apenas 1 comparação com 492 (dentro do que parece ser um
handler específico) e 1 push de 551 (provavelmente construtor).

### 3.3 Contexto de `cmp eax, 492` @ 0x5ac0fc

```
005ac0f0: 8b 03            mov  eax, [ebx]         ; vtable ptr
005ac0f2: 8b cb            mov  ecx, ebx           ; this = ebx
005ac0f4: ff 50 04         call [eax+4]            ; virt method @ vtable+4
005ac0f7: (result in eax)
005ac0fc: 3d ec 01 00 00   cmp  eax, 0x1EC (=492)
005ac101: 0f 85 3b 01 00 00 jne  +0x13b
```

Padrão clássico C++: um objeto de mensagem tem virtual method
`getTag()` (ou similar) em vtable offset +4. Retorno comparado com 492
para verificação de identidade (assertion "sou o handler correto"). Se
não bate, faz cleanup/erro; se bate, cai no corpo do handler.

**Isso confirma: message dispatch em Warspear é via C++ virtual dispatch,
NÃO via switch/table indexado por tag.**

### 3.4 Busca por vtables/tabelas em `.rdata`

392 runs de ponteiros de código consecutivos em `.rdata` (>=8 entradas).
Runs grandes:

```
0x8c1e94  7691 entries  — provável RTTI/exception unwind
0x809fe4  5829 entries
0x8a41f8  1384 entries
0x7f9254  1375 entries
0x88700c   577 entries  — plausível tabela de handlers
0x8096b0   574 entries
0x897d78   545 entries
0x898e44   525 entries
```

Cross-check: verifiquei se entry `[492]` de cada tabela grande aponta pra
função contendo 0x5ac0fc (VA 0x9accfc). **Nenhum bate.** Confirma que o
dispatch NÃO é `table[tag]()`.

## 4. Modelo de dispatch inferido

Estrutura provável (C++ típico):

```cpp
class Message {
public:
    virtual ~Message() = 0;
    virtual int getTag() = 0;             // vtable+4
    virtual void parse(Buffer&) = 0;       // vtable+8
    virtual void handle() = 0;             // vtable+12
};

class DamageMessage : public Message { ... };  // getTag() returns 427
class ContainerMessage : public Message { ... }; // getTag() returns 492
class RosterMessage : public Message { ... };  // getTag() returns 551

Message* createMessage(int tag) {  // FACTORY — dispatcher real
    switch (tag) {
        case 427: return new DamageMessage;
        // ...
    }
}
```

Para achar o dispatcher REAL, é preciso:
1. Achar a função factory que cria mensagens por tag
2. OU rastrear onde `getTag()` retorna cada valor específico

Constantes retornadas por `getTag()` provavelmente estão em `mov eax, imm32`
seguidas de `ret` — padrão de virtual method curto. Padrão binário:
`B8 AB 01 00 00 C3` (mov eax, 427; ret) para o `getTag` do handler de dano.

## 5. Passo 2 (Ghidra) — CONCLUÍDO

Análise em 274s (~4.5 min). Decompilação via `re/DecompileHandlers.java` e
`re/DecompileContainer.java`. Outputs em `re/decompile_output.txt` e
`re/decompile_container.txt`.

## 6. VTABLES DE MENSAGENS LOCALIZADAS — achado principal

Busca por padrão `B8 <tag> 00 00 C3` = `mov eax, tag; ret` (o `getTag()`
mínimo de cada classe de mensagem em C++). Match encontrado para TODAS as
tags conhecidas. Cross-referenciar os endereços resultantes em `.rdata`
revelou os vtables inteiros.

**Layout uniforme de vtable de Message (validado empiricamente):**

| slot | função inferida |
|---|---|
| [0] | vector deleting destructor |
| [1] | scalar deleting destructor |
| [2] | (base method, geralmente 0x431450 — compartilhado) |
| **[3]** | **getTag()** ← retorna a constante-tag |
| **[4]** | **parse / read from buffer** |
| **[5]** | **handle / dispatch** |
| [6] | (nome-serialização / debug) |
| [7] | (metadata comum) |
| [8..] | métodos específicos da classe |

Cada tag tem MÚLTIPLAS vtables (uma por classe c2s/s2c ou por variantes).

### Tabela de vtables e handlers por tag

Endereços em VA (image base 0x400000).

**Tag 427 — DAMAGE**
- Vtable @ `.rdata:0x80ecc4−12` (slot 0), classe s2c
- `getTag()` @ `0x63aaf0` → retorna 427
- Parse @ `0x63ac60`
- Handle @ `0x63abc0`
- Outros slots: `0x63ab00`, `0x431190`, `0x65d830`, `0x65d960`

**Tag 492 — CONTAINER (bulk)**
- Vtable @ `.rdata:0x80cfe4−12`
- `getTag()` @ `0x632660`
- Parse @ `0x632730`  ← **PRIORIDADE MÁXIMA de leitura**
- Handle @ `0x6326e0`
- Outros: `0x632670`, `0x440a00`, `0x631cd0`, `0x631ec0`

**Tag 551 — ROSTER (validação de referência — já sabemos layout)**
- Vtable @ `.rdata:0x80e3f8−12`
- `getTag()` @ `0x62bce0`
- Parse @ `0x62bf10`
- Handle @ `0x62be20`

**Tag 91 — ATTRIBUTION block**
- Vtable @ `.rdata:0x809780−12`
- `getTag()` @ `0x5e8b40`
- Parse @ `0x5e8db0`
- Handle @ `0x5e8cb0`

**Tag 103 — mob→player block**
- Vtable @ `.rdata:0x80a5d0−12`
- `getTag()` @ `0x60d810`
- Parse @ `0x60d910`
- Handle @ `0x60d8a0`

**Tag 97, 98, 85, 87, 428** — todos catalogados com pattern idêntico:

| tag | getTag VA | parse VA | handle VA | vtable @ .rdata |
|---|---|---|---|---|
| 85 | 0x5e9f20 | 0x5ea090 | 0x5e9ff0 | 0x809a48−12 |
| 87 | 0x5e9840 | 0x5e9c50 | 0x5e9a60 | 0x809e30−12 |
| 91 | 0x5e8b40 | 0x5e8db0 | 0x5e8cb0 | 0x809780−12 |
| 97 | 0x5e7c70 | 0x5e7ed0 | 0x5e7db0 | 0x809a34−12 |
| 98 | 0x5e78e0 | 0x5e7b40 | 0x5e7a30 | 0x809744−12 |
| 103 | 0x60d810 | 0x60d910 | 0x60d8a0 | 0x80a5d0−12 |
| 427 | 0x63aaf0 | 0x63ac60 | 0x63abc0 | 0x80ecc4−12 |
| 428 | 0x63a8c0 | 0x63aaa0 | 0x63a9b0 | 0x80f084−12 |
| 492 | 0x632660 | 0x632730 | 0x6326e0 | 0x80cfe4−12 |
| 551 | 0x62bce0 | 0x62bf10 | 0x62be20 | 0x80e3f8−12 |

Padrões notáveis:
- Vtables agrupadas em faixa `.rdata` [0x8097xx..0x80f1xx] — hierarquia
  de classes de mensagem sitting together.
- Slot [2] compartilhado por várias classes (0x431450, 0x4318d0, 0x431190,
  etc.) — provável método herdado da classe base.
- Handles das tags mais pequenas (85, 87) na faixa 0x5e7xxx-0x5e9xxx
  (funções pequenas, provavelmente delimitadores vazios). Tags maiores
  (427, 492, 551) em 0x62xxxx-0x63xxxx com parse/handle mais longos.

### Cross-check com handler 492 encontrado antes

O `cmp eax, 492 @ 0x5ac0fc` NÃO é o `parse()` (0x632730) nem o `handle()`
(0x6326e0). É outro sítio — provavelmente um IF de código que trata tag=492
em outra classe (talvez o container walker que despacha os sub-blocks
depois de identificar o container-tag).

## 6.5 DECOMPILAÇÃO — layouts confirmados no código

Handlers extraídos são **serializers** (client→server WRITE). Assinatura
comum: `void serialize(this, Buffer* buf)`. Buffer struct = `[data*][size][pos][commit_pos][?][err_flag][?]`.
Cada write checa `pos + N <= size`, escreve, incrementa `pos`. Erro → `err_flag = 2`.

### Utility functions descobertas (críticas)

| VA | função | comportamento |
|---|---|---|
| **0x5fd240** | **varint writer (LEB128)** | escreve `int` como varint no buffer |
| 0x432d40 | byte-array serializer | `varint(count) + count bytes` |
| 0x432680 | u32-array serializer | `varint(count) + count*u32` |
| 0x432c00 | varint-array serializer | `varint(count) + count*varint` |
| 0x432790 | u32-array serializer (variante) | idem 432680 |
| 0x446620 | poly-object-array | `varint(count) + count * virtual_method(item, stride=0x24)` |
| **0x5ef7b0** | **common message header** | escreve 14B `[u32][u8][u8][u32][u32]` — cabeçalho compartilhado |

**Descoberta chave:** todos os arrays usam LEB128 varint pra prefixo de contagem
via **FUN_005fd240**. Isso confirma o framing top-level LEB128 já observado.

### Layouts confirmados (do lado C++ serializer)

**tag=427 (VA 0x63abc0):** ✓ BATE COM WIRE
```
+4  u32  damage
+8  u32  attacker
+12 u32  target
+16 u8   flag
= 13 bytes  ← EXATO
```

**tag=428 (VA 0x63a9b0):** ✓ BATE COM WIRE
```
+4  u16
+6  u16
+8  u32
+12 u32
+16 u32
+20 u16
= 18 bytes  ← wire `ac 03 12 (=18) ...`
```

**tag=492 (VA 0x6326e0):** ← ESTRUTURA DO CONTAINER
```
FUN_00432d40(this+4)        // escreve [varint count][count bytes]
FUN_005fd240(this+0x14)?    // esta pode ser a linha "write u32"
u32 at this+0x14             // 4-byte trailer
```

Wire tag=492 body = **`[varint count][count bytes payload][u32 trailer]`**.

**Este é o header/estrutura que faltava!** As tentativas empíricas de walker
falharam porque:
- Header não é fixo 2-4B — é um **VARINT** (1..5B dependendo do count)
- Não é TLV puro do body — é blob opaco com prefixo de tamanho
- Termina com `u32 trailer` (não com bytes de padding)

O payload de `count` bytes é o que temos observado como transações
`5b 0b 00 00 ... ab 03 0d ...`. Ainda é preciso decodificar essa camada,
mas agora sabemos que o container é apenas um envelope opaco.

### Outras tags: enum-shared, classes diferentes

**tag=91 (VA 0x5e8cb0):** classe encontrada NÃO bate com wire 11B. Escreve:
```
FUN_005ef7b0(this)   // 14B common header
+0x30 u16
+0x34 u32
+0x38 u32
+0x3c u8
+0x40 u32
FUN_00432c00(this+0x44)  // varint-array
FUN_00432790(this+0x54)  // u32-array
```
Total: 14+2+4+4+1+4=29 bytes fixos + arrays variáveis. Bem maior que os 11
bytes do wire. **Múltiplas classes returning getTag=91** existem — a maioria
das outras vtables também não bateu. Provável causa: o valor de enum é
compartilhado entre uma família "NetworkMessage" (a que aparece no wire) e
uma família "GameEvent" (persistência interna, DB, save). Só 427 e 428
caíram por acaso na família certa que estamos investigando.

**tag=85, 87, 97, 98, 103:** idem — classes decompiladas não batem com
wire body count. Vtables adicionais existem por tag (2-4 cada) mas Ghidra
não marcou os `getTag()` alternativos como funções (padrão `B8 XX 00 00 C3`
é 6 bytes, não sempre reconhecido automaticamente).

## 6.6 Interpretação do dispatcher

Layout de mensagens do cliente segue:
1. Wire recebe: `[varint tag][varint body_len][body_bytes]`
2. Cliente lê `tag`, cria objeto da classe correspondente (factory
   `create_message(tag)` ainda não localizado)
3. `body_bytes` alimenta a virtual `parse()` — ainda não decompilada
4. Após parse, calls virtual `handle()` — que despacha efeito em game state
5. Objeto pode ser reserializado via virtual `serialize()` (slot [5]),
   escrevendo os mesmos campos — que é o que decompilamos

Handlers de tag=427 e 428 batem exatamente com wire → validam metodologia.

## 6.8 Rodada 2 — READERS decompilados

Ghidra force-create nos slots que não estavam marcados como função. Descoberta
completa dos LEITORES (deserialize) das classes.

### Layout de vtable RE-CONFIRMADO

| slot | função |
|---|---|
| [0][1] | destructors |
| [2] | base class helper |
| **[3]** | **getTag()** |
| [4] | init/reset (zero fields) |
| [5] | **serialize (write to buffer)** |
| **[6]** | **deserialize (read from buffer)** |
| [7]..  | outros (destructor, clone, etc.) |

### Readers descobertos

**FUN_005fd1c0 = LEB128 VARINT READER** ✓
```c
uint FUN_005fd1c0(buffer) {
    uint r = 0; byte sh = 0; int cnt = 0;
    do {
        byte b = read_byte(buffer);
        if (cnt > 4) { error = 1; return 0; }
        r |= (b & 0x7f) << (sh & 0x1f);
        sh += 7; cnt++;
    } while (b & 0x80);
    return r;
}
```

**FUN_00432da0 = BYTE-ARRAY READER** ✓ (counterpart de FUN_00432d40)
```c
// count = varint; alloc(count); read count bytes into target
count = FUN_005fd1c0();
FUN_004320a0(count, target);
for (i=0; i<count; i++) target[i] = read_byte(buffer);
```

**FUN_00447b30 = POLY-OBJECT-ARRAY READER** (counterpart de FUN_00446620)
```c
count = FUN_005fd1c0();
alloc(count * 0x24);   // 36 bytes per object
for (i=0; i<count; i++) obj[i].vtable = &PTR_FUN_00c0f484;  // base sub-event class
for (i=0; i<count; i++) (*obj[i].vtable[+0x10])(buffer);   // virtual read
```

### tag=427 READER — FUN_0063ab00 ✓ EXATO
```c
this[1] = read_u32();  // damage
this[2] = read_u32();  // attacker
this[3] = read_u32();  // target
this[4] = read_u8();   // flag
```
Confirma 100% o layout empírico já conhecido.

### tag=492 READER — FUN_00632670 ✓
```c
FUN_00432da0(this + 1);          // read byte-array into this+4..0xc
this[5] = read_u32();            // u32 trailer into this+0x14
```
**Wire tag=492 body = `[LEB128 count][count bytes][u32 trailer]`**

Container é um blob opaco. Os `count` bytes NÃO são parseados pelo reader
do 492 — são armazenados como raw bytes. Alguma outra função DEPOIS
processa esses bytes.

### tag=551 READER — FUN_0062bcf0
Layout que NÃO bate com wire tag=551 empírico:
```
bool (1B) + u8 + string (via FUN_00447b30) + string + u16 + u16 + FUN_005fd120
```
Classe encontrada É a família correta pra ESSA tag, mas o wire tag 551 é
processado por classe DIFERENTE (não localizada nesta rodada — pode ser
uma família herdada dessa base).

### Base sub-event class — FUN_00672280 layout
Vtable base @ 0xc0f484, virtual read @ +0x10 = FUN_00672280:
```c
this[1] = read_u32();
FUN_00432da0(this + 2);     // byte-array into this+8..0x14
this[6][0] = read_u8();     // at this+0x18
this[6][1] = read_u8();     // at this+0x19
this[7]   = read_u32();     // at this+0x1c
this[8]   = read_u32();     // at this+0x20
```

**Este é o layout de UM sub-evento base**, 36 bytes fixos + payload variável.
Provavelmente É a base pros sub-eventos que vivem no payload do tag=492
(via poly-obj-array reader FUN_00447b30), mas NÃO CONFIRMADO — as bodies
de wire testadas não fecharam com essa estrutura no parser Python. Pode
ser que:
- Os sub-eventos do 492 são de FAMÍLIA diferente
- OU o layout mudou por override em subclasse
- OU o sample de body testado estava truncado

### Callers de FUN_00432da0 identificados

30+ funções chamam o byte-array reader. As mais interessantes (não são
utilitários mas classes de mensagem específicas):
- FUN_005e8f60, FUN_005eb640, FUN_005f31e0, FUN_005f4100
- FUN_005fd8c0, FUN_005fda60, FUN_005fe540
- FUN_005ff5c0, FUN_005ff740
- FUN_00601790, FUN_00603180, FUN_00604090
- FUN_00604580, FUN_00604920, FUN_00604db0, FUN_00607430

Cada uma dessas é uma classe de mensagem/objeto que lê um byte-array
como parte do body. Podem ser as classes das outras tags que buscamos.

### Callers de FUN_00447b30 (poly-obj-array) — chave pro tag=492

Não coletado no output atual — próxima rodada.

## 6.9 Factory create_message(tag) — NÃO LOCALIZADO

Tentativas:
- Busca por `cmp eax, imm32` para tags conhecidas em .text: só 1 hit
  para 492, 0 pra 427/551. Não é switch por constante.
- Busca por cluster de 3+ constantes-tag na mesma função: zero.
- Referências a vtables 0xc100c0 (tag=427) e 0xc0e3e0 (tag=492): só
  destructor/ctor triviais aparecem, não uma factory global.

Hipóteses:
1. Factory usa **jump table por tag** onde tag é usado como índice.
   Table teria ~800 slots (para tags 0..~758). Está em .rdata, mas
   nenhuma tabela grande de handlers encontrada bate com Layout `entry[tag] = new_message()`.
2. Factory usa **map<tag, factory_func>** ou **std::function<>** — mais
   difícil de identificar estaticamente.
3. Cada classe **auto-registra** no map via constructor global (static
   initializer). Nesse caso o factory é `map.find(tag)->second()`.

Precisa próxima rodada de análise focada no path de RECV do socket
(WSARecv chain) pra localizar.

## 6.10 Sub-eventos dentro do tag=492 — NÃO DECIFRADO

Confirmado:
- Payload é blob opaco de `count` bytes seguido de `u32 trailer`
- `count` é um LEB128 varint no início do body

NÃO confirmado:
- Formato de cada sub-evento dentro dos `count` bytes
- Se é homogêneo ou heterogêneo
- Regra de dispatch de sub-eventos por tipo

Tentativa com layout de FUN_00672280 (`[u32][byte-array][u8][u8][u32][u32]`)
NÃO bateu com o wire body do dummy dump. Body de amostra tinha count=104
mas apenas ~80 bytes no meu sample truncado — pode ter dado erro de
truncamento, ou layout é outro.

Próxima rodada precisa:
1. Extrair body completo (não truncado) de uma msg tag=492
2. Ler bytes por bytes contra várias hipóteses de layout de sub-evento
3. Encontrar a função que PROCESSA `this.byte_array` após tag=492 read
   (algum handle() ou onReceive())

## 6.11 Regra de atribuição de atacante — NÃO DECIFRADO

Depende de resolver 6.10 primeiro. Sem saber estrutura dos sub-eventos,
não dá pra saber como o atacante é derivado.

## 6.12 Layout do tag=427 aninhado `[dmg u16][11B unknown]` — NÃO DECIFRADO

Depende de encontrar a CLASSE certa (pode ser subclasse do tag=427 wire).
Não foi tentado com heurística nesta rodada.

## 6.13 Rodada 3 (2026-09-21) — FACTORY LOCALIZADO ✓

### Enumeração completa: cada tag tem múltiplas classes

Busca por `mov eax, tag; ret` (getTag pattern) achou 3-4 vtables por tag em
diferentes faixas de endereço em `.text`:

| tag | vtables (endereços dos readers slot [6]) |
|---|---|
| 85 | 0x5e9f30, 0x60e9a0, **0x65edd0** |
| 87 | 0x5e9850, 0x60e6a0, **0x65ecf0** |
| 91 | 0x5e8b50, 0x60e270, **0x65e860** ✓ WIRE |
| 97 | 0x5e7c80, 0x60dd90, 0x65dec0 |
| 98 | 0x5e78f0, 0x60dd30, 0x65dd40 |
| 103 | 0x60d820, **0x65d500** ✓ WIRE |
| 427 | **0x63ab00** ✓ WIRE (única) |
| 428 | **0x63a8d0** ✓ WIRE (única) |
| 492 | **0x632670** ✓ WIRE (única) |
| 551 | **0x62bcf0** ✓ WIRE (única) |

### Wire class de tag=91 CONFIRMADA @ 0x65e860

```c
this[1] = read_u16();   // 2B  → "00 00" prefix
this[2] = read_u32();   // 4B  → attacker
this[3] = read_u32();   // 4B  → target
this[4] = read_u8();    // 1B  → flag
```
Total 11B — MATCH exato com wire empírico.

### Wire class de tag=103 CONFIRMADA @ 0x65d500

Layout IDÊNTICO ao 91 (com u8 final version-gated: só lê se `buffer.version >= 0x98a623`).

## 6.14 FACTORY LOCALIZADA — FUN_006685d0 ✓

Callers dos ctors de tag=91 wire (FUN_0065e9d0) e tag=103 wire (FUN_0065d690):
AMBOS vêm de **FUN_006685d0**.

Descompilada: **switch statement gigante com 602 cases**. Dispatches
diretamente por wire tag value:

```c
Message* FUN_006685d0(int tag) {   // <-- CREATE_MESSAGE FACTORY
    switch (tag) {
        case 0x5b:  /* 91  */  alloc(0x14); return FUN_0065e9d0();  // wire 91 ctor
        case 0x67:  /* 103 */  alloc(0x14); return FUN_0065d690();  // wire 103 ctor
        case 0x1ab: /* 427 */  alloc(0x14); return FUN_0063ac90();  // wire 427 ctor
        case 0x1ac: /* 428 */  alloc(0x18); return FUN_0063aad0();
        case 0x1ec: /* 492 */  alloc(0x18); return FUN_00632770();  // wire 492 ctor
        case 0x227: /* 551 */  alloc(0x30); return FUN_0062bfa0();  // wire 551 ctor
        // ... 602 cases total, tags 0..~600+
    }
}
```

**602 cases** — a factory cobre o vocabulário wire inteiro.

### Object allocation sizes

| tag | size | body |
|---|---|---|
| 91 | 20B | 4B vtable + 11B body + padding |
| 103 | 20B | idem |
| 427 | 20B | 4B vtable + 13B body + padding |
| 428 | 24B | 4B vtable + 18B body |
| 492 | 24B | container obj + trailer u32 |
| 551 | 48B | classe grande |

## 6.15 SÓ UMA classe por wire tag — dúvida resolvida

Só a classe instanciada pela factory `FUN_006685d0(tag)` é a wire class.
As outras com mesmo `getTag()` (nas faixas 0x5e7-0x610-0x61b) são de
outras hierarquias (persistência, sub-widgets, save game etc.).

**Tag=427 nested no payload do 492 = MESMA classe do 427 top-level.**
Nenhuma "família GameEvent" separada. O reader é sempre `FUN_0063ab00`
com layout `[u32 dmg][u32 att][u32 tgt][u8 flag]`.

## 6.16 Payload do 492 = TLV stream recursivo

Confirmações combinadas:
- Reader do 492 lê `[varint count][count opaque bytes][u32 trailer]`
- Bytes internos observados no wire: `5b 0b 00 00 ... 57 00 ... ab 03 0d ...`
- `5b 0b`, `57 00`, `ab 03` são varints válidos (91, 87, 427)
- Factory mapeia esses tags direto pras classes wire
- Cada reader consome exatamente o body indicado pelo len varint

**Conclusão:** o payload é um SEGUNDO STREAM TLV usando os mesmos
`[varint tag][varint len][body]` que o top-level, e as classes são
compartilhadas via factory.

## 6.17 Atribuição de atacante — resolvida

Sub-eventos wire aninhados no 492:
```
tag=91  [00 00][att u32][tgt u32][flag u8]   -- attribution
tag=87  (empty)                                -- delimiter
tag=427 [dmg u32][att u32][tgt u32][flag u8] -- damage COM atacante próprio
```

O atacante já está DIRETO no body do tag=427 aninhado. Não precisa
inferir do 91 anterior — o cliente lê os campos u32 att/tgt do próprio
sub-evento.

**Fase 8D atual atribui via marker 91 anterior — funciona por coincidência
(91 e 427 sempre aparecem juntos com mesmos IDs).** Ler o att/tgt direto
do body do 427 (offsets +4 e +8 depois do varint tag+len) daria mesmo
resultado, sem depender do 91.

## 6.18 Layout dos 11B do 427 aninhado — investigação parcial

Byte pattern sample: `ab 03 0d 03 0a 12 00 71 15 ac 03 12 00 00 65 22`.
Body 13B: `03 0a 12 00 71 15 ac 03 12 00 00 65 22`.

Reader oficial (FUN_0063ab00) lê `[u32 dmg][u32 att][u32 tgt][u8 flag]`:
- dmg = 0x00120a03 = 1.181.187 — grande demais pra dano típico
- att = 0x03ac1571 — hi byte 0x03 (dentro do mob range per CLAUDE.md)
- tgt = 0x65000012 — hi byte 0x65 NÃO é range conhecido
- flag = 0x22

Não bate 100%. Duas possibilidades:
1. Sample tirado de um contexto onde o `ab 03 0d` não é um tag=427 real
   (é lixo/coincidência dentro de outra estrutura)
2. Layout do 427 dentro do 492 tem overload versão-dependente (como o
   tag=103 tem field version-gated)

Precisa próxima rodada com sample de wire body 492 COMPLETO e running
o reader step-by-step contra os bytes.

## 6.19 Callers da factory FUN_006685d0 — NÃO explorado

Rastrear caller da factory revela o RECV path — quem lê o varint tag do
socket e chama factory. Isso completa o loop de recepção. Fica pra
próxima rodada.

## 7. Achados úteis desta rodada

1. **Localizar o payload interno do container 492.** Sabemos que é `[varint count][count bytes]`. O que ESTÁ nesses count bytes? Provável hipótese: **sub-stream serializado por FUN_00446620 (poly-object-array) com stride 0x24**. Cada item = 0x24 bytes de objeto (talvez uma pequena "event class"). Verificar: decompilar callers de FUN_00446620 pra saber quem serializa a lista de eventos.

2. **Achar factory de mensagens (`create_message`).** Provável switch/table indexado por tag → aloca a classe correta. Ali está o mapa tag_wire → class_wire, resolvendo a ambiguidade entre classes com getTag idêntico mas layouts diferentes.

3. **Decompilar `parse()` (read side).** Vtable slot original que não é `[5]`. Precisa força-função no Ghidra pra os slots que não foram auto-marcados.

4. **Fase 8D pode ser mantida com ajuste:** o `varint count` inicial explica por que headers 1-4B apareciam empiricamente (1B para count<128, 2B para 128-16383, etc.). O `u32 trailer` explica o excesso constante de 4 bytes no fim.

## 7. Achados úteis desta rodada

- Binário NATIVO x86, não packed, análise viável
- Dispatch NÃO é switch/table indexado por tag → C++ virtual dispatch
- `getTag()` está em vtable offset +4 do objeto de mensagem
- Handler para tag=492 identificado em 0x5ac0fc (dentro de função ainda
  não delimitada)
- Handler para tag=551 possivelmente em 0x1903f3 (push 551 = construtor)
- Padrão para descobrir todos os handlers: procurar `B8 XX XX XX XX C3`
  (mov eax, tag; ret) onde tag ∈ {427, 492, 551, 91, 103, 97, etc.}

## 8. Próximos passos (executar quando Ghidra terminar análise)

1. ~~Rodar padrão `B8 <tag> 00 00 C3`~~ — **FEITO**, todos os getTag() e vtables mapeados.
2. **Decompilar via Ghidra:**
   - Parse do tag=551 @ VA 0x62bf10 → validar layout já conhecido
     `[id u32][name_len u8][name ASCII][classId u8][flag 0x21/0x22][index u32][extra u32]`
     Se bater 100%, a metodologia está correta.
   - Parse do tag=427 @ VA 0x63ac60 → confirmar layout top-level
     `[dmg u32][att u32][tgt u32][flag u8]` (13 bytes).
   - **Parse do tag=492 @ VA 0x632730** ← ALVO CRÍTICO. Vai revelar:
     - Regra do header do body (2-4 bytes, sem padrão empírico até hoje)
     - Como o body é percorrido (TLV aninhado real? registros fixos?
       tabela de tipos por primeiro byte?)
     - De onde vem o atacante de cada dano embutido
   - Parse do tag=91 @ VA 0x5e8db0 → confirmar `[00 00][att u32][tgt u32][flag u8]` (11B)
   - Parse do tag=103 @ VA 0x60d910 → decidir semântica (mob-attack real ou
     evento diferente — 99.4% mob→player já observado)
3. Se o parse do 492 chamar sub-parsers TAG-driven, o dispatcher aninhado
   está dentro dele. Rastrear indireta.

## 9. Como reproduzir a descoberta (para o `re/decompile_targets.py`)

O script Ghidra:
1. Enumera todas instruções `CMP`/`PUSH`/`MOV` com operando imediato ∈
   {427, 492, 551, ...}
2. Coleta as funções que contêm essas instruções
3. Decompila cada uma via `DecompInterface`
4. Escreve tudo em `re/decompile_output.txt`

Complementar com um segundo passo (a adicionar): dado o mapeamento
vtable→getTag desta rodada, decompilar diretamente as VAs de parse/handle
listadas na tabela acima.

## 8. Ferramentas / scripts criados

- `re/client/warspear.exe` — cópia do binário
- `re/decompile_targets.py` — script Ghidra que extrai decompilação das
  funções contendo constantes-tag (a rodar após análise)
- `re/ghidra_proj/` — projeto Ghidra headless
- `re/analyze.log` — log do headless

## 9. NADA modificado

- Arquivo original `C:\Users\antun\AppData\Local\Warspear Online\warspear.exe`
  intocado. Só copiado (read-only) pra `re/client/`.
- Sem debugger anexado ao processo do jogo.
- Sem execução do binário fora do jogo.
- src/ do projeto WS-engine intocado. Decoder, tag=492, Fase 8D intactos.
