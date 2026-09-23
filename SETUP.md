# Guia de instalação — WS-engine

Passo-a-passo pra rodar o WS-engine do zero. ~5-10 min.

---

## 1. Instalar o Wireshark + Npcap

O programa usa o `dumpcap.exe` do Wireshark pra capturar os pacotes do jogo.

1. Baixar o instalador em: **https://www.wireshark.org/download.html**
2. Rodar como Administrador.
3. **IMPORTANTE**: na tela **"Choose Components"**, deixa marcado tudo. Na tela **"Install Npcap"** clica no botão pra instalar o Npcap. Deixa as opções padrão. Ou baixe separado em https://npcap.com/#download
4. Terminar a instalação normal.
5. **Reiniciar o PC** — o driver do Npcap precisa disso.

Pra conferir se ficou OK: abre um CMD e roda `dumpcap -D`. Deve listar suas placas de rede. Se der erro dizendo que Npcap não tá instalado, reinstala.

---

## 2. Verificar o WebView2 Runtime

O painel do WS-engine é renderizado dentro de uma janela Chromium (WebView2).

- **Windows 11**: já vem instalado. Pula esse passo.
- **Windows 10 21H1+**: normalmente já vem. Se o WS-engine abrir e reclamar de "WebView2 Runtime ausente", baixa aqui:
  https://developer.microsoft.com/en-us/microsoft-edge/webview2/#download
  Escolhe **"Evergreen Standalone Installer"** → **"x86"** ou **"x64"** de acordo com seu Windows.

---

## 3. Extrair o WS-engine

- Extrai/copia a pasta inteira do WS-engine pra qualquer lugar do PC.
  - Ex.: `C:\Games\WS-engine\` ou `Documentos\WS-engine\`.
- **NÃO precisa** ficar dentro da pasta do Warspear.
- Precisa manter TODOS os arquivos juntos (não apaga DLL, não apaga pasta `assets`).

Estrutura esperada:
```
WS-engine\
├── WS-engine.exe          ← duplo-clique aqui
├── memscan.exe
├── *.dll                  (5 arquivos)
├── assets\                (ícones, interface)
├── data\                  (dados do jogo)
└── libs\                  (dependências)
```

---

## 4. Rodar

1. Abre o **Warspear Online** como Administrador (botão direito → "Executar como administrador"). Loga com seu char.
2. Duplo-clique em **`WS-engine.exe`**.
3. Aceita o UAC (pede admin porque precisa capturar rede e ler memória do jogo).
4. Aparece uma janela escura com abas **LUTA** / **JOGADORES**.
5. O contador "capturando" no topo fica verde pulsando = tá funcionando.
6. Entra em combate — a tabela preenche em ~1-2 segundos.

---

## 5. Adicionar exceção no antivírus (opcional)

O WS-engine pode ser flagado por antivírus (Windows Defender, Avast, Kaspersky) porque:
- É `.exe` sem assinatura digital.
- Pede admin.
- Lê tráfego de rede e memória de outro processo.

Isso é cara de trojan pra AV, mesmo não sendo. Se o AV bloqueia:

**Windows Defender:**
1. Configurações → Privacidade e segurança → Segurança do Windows → Proteção contra vírus e ameaças.
2. Gerenciar configurações → Exclusões → Adicionar uma exclusão → Pasta.
3. Escolhe a pasta do WS-engine.

---

## Problemas comuns

### "dumpcap.exe not found in the configured folder"

- Wireshark não foi instalado no caminho padrão. Reinstale em `C:\Program Files\Wireshark\` (padrão do instalador).
- Ou: abre o arquivo `ws-engine.config.json` (criado no primeiro run) e edita `"wiresharkDir"` pro caminho onde está o `dumpcap.exe`.

### "Sem interfaces" / captura não pega nada

- Escolha da interface de rede errada. Ao rodar, o programa auto-detecta o adaptador que tá com internet. Se você usa VPN ou tem várias placas, pode escolher a errada.
- Fecha o programa, apaga o arquivo `ws-engine.config.json` (mesma pasta do `WS-engine.exe`) e abre de novo pra re-detectar.

### Programa abre mas fica só "Parado"

- Warspear precisa estar rodando. O programa auto-detecta quando o jogo abre.
- Se o Warspear já tá aberto e mesmo assim não pega:
  - Confere se o Warspear foi aberto como Administrador (botão direito → Executar como admin).
  - Confere se o WS-engine tá também como Administrador (deveria ter aparecido UAC ao abrir).

### Nomes/classes não aparecem

- Precisa esperar alguns segundos. O nome vem de várias fontes:
  - Chat: aparece assim que alguém falar.
  - Placar de instância: só no fim da instância.
  - Memória do jogo: em 5-10 segundos após entrar na sua área.
- Pra forçar renome manual: botão direito na linha do jogador → "Renomear...".
- Icons de classe: se ficar "?" pra sempre, é sinal que a memória do jogo mudou de layout (patch novo). Aguarda update do programa.

### Icons de buff aparecem estranhos ou faltam

- Confere se a pasta `assets/buff-icons/` tem 3 PNGs: `pocao.png`, `pergaminho.png`, `comida.png`.
- Se sumiu, recopia da pasta original.

### WebView2 "não encontrado"

- Baixa e instala o Runtime: https://developer.microsoft.com/en-us/microsoft-edge/webview2/#download
- Escolhe **"Evergreen Standalone Installer"** compatível com seu Windows (x86 ou x64).
- Reabre o WS-engine.

### Números do meter parecem baixos comparados ao placar do jogo

- O placar oficial do Warspear inclui dano de vários eventos que o programa filtra (bosses vs adds, curas parciais). Diferença de ~5-10% é esperada.
- Se a diferença for grande (metade ou menos), pode ser que a captura começou no meio da luta. Fecha o programa, começa a luta do zero, abre o programa antes.

### Como recomeçar do zero?

Apaga esses arquivos (ficam ao lado do `WS-engine.exe`):
- `ws-engine.config.json`
- `ws-engine.db`
- `ws-engine.mem-*.json`
- `ws-engine.nicknames.json`
- `ws-engine.me.txt`
- pasta `captures/`

Reabre.

---

## Como parar tudo e desinstalar

1. Fecha o WS-engine (X na janela). Ele encerra o `dumpcap.exe` automaticamente.
2. Confere no Gerenciador de Tarefas que não sobrou `dumpcap.exe` ou `memscan.exe` rodando.
3. Apaga a pasta do WS-engine.
4. Se quiser tirar tudo: desinstala o Wireshark pelo Painel de Controle.

Pronto.
