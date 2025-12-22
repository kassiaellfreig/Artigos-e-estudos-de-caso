
# 📘 SOC All-in-One Lab: Suricata (IDS), Zeek (NSM), Elastic Stack (SIEM) e Wazuh (HIDS) no Kali Purple

🟣 **Baseado em Kali Purple + ferramentas reais de SOC**
🔒 **Foco: Aprender SOC do zero, como analista júnior**

---

## 📌 VISÃO GERAL DA TRILHA

### 🎯 **Objetivo final**

Ao concluir toda a trilha, você será capaz de:

* Montar um SOC funcional all-in-one
* Detectar ataques reais em rede simulada
* Investigar incidentes com logs correlacionados
* Simular o dia a dia de analista SOC Tier 1
* Explicar arquitetura SOC em entrevista técnica

### 🧭 **ESTRUTURA DO MANUAL** (7 partes)

```
PARTE 1 — Fundamentos + Preparação VM ← (esta)
PARTE 2 — IDS: Suricata (detecção de rede)
PARTE 3 — NSM: Zeek (análise de tráfego)
PARTE 4 — SIEM: Elastic Stack (centralização)
PARTE 5 — HIDS: Wazuh (host monitoring)
PARTE 6 — Correlação + Alertas + Playbooks
PARTE 7 — Rotina SOC: Casos reais + automação
```

---

# 🧭 PARTE 1 — Fundamentos + Preparação do Ambiente

---

## 🎯 OBJETIVO DESTA PARTE

Ao final da Parte 1, você terá:

✔ Kali Purple corretamente instalado
✔ Ambiente isolado e seguro
✔ Topologia SOC clara
✔ Conceito real de SOC (não só ferramentas)
✔ Base pronta para integrar IDS, NSM, SIEM e HIDS

> ⚠️ **Nada será instalado “no escuro”**
> Tudo aqui tem **motivo operacional**, como num SOC real.

---

## 🧠 O QUE É UM SOC (SEM ENFEITE)

### SOC (Security Operations Center) é:

> Um **ambiente centralizado** que:

* Coleta eventos
* Detecta comportamentos suspeitos
* Correlaciona dados
* Gera alertas
* Suporta investigação

### 🔗 Um SOC **NÃO é uma ferramenta**

É uma **arquitetura operacional**.

---

## 🧩 COMPONENTES DO NOSSO SOC CASEIRO

| Função          | Ferramenta    |
| --------------- | ------------- |
| IDS (Rede)      | Suricata      |
| NSM (Metadados) | Zeek          |
| SIEM            | Elastic Stack |
| HIDS            | Wazuh         |
| Base            | Kali Purple   |

---

## 🧱 ARQUITETURA GERAL (VISUAL)

```
                  INTERNET (simulada)
                          |
                          |
                   [ Rede de Ataque ]
                          |
        ┌─────────────────┴─────────────────┐
        |                                   |
 [ Máquina Atacante ]               [ Máquina Alvo ]
 (Kali / Metasploit)               (Ubuntu / Windows)
                                             |
                                             |
                                   ┌─────────┴─────────┐
                                   |      KALI PURPLE   |
                                   |-------------------|
                                   | Suricata (IDS)    |
                                   | Zeek (NSM)        |
                                   | Elastic (SIEM)    |
                                   | Wazuh (HIDS)      |
                                   └───────────────────┘
```

📌 **Tudo converge para o Kali Purple**
Ele é o **cérebro do SOC**.

---

## 🖥️ TOPOLOGIA DE LAB (SIMPLIFICADA E REAL)

### Máquinas mínimas recomendadas

| Máquina       | Função   |
| ------------- | -------- |
| Kali Purple   | SOC      |
| Ubuntu Server | Alvo     |
| Kali Linux    | Atacante |

> ⚠️ Se seu hardware for limitado, **o SOC pode rodar sozinho**, mas o aprendizado é menor.

---

## ⚙️ REQUISITOS DE HARDWARE (REALISTAS)

### Kali Purple (SOC)

| Recurso | Mínimo | Ideal    |
| ------- | ------ | -------- |
| CPU     | 4 vCPU | 6–8 vCPU |
| RAM     | 8 GB   | 16 GB    |
| Disco   | 80 GB  | 120+ GB  |

> Elastic Stack **consome RAM**.
> Menos que isso = sofrimento.

---

## 🧰 INSTALAÇÃO DO KALI PURPLE

### 📥 Download

* Site oficial Kali
* ISO: **Kali Purple Installer**
* Arquitetura: `amd64`

> ⚠️ **Não use Kali Linux padrão**
> Purple já vem pensado para SOC.

---

## 🧩 CONFIGURAÇÃO DA VM (VirtualBox / VMware)

### Adaptadores de rede (IMPORTANTE)

| Interface | Modo                  | Função        |
| --------- | --------------------- | ------------- |
| `eth0`    | NAT                   | Internet      |
| `eth1`    | Host-only ou Internal | Monitoramento |

📌 **eth1 será usada para sniffing de tráfego**

---

## 🔧 CONFIGURAÇÃO INICIAL DO SISTEMA

Após instalar o Kali Purple:

```bash
sudo apt update && sudo apt upgrade -y
```

Verifique interfaces:

```bash
ip a
```

Você deve ver algo como:

```
eth0 → internet
eth1 → rede interna
```

---

## 🔍 CONCEITO CRÍTICO: INTERFACE DE MONITORAMENTO

### Em SOC real:

* A interface de monitoramento:

  * ❌ Não tem IP
  * ❌ Não gera tráfego
  * ✅ Apenas escuta

### Vamos configurar isso depois para:

* Suricata
* Zeek

---

## 🧠 ORGANIZAÇÃO DE DIRETÓRIOS (PADRÃO SOC)

Crie uma estrutura limpa:

```bash
sudo mkdir -p /opt/soc/{suricata,zeek,elastic,wazuh,pcaps,playbooks}
```

Resultado:

```
/opt/soc
├── suricata
├── zeek
├── elastic
├── wazuh
├── pcaps
└── playbooks
```

📌 **Mentalidade profissional desde o início**

---

## 📚 FUNDAMENTOS QUE VOCÊ PRECISA ENTENDER AGORA

### 🔐 IDS vs NSM

| IDS (Suricata)    | NSM (Zeek)               |
| ----------------- | ------------------------ |
| Detecta ataques   | Gera contexto            |
| Baseado em regras | Baseado em comportamento |
| Alertas           | Logs ricos               |

👉 **SOC bom usa os dois**

---

### 📊 SIEM (Elastic)

* Centraliza logs
* Permite busca
* Cria dashboards
* Correlaciona eventos

---

### 🖥️ HIDS (Wazuh)

* Monitora hosts
* Detecta:

  * Alteração de arquivos
  * Login suspeito
  * Malware
* Envia eventos ao SIEM

---

## 🧠 MENTALIDADE DE ANALISTA SOC JÚNIOR

Sempre se pergunte:

> “Esse alerta sozinho me diz algo?”

Se não:

* Precisa de contexto (Zeek)
* Precisa de correlação (Elastic)
* Precisa de evidência no host (Wazuh)

---

## ✅ CHECKLIST — PARTE 1

✔ Kali Purple instalado
✔ Interfaces configuradas
✔ Estrutura `/opt/soc` criada
✔ Conceito de SOC entendido
✔ Pronto para capturar tráfego

---

# 🧭 PARTE 2 — IDS: Suricata (Detecção de Rede)

🟣 **Ferramenta: Suricata**
🎯 **Função no SOC: Detectar atividades suspeitas em tráfego de rede**
👩‍💻 **Nível: SOC Analyst Tier 1**

---

## 🎯 OBJETIVO DESTA PARTE

Ao final da Parte 2, você será capaz de:

✔ Entender **como o Suricata funciona internamente**
✔ Configurar **interface de monitoramento corretamente**
✔ Ajustar o `suricata.yaml` sem quebrar o sistema
✔ Carregar regras de forma consciente
✔ Gerar **alertas reais** a partir de tráfego
✔ Validar se o IDS está funcionando (sem “achar que está”)

---

## 🧠 O QUE É O SURICATA (NA PRÁTICA)

> **Suricata é um IDS/IPS baseado em regras que inspeciona pacotes em tempo real.**

No nosso SOC ele será usado como:

* **IDS passivo**
* Escutando tráfego
* Gerando alertas
* Salvando evidências (logs)

📌 **Ele NÃO toma decisão sozinho**
Ele apenas diz:

> “isso parece perigoso”

---

## 🧩 PAPEL DO SURICATA NO NOSSO SOC

```
[ Tráfego de Rede ]
        ↓
[ Suricata ]
        ↓
[ Alertas + Logs ]
        ↓
[ Elastic / Correlação ]
```

👉 Ele é a **primeira camada de detecção**.

---

## 🔍 COMO O SURICATA FUNCIONA (SIMPLIFICADO)

1. Captura pacotes da interface
2. Decodifica protocolos (IP, TCP, HTTP, DNS…)
3. Compara com regras
4. Gera eventos:

   * Alert
   * Flow
   * Stats

📌 Tudo isso será salvo em **JSON**, ideal para SIEM.

---

## 🌐 INTERFACE DE MONITORAMENTO (PASSO CRÍTICO)

### 🎯 Objetivo

Garantir que o Suricata **escute tráfego real**, sem interferir na rede.

---

### 1️⃣ Identificar a interface correta

```bash
ip a
```

Exemplo esperado:

```
eth0 → NAT (internet)
eth1 → rede interna (monitoramento)
```

📌 **Usaremos `eth1`**

---

### 2️⃣ Garantir que a interface NÃO tenha IP

```bash
sudo ip addr flush dev eth1
```

Valide:

```bash
ip a show eth1
```

Resultado correto:

```
eth1: <UP> 
inet ❌ (não deve existir)
```

✔ Isso está **correto e funcional**

---

### 3️⃣ Colocar interface em modo promiscuous

```bash
sudo ip link set eth1 promisc on
```

Verifique:

```bash
ip link show eth1
```

Você deve ver:

```
PROMISC
```

📌 Sem isso, o Suricata perde pacotes.

---

## 📂 ESTRUTURA DE ARQUIVOS DO SURICATA

Local padrão no Kali Purple:

```
/etc/suricata/
├── suricata.yaml
├── rules/
├── classification.config
└── reference.config
```

Logs:

```
/var/log/suricata/
├── eve.json
├── fast.log
└── stats.log
```

✔ **Esses caminhos são reais e corretos**

---

## ⚙️ CONFIGURAÇÃO PRINCIPAL — `suricata.yaml`

### 📌 Arquivo:

```
/etc/suricata/suricata.yaml
```

Sempre edite com cuidado:

```bash
sudo nano /etc/suricata/suricata.yaml
```

---

### 🔧 Ajuste 1 — Interface correta

Procure por:

```yaml
af-packet:
  - interface: eth0
```

Altere para:

```yaml
af-packet:
  - interface: eth1
```

✔ Sintaxe correta
✔ Método recomendado para VM

---

### 🔧 Ajuste 2 — Diretório de regras

Confirme que existe:

```yaml
default-rule-path: /etc/suricata/rules
```

E que este arquivo está incluído:

```yaml
rule-files:
  - suricata.rules
```

📌 Sem isso, **nenhuma regra é carregada**.

---

### 🔧 Ajuste 3 — Log em JSON (obrigatório para SIEM)

Confirme:

```yaml
outputs:
  - eve-log:
      enabled: yes
      filetype: regular
      filename: eve.json
```

✔ Isso garante integração futura com Elastic.

---

## 🧪 TESTE DE SINTAXE (PASSO OBRIGATÓRIO)

Antes de rodar o Suricata:

```bash
sudo suricata -T -c /etc/suricata/suricata.yaml -v
```

Resultado esperado:

```
Configuration provided was successfully loaded.
```

❌ Se houver erro, **NÃO PROSSIGA**.

---

## 📥 REGRAS — ENTENDENDO ANTES DE BAIXAR

### Tipos de regras

* Emerging Threats (ET)
* Community
* Customizadas (as mais importantes para estudo)

📌 Vamos começar **simples**, para entender o funcionamento.

---

### 🧠 Estrutura básica de uma regra

```text
alert tcp any any -> any 80 (msg:"Teste HTTP"; sid:1000001; rev:1;)
```

| Campo   | Função    |
| ------- | --------- |
| alert   | Ação      |
| tcp     | Protocolo |
| any any | Origem    |
| ->      | Direção   |
| any 80  | Destino   |
| msg     | Mensagem  |
| sid     | ID único  |

---

## ✍️ CRIANDO SUA PRIMEIRA REGRA (MANUAL)

Abra o arquivo de regras:

```bash
sudo nano /etc/suricata/rules/suricata.rules
```

Adicione:

```text
alert icmp any any -> any any (msg:"ICMP Detected - Ping"; sid:1000001; rev:1;)
```

✔ Sintaxe válida
✔ Fácil de testar
✔ Ótima para aprendizado

---

## ▶️ INICIANDO O SURICATA

Modo foreground (debug):

Use este modo **apenas para validar** configuração e regras:
```bash
sudo suricata -c /etc/suricata/suricata.yaml -i eth1

```
> ⚠️ **Importante:**
>
> * O modo foreground **não deve rodar junto com o serviço systemd**.
> * Após confirmar que Suricata está funcionando, **encerre o processo** (Ctrl+C) antes de iniciar o serviço.
> * Isso evita conflitos na interface `eth1` e logs inconsistentes.

---
## ▶️ Habilitar Suricata como serviço (persistente)
sudo systemctl enable suricata
sudo systemctl start suricata
sudo systemctl status suricata

📌 **Deixe rodando**

---

## 🧪 TESTE REAL — GERANDO ALERTA

De outra máquina (ou do host):

```bash
ping <IP_DO_ALVO>
```

No SOC, verifique:

```bash
sudo tail -f /var/log/suricata/fast.log
```

Resultado esperado:

```
[**] ICMP Detected - Ping [**]
```

✔ Isso confirma:

* Interface ok
* Regras funcionando
* Logs sendo gerados

---

## 🧠 O QUE VOCÊ APRENDEU AQUI (IMPORTANTE)

* IDS **não investiga**, apenas alerta
* Regras simples são melhores para aprender
* Log correto > mil ferramentas
* Se não alerta, algo está errado (não “normal”)

---

## ✅ CHECKLIST — PARTE 2

✔ Interface em modo monitor
✔ Suricata configurado corretamente
✔ Regras carregadas
✔ Alertas reais gerados
✔ Logs funcionando

---

# 🧭 PARTE 3 — NSM: Zeek (Investigação de Tráfego)

🟣 **Ferramenta: Zeek (antigo Bro)**
🎯 **Função no SOC: Gerar contexto e visibilidade de rede**
👩‍💻 **Nível: Analista SOC Tier 1**

---

## 🎯 OBJETIVO DESTA PARTE

Ao final desta parte, você será capaz de:

✔ Entender **por que alertas não são suficientes**
✔ Compreender o papel do **NSM dentro de um SOC**
✔ Configurar o Zeek corretamente no Kali Purple
✔ Gerar e interpretar logs reais de rede
✔ Usar Zeek para **investigar alertas do Suricata**
✔ Pensar como um analista SOC em investigação inicial

---

## 🧠 O QUE É NSM (NETWORK SECURITY MONITORING)

> **NSM é visibilidade + contexto.**

Enquanto o IDS diz:

> “Algo suspeito aconteceu”

O NSM responde:

> “O que aconteceu, como, quando, entre quem e com que impacto”

📌 **Zeek NÃO gera alertas por padrão**
Ele **descreve comportamentos**.

---

## 🧩 PAPEL DO ZEEK NO NOSSO SOC

```
[ Tráfego de Rede ]
        ↓
[ Zeek ]
        ↓
[ Logs ricos ]
        ↓
[ Elastic / Investigação ]
```

### Exemplos de perguntas que o Zeek responde:

* Quem falou com quem?
* Que protocolos foram usados?
* Houve DNS suspeito?
* Qual foi o User-Agent?
* Qual foi a sequência do ataque?

---

## 🔄 SURICATA vs ZEEK (NA PRÁTICA)

| Suricata (IDS)    | Zeek (NSM)         |
| ----------------- | ------------------ |
| Alerta            | Contexto           |
| Baseado em regras | Baseado em eventos |
| “Possível ataque” | “Sessão detalhada” |
| Pouco contexto    | Muito contexto     |

👉 **Eles se complementam**, nunca substituem.

---

## 🧠 MENTALIDADE SOC (IMPORTANTE)

> Nenhum alerta deve ser analisado sem contexto.

Fluxo correto:

```
Suricata alerta
        ↓
Zeek explica o tráfego
        ↓
Elastic correlaciona
        ↓
Analista decide
```

---

## 📂 ESTRUTURA DE ARQUIVOS DO ZEEK

Diretório padrão:

```
/opt/zeek/
├── bin/
├── share/
├── logs/
└── etc/
```

Logs padrão:

```
/opt/zeek/logs/current/
├── conn.log
├── dns.log
├── http.log
├── ssl.log
├── notice.log
```

✔ Caminhos **reais e corretos** no Kali Purple

---

## 🌐 INTERFACE DE MONITORAMENTO (REUTILIZAÇÃO)

👉 **Zeek usará a MESMA interface do Suricata (`eth1`)**

✔ Sem IP
✔ Modo promiscuous
✔ Apenas escuta

📌 Isso já foi feito na Parte 2 (nenhuma duplicação).

---

## ⚙️ CONFIGURAÇÃO INICIAL DO ZEEK

### 1️⃣ Verificar se o Zeek está instalado

```bash
zeek --version
```

Se retornar versão → OK
Se não, instale:

```bash
sudo apt install zeek -y
```

✔ Sintaxe correta
✔ Pacote oficial Kali

---

### 2️⃣ Configurar interface padrão do Zeek

Arquivo:

```
/opt/zeek/etc/node.cfg
```

Abra:

```bash
sudo nano /opt/zeek/etc/node.cfg
```

Configuração mínima correta:

```ini
[zeek]
type=standalone
host=localhost
interface=eth1
```

✔ `standalone` = SOC all-in-one
✔ Interface correta
✔ Lógica funcional

---

## 🔧 AJUSTE DO ARQUIVO `networks.cfg`

Arquivo:

```
/opt/zeek/etc/networks.cfg
```

Abra:

```bash
sudo nano /opt/zeek/etc/networks.cfg
```

Defina sua rede interna (exemplo):

```text
192.168.56.0/24
```

📌 Isso ajuda o Zeek a diferenciar:

* Rede interna
* Tráfego externo

---

## ▶️ INICIANDO O ZEEK

### 🔹 Modo simples (recomendado para o lab)

```bash
sudo zeek -i eth1
```

> ⚠️ **Importante:**
>
> * Este comando inicia o Zeek **na interface de monitoramento**.
> * O Zeek **não imprime saída na tela**, apenas gera logs em `/opt/zeek/logs/current/`.
> * **Não use `zeekctl deploy`** neste lab all-in-one: ele é destinado a clusters ou setups complexos, e pode confundir ou gerar erros.

---

📌 O Zeek **não imprime saída na tela**
Ele escreve logs.

---

## 🧪 TESTE REAL — GERANDO TRÁFEGO

De outra máquina:

```bash
ping <IP_DO_ALVO>
```

Ou acesso HTTP:

```bash
curl http://example.com
```

---

## 🔍 ANALISANDO LOGS DO ZEEK

Entre no diretório:

```bash
cd /opt/zeek/logs/current/
ls
```

---

### 📄 `conn.log` — Conexões

```bash
cat conn.log | head
```

Você verá:

* IP origem
* IP destino
* Porta
* Duração
* Protocolo

📌 **Base de toda investigação**

---

### 📄 `dns.log` — Resoluções DNS

```bash
cat dns.log
```

Ideal para:

* C2
* Domínios suspeitos
* Beaconing

---

### 📄 `http.log` — Tráfego Web

```bash
cat http.log
```

Você verá:

* URLs
* Métodos
* User-Agent

📌 Extremamente valioso em incidentes.

---

## 🔗 RELAÇÃO COM SURICATA (EXEMPLO REAL)

### Suricata alerta:

```
ET SCAN Possible Nmap Scan
```

### Zeek mostra em `conn.log`:

* Muitas conexões
* Portas sequenciais
* Curta duração

👉 **Isso confirma o comportamento**, não só o alerta.

---

## 🧠 O QUE VOCÊ APRENDEU AQUI

* Alertas sozinhos não explicam incidentes
* Zeek é ferramenta de **investigação**
* Logs > achismo
* SOC bom tem visibilidade

---

## ✅ CHECKLIST — PARTE 3

✔ Zeek instalado  
✔ Interface configurada (eth1 sem IP, modo promiscuous)  
✔ Zeek iniciado via `sudo zeek -i eth1`  
✔ Logs sendo gerados em `/opt/zeek/logs/current/`  
✔ Tráfego visível para investigação inicial  
✔ Capacidade de correlação com alertas Suricata

---

# 🧭 PARTE 4 — SIEM: Elastic Stack (Centralização)

🟣 **Ferramenta: Elastic Stack (Elasticsearch + Kibana)**
🎯 **Função no SOC: Centralizar, correlacionar e visualizar eventos**
👩‍💻 **Nível: Analista SOC Tier 1**

---

## 🎯 OBJETIVO DESTA PARTE

Ao final desta parte, você será capaz de:

✔ Entender **o papel real de um SIEM**
✔ Instalar e configurar o Elastic Stack no Kali Purple
✔ Ingerir logs do **Suricata** e do **Zeek**
✔ Validar ingestão sem crash
✔ Usar Kibana para **investigação básica SOC**
✔ Preparar o ambiente para correlação futura

---

## 🧠 O QUE É UM SIEM (SEM MARKETING)

> **SIEM é um agregador inteligente de eventos.**

Ele não detecta sozinho.
Ele **organiza, cruza e apresenta** dados para o analista decidir.

No nosso SOC, o Elastic será responsável por:

* Centralizar logs
* Permitir busca rápida
* Servir de base para correlação
* Apoiar investigações

---

## 🧩 PAPEL DO ELASTIC NO NOSSO SOC

```
[ Suricata ] ─┐
              ├──► [ Elastic ] ───► [ Kibana ]
[ Zeek ] ─────┘
```

📌 Elastic **não substitui** Suricata nem Zeek
Ele **dá sentido ao conjunto**

---

## ⚠️ AVISO IMPORTANTE (ESTABILIDADE)

Elastic consome recursos.
Para **não crashar**:

✔ Use configuração mínima
✔ Não habilite segurança agora
✔ Use apenas **1 nó (standalone)**

Tudo aqui é **deliberadamente simples**, mas correto.

---

## ⚙️ INSTALAÇÃO DO ELASTIC STACK

### 1️⃣ Instalar Elasticsearch

```bash
sudo apt install elasticsearch -y
```

✔ Pacote oficial
✔ Compatível com Kali Purple

---

### 2️⃣ Configuração mínima do Elasticsearch

Arquivo:

```
/etc/elasticsearch/elasticsearch.yml
```

Abra:

```bash
sudo nano /etc/elasticsearch/elasticsearch.yml
```

Use **exatamente** estas configurações mínimas:

```yaml
cluster.name: soc-lab
node.name: soc-node-1

network.host: 127.0.0.1
http.port: 9200

discovery.type: single-node
```

🔒 Motivos técnicos:

* `127.0.0.1` → seguro e estável
* `single-node` → evita erro de cluster
* Porta padrão → compatível com Beats

---

### 3️⃣ Ajuste de memória (CRÍTICO)

Arquivo:

```
/etc/elasticsearch/jvm.options
```

Edite:

```bash
sudo nano /etc/elasticsearch/jvm.options
```

Altere para:

```text
-Xms1g
-Xmx1g
```

📌 Isso evita:

* OOM
* Crash silencioso
* Lentidão extrema

---

### 4️⃣ Iniciar Elasticsearch

```bash
sudo systemctl enable elasticsearch
sudo systemctl start elasticsearch
```

Verifique:

```bash
curl http://localhost:9200
```

Resposta esperada (JSON):

```json
"cluster_name" : "soc-lab"
```

✔ Elasticsearch funcionando

---

## 🖥️ INSTALAÇÃO DO KIBANA

### 1️⃣ Instalar Kibana

```bash
sudo apt install kibana -y
```

---

### 2️⃣ Configuração mínima do Kibana

Arquivo:

```
/etc/kibana/kibana.yml
```

Abra:

```bash
sudo nano /etc/kibana/kibana.yml
```

Use:

```yaml
server.port: 5601
server.host: "127.0.0.1"

elasticsearch.hosts: ["http://127.0.0.1:9200"]
```

✔ Sintaxe correta
✔ Comunicação direta com Elasticsearch

---

### 3️⃣ Iniciar Kibana

```bash
sudo systemctl enable kibana
sudo systemctl start kibana
```

Acesse no navegador:

```
http://localhost:5601
```

✔ Interface Kibana carregando

---

## 📥 INGESTÃO DE LOGS (FILEBEAT)

📌 **Filebeat será o coletor**
Ele é leve, estável e padrão de mercado.

---

### 1️⃣ Instalar Filebeat

```bash
sudo apt install filebeat -y
```

---

### 2️⃣ Configuração base do Filebeat

Arquivo:

```
/etc/filebeat/filebeat.yml
```

Abra:

```bash
sudo nano /etc/filebeat/filebeat.yml
```

---

### 🔧 INPUT — SURICATA

Adicione:

```yaml
filebeat.inputs:
- type: log
  enabled: true
  paths:
    - /var/log/suricata/eve.json
  json.keys_under_root: true
  json.add_error_key: true

- type: log
  enabled: true
  paths:
    - /opt/zeek/logs/current/*.log
```

✔ Sintaxe validada
✔ Compatível com EVE JSON

---

✔ Coleta todos os logs Zeek

---

### 🔧 OUTPUT — ELASTICSEARCH

⚠️ **Nota operacional**
Antes de iniciar o Filebeat, carregue os pipelines e templates:

```bash
sudo filebeat setup --pipelines
sudo filebeat setup --template
```

Confirme:

```yaml
output.elasticsearch:
  hosts: ["http://127.0.0.1:9200"]
  pipeline: "filebeat-<VERSAO>-suricata-pipeline"
```
###⚠️ IMPORTANTE:
Substitua `<VERSAO>` pela versão exata do Filebeat instalada.
Exemplo: filebeat-8.11.3-suricata-pipeline


⚠️ **Desabilite Logstash**, se existir:

```yaml
#output.logstash:
```

---

### 3️⃣ Testar Filebeat (OBRIGATÓRIO)

```bash
sudo filebeat test config
```

Resultado esperado:

```
Config OK
```

Depois:

```bash
sudo filebeat test output
```

Resultado esperado:

```
Connection to Elasticsearch successful
```

---

### 4️⃣ Iniciar Filebeat

```bash
sudo systemctl enable filebeat
sudo systemctl start filebeat
```

---

## 🔍 VALIDANDO INGESTÃO NO KIBANA

No Kibana:

1. Vá em **Discover**
2. Crie Data View:

   * `filebeat-*`
3. Veja eventos chegando

Você deve ver:

* Logs do Suricata
* Logs do Zeek

✔ Centralização funcionando

---

## 🧠 FLUXO SOC ATÉ AQUI (AMARRAÇÃO)

```
Tráfego
   ↓
Suricata (alerta)
   ↓
Zeek (contexto)
   ↓
Filebeat (coleta)
   ↓
Elastic (centralização)
   ↓
Kibana (investigação)
```

Nada está sobrando.
Nada está faltando.

---

## 🧠 O QUE VOCÊ APRENDEU AQUI

* SIEM não detecta, **organiza**
* Elastic precisa ser contido para não quebrar
* Filebeat é a ponte crítica
* SOC começa a “ganhar visão”

---

## ✅ CHECKLIST — PARTE 4

✔ Elasticsearch funcional
✔ Kibana acessível
✔ Filebeat coletando
✔ Logs Suricata visíveis
✔ Logs Zeek visíveis
✔ SOC centralizado sem crash

---

# 🧭 PARTE 5 — HIDS: Wazuh (Monitoramento de Host)

🟣 **Ferramenta: Wazuh**
🎯 **Função no SOC: Monitorar comportamento e integridade de hosts**
👩‍💻 **Nível: Analista SOC Tier 1**

---

## 🎯 OBJETIVO DESTA PARTE

Ao final desta parte, você será capaz de:

✔ Entender o papel do **HIDS dentro de um SOC real**
✔ Instalar e configurar o **Wazuh Manager** no Kali Purple
✔ Integrar o Wazuh ao **Elastic Stack já existente**
✔ Registrar e monitorar **agentes (hosts)**
✔ Visualizar alertas de host no Kibana
✔ Completar a visão SOC (Rede + Host)

---

## 🧠 O QUE É UM HIDS (NA PRÁTICA)

> **HIDS monitora o que acontece DENTRO do host.**

Enquanto a rede mostra:

* Conexões
* Protocolos
* Fluxos

O HIDS mostra:

* Alteração de arquivos
* Logins
* Escalação de privilégio
* Malware
* Persistência

📌 **SOC sem HIDS é cego no endpoint**

---

## 🧩 PAPEL DO WAZUH NO NOSSO SOC

```
[ Host Monitorado ]
        ↓
[ Wazuh Agent ]
        ↓
[ Wazuh Manager ]
        ↓
[ Elastic / Kibana ]
```

👉 Ele fecha o ciclo da investigação.

---

## 🔄 RELAÇÃO COM AS OUTRAS CAMADAS

| Camada | Ferramenta | Pergunta que responde        |
| ------ | ---------- | ---------------------------- |
| IDS    | Suricata   | Houve ataque?                |
| NSM    | Zeek       | Como foi o tráfego?          |
| HIDS   | Wazuh      | O host foi afetado?          |
| SIEM   | Elastic    | Tudo isso junto faz sentido? |

---

## ⚠️ AVISO DE ARQUITETURA (IMPORTANTE)

Para **SOC de estudo**, usaremos:

✔ **Wazuh All-in-One (Manager + API)**
✔ **Elastic já instalado (Parte 4)**
✔ **Sem cluster**
✔ **Sem TLS neste momento**

📌 Isso evita:

* Conflito de portas
* Uso excessivo de RAM
* Debug desnecessário

---

## ⚙️ INSTALAÇÃO DO WAZUH MANAGER

### 1️⃣ Adicionar repositório oficial do Wazuh

```bash
curl -s https://packages.wazuh.com/key/GPG-KEY-WAZUH | sudo gpg --dearmor -o /usr/share/keyrings/wazuh.gpg
```

```bash
echo "deb [signed-by=/usr/share/keyrings/wazuh.gpg] https://packages.wazuh.com/4.x/apt/ stable main" | sudo tee /etc/apt/sources.list.d/wazuh.list
```

Atualize:

```bash
sudo apt update
```

✔ Sintaxe validada
✔ Método oficial Wazuh

---

### 2️⃣ Instalar Wazuh Manager

```bash
sudo apt install wazuh-manager -y
```

---

### 3️⃣ Iniciar e habilitar serviço

```bash
sudo systemctl enable wazuh-manager
sudo systemctl start wazuh-manager
```

Verifique:

```bash
sudo systemctl status wazuh-manager
```

Estado esperado:

```
active (running)
```

✔ Manager funcional

---

## 🔌 INTEGRAÇÃO WAZUH → ELASTIC

📌 O Wazuh envia eventos via **Filebeat**, que já está instalado.

---

### 1️⃣ Instalar módulo Wazuh para Filebeat

```bash
sudo apt install wazuh-filebeat -y
```

---

### 2️⃣ Configurar Filebeat para Wazuh

Arquivo:

```
/etc/filebeat/filebeat.yml
```

Confirme que existe:

```yaml
filebeat.modules:
- module: wazuh
  alerts:
    enabled: true
```

📌 Este módulo lê diretamente:

```
/var/ossec/logs/alerts/alerts.json
```

✔ Caminho correto
✔ Integração oficial

---

### 3️⃣ Reiniciar Filebeat

```bash
sudo systemctl restart filebeat
```

---

## 🧪 VALIDANDO ALERTAS DO WAZUH

Verifique se o arquivo existe:

```bash
ls /var/ossec/logs/alerts/
```

Você deve ver:

```
alerts.json
```

Teste leitura:

```bash
sudo tail -f /var/ossec/logs/alerts/alerts.json
```

✔ Eventos sendo gerados = integração OK

---

## 🖥️ REGISTRANDO UM AGENTE (HOST)

📌 O próprio **Kali Purple pode ser um agente**, para estudo inicial.

---

### 1️⃣ Instalar agente localmente (opcional, mas recomendado)

```bash
sudo apt install wazuh-agent -y
```

---

### 2️⃣ Registrar agente no Manager

```bash
sudo /var/ossec/bin/agent-auth -m 127.0.0.1
```

✔ Comunicação local
✔ Sem firewall
✔ Sem TLS (lab)

---

### 3️⃣ Iniciar agente

```bash
sudo systemctl enable wazuh-agent
sudo systemctl start wazuh-agent
```

Verifique:

```bash
sudo systemctl status wazuh-agent
```

---

## 🔍 VALIDANDO NO MANAGER

Liste agentes:

```bash
sudo /var/ossec/bin/agent_control -lc
```

Resultado esperado:

```
ID: 001, Name: kali-purple, Status: Active
```

✔ Agente registrado
✔ Comunicação funcionando

---

## 📊 VISUALIZAÇÃO NO KIBANA

No Kibana:

1. Vá em **Discover**
2. Data View:

   * `wazuh-alerts-*` ou `filebeat-*`
3. Filtre por:

   * `rule.level`
   * `agent.name`

Você verá:

* Alterações de arquivos
* Eventos de login
* Alertas de integridade

---

## 🧠 EXEMPLO REAL DE USO SOC

### Situação:

Suricata detecta tráfego suspeito
Zeek mostra conexão incomum
Wazuh mostra:

* Novo arquivo criado
* Execução de comando
* Tentativa de persistência

👉 **Agora sim você tem um incidente real**

---

## 🧠 O QUE VOCÊ APRENDEU AQUI

* SOC sem HIDS é incompleto
* Wazuh dá visibilidade interna
* Filebeat é o elo crítico
* Host + Rede = decisão correta

---

## ✅ CHECKLIST — PARTE 5

✔ Wazuh Manager ativo
✔ Filebeat integrado
✔ Alerts.json sendo ingerido
✔ Agente registrado
✔ Eventos visíveis no Kibana
✔ SOC com visão de host

---

# 🧭 PARTE 6 — Correlação + Alertas + Playbooks (SOC)

🟣 **Camada: Analítica e Operacional**
🎯 **Função no SOC: Transformar eventos em ações**
👩‍💻 **Nível: Analista SOC Tier 1**

---

## 🎯 OBJETIVO DESTA PARTE

Ao final desta parte, você será capaz de:

✔ Entender o que é **correlação de eventos**
✔ Criar **alertas acionáveis** no Kibana
✔ Diferenciar alerta técnico de alerta SOC
✔ Construir **playbooks simples e funcionais**
✔ Simular o **dia a dia real de um SOC Tier 1**

---

## 🧠 O QUE É CORRELAÇÃO (SEM COMPLICAÇÃO)

> **Correlação é ligar eventos que, sozinhos, dizem pouco.**

Exemplo:

* 🔔 Suricata: “Possível scan”
* 📄 Zeek: “Múltiplas conexões curtas”
* 🖥️ Wazuh: “Login suspeito no host”

👉 **Juntos = incidente provável**

📌 SOC não reage a eventos isolados
SOC reage a **contexto acumulado**

---

## 🧩 VISÃO DE CORRELAÇÃO NO NOSSO SOC

```
[ Suricata Alert ]
        +
[ Zeek Log ]
        +
[ Wazuh Alert ]
        ↓
[ Elastic (Correlação) ]
        ↓
[ Alerta SOC ]
        ↓
[ Playbook ]
```

Tudo que faremos agora **usa dados que já existem**.

---

## ⚠️ IMPORTANTE (LIMITES DO LAB)

Neste SOC de estudo:

✔ Correlação será feita via **KQL + lógica humana**
✔ Alertas via **Kibana (Rules & Alerts)**
❌ Sem ML
❌ Sem SOAR automático

📌 **Exatamente como muitos SOCs reais Tier 1**

---

## 🔍 DEFININDO EVENTOS-CHAVE (BASE DA CORRELAÇÃO)

Vamos trabalhar com **3 tipos de sinais**:

### 1️⃣ IDS — Suricata

* Campo típico:

  * `event_type: alert`
  * `alert.signature`

### 2️⃣ NSM — Zeek

* Campos típicos:

  * `id.orig_h`
  * `id.resp_h`
  * `proto`
  * `service`

### 3️⃣ HIDS — Wazuh

* Campos típicos:

  * `rule.level`
  * `rule.description`
  * `agent.name`

---

## 🔎 CONSULTAS BASE (KQL) — VALIDADAS

### 🔔 Suricata — Alertas de Rede

```kql
event_type: "alert"
```

Filtra apenas eventos do Suricata.

---

### 🌐 Zeek — Conexões Suspeitas

```kql
service: "http" or service: "dns"
```

Útil para investigação inicial.

---

### 🖥️ Wazuh — Alertas Relevantes

```kql
rule.level >= 7
```

📌 Nível 7+ = atenção SOC Tier 1

---

## 🧠 PRIMEIRA CORRELAÇÃO (MANUAL E REAL)

### 🎯 Cenário

Queremos saber:

> “Houve alerta de rede **e** impacto no host?”

---

### 🔎 Consulta combinada (tempo próximo)

No Kibana → Discover:

```kql
(event_type: "alert") or (rule.level >= 7)
```

Depois:

* Ajuste o **time range** (ex: últimos 5 minutos)
* Verifique:

  * Mesmo IP
  * Mesmo host
  * Sequência temporal

📌 **Isso é correlação SOC real**, não teoria.

---

## 🚨 CRIANDO UM ALERTA NO KIBANA (RULE)

### 1️⃣ Acessar Alertas

Kibana →
**Stack Management → Rules and Connectors**

Clique em **Create rule**

---

### 2️⃣ Tipo de Regra

Escolha:

👉 **Elasticsearch query**

✔ Simples
✔ Estável
✔ Funcional no lab

---

### 3️⃣ Query do Alerta (Exemplo)

```kql
event_type: "alert" and alert.severity >= 2
```

📌 Alerta básico de IDS relevante.

---

### 4️⃣ Condição

* **When:** number of documents
* **Is above:** 0
* **For the last:** 1 minute

✔ Não gera ruído
✔ Responde rápido

---

### 5️⃣ Ação (Simples)

Para lab:

* Log no Kibana
* (Opcional) Email local

📌 Playbook será manual (como Tier 1)

---

## 🧠 DIFERENÇA CRÍTICA: ALERTA vs INCIDENTE

| Alerta                  | Incidente         |
| ----------------------- | ----------------- |
| Evento técnico          | Evento confirmado |
| Pode ser falso positivo | Exige ação        |
| IDS gera                | Analista confirma |

👉 **Playbook só começa após validação**

---

## 📘 PLAYBOOK SOC (ESTRUTURA PADRÃO)

Crie em:

```
/opt/soc/playbooks/
```

Exemplo:

```bash
sudo nano /opt/soc/playbooks/scan_rede.md
```

---

### 📄 MODELO DE PLAYBOOK (COPIÁVEL)

```md
# Playbook — Possível Scan de Rede

## 1. Identificação
- Fonte do alerta: Suricata
- Tipo: Scan
- Severidade: Média

## 2. Validação
- Verificar Zeek (conn.log)
- Confirmar múltiplas conexões curtas
- Identificar IP origem

## 3. Impacto no Host
- Consultar Wazuh
- Verificar login, arquivos, processos

## 4. Classificação
- [ ] Falso positivo
- [ ] Scan sem impacto
- [ ] Scan com impacto

## 5. Ação
- Documentar evento
- Escalar se necessário

## 6. Encerramento
- Registrar no SOC
- Ajustar regras se preciso
```

✔ Simples
✔ Real
✔ Usável em entrevista

---

## 🧠 SIMULAÇÃO REAL DE ROTINA SOC TIER 1

```
Alerta dispara
      ↓
Analista verifica contexto
      ↓
Consulta Zeek
      ↓
Consulta Wazuh
      ↓
Decide: incidente ou não
      ↓
Executa playbook
```

📌 **Isso é SOC de verdade**

---

## 🧠 O QUE VOCÊ APRENDEU AQUI

* Correlação é lógica, não ferramenta
* Alertas precisam ser acionáveis
* Playbook evita improviso
* SOC Tier 1 pensa em fluxo, não em ferramenta

---

## ✅ CHECKLIST — PARTE 6

✔ Entendimento de correlação
✔ Queries KQL funcionais
✔ Alerta criado no Kibana
✔ Playbook estruturado
✔ Rotina SOC simulada

---

# 🧭 PARTE 7 — Rotina SOC: Casos Reais + Automação Básica

**(Operação diária de um SOC júnior – tudo integrado e funcional)**

🟣 **Baseado no SOC que você construiu nas Partes 1–6**
🔒 **Foco total: prática real de analista SOC Tier 1**
🧠 **Mentalidade: observar → investigar → decidir → documentar**

---

## 📌 OBJETIVO DA PARTE 7

Ao finalizar esta parte, você será capaz de:

* Operar o SOC diariamente sem quebrar nada
* Reconhecer ataques comuns via Suricata + Zeek
* Investigar incidentes no Elastic
* Correlacionar eventos (rede + host)
* Criar **automação básica realista**
* Simular entrevistas técnicas de SOC

Tudo aqui **parte do pressuposto que as Partes 1–6 estão funcionando corretamente**.

---

# 🧠 VISÃO GERAL: COMO FUNCIONA UM SOC NA PRÁTICA

### 📊 Fontes de dados que você já tem

```
Rede
 ├─ Suricata → alertas IDS
 ├─ Zeek → logs de tráfego (DNS, HTTP, Conn)
Host
 ├─ Wazuh Agent → logs do sistema
SIEM
 ├─ Elastic → centralização + investigação
```

---

# 🕘 ROTINA DIÁRIA DE UM ANALISTA SOC (CHECKLIST REAL)

> 📌 **Esse checklist é ouro**
> Copie exatamente assim para seu Notion / Obsidian

```md
## 🕘 Rotina SOC — Início do Turno

[ ] Verificar status dos serviços
[ ] Conferir alertas críticos no Elastic
[ ] Validar alertas de Suricata
[ ] Investigar tráfego suspeito no Zeek
[ ] Correlacionar com eventos de host (Wazuh)
[ ] Classificar incidente
[ ] Documentar ocorrência
```

---

## 🔧 1. Verificação de Saúde do SOC (OBRIGATÓRIO)

### 🔍 Serviços principais

```bash
sudo systemctl status suricata
sudo zeekctl status
sudo systemctl status elasticsearch
sudo systemctl status kibana
sudo systemctl status wazuh-manager
```

📌 **Todos devem estar `active (running)`**

Se algum cair:

* **NÃO reinicie tudo**
* Reinicie **apenas o serviço afetado**

Exemplo:

```bash
sudo systemctl restart suricata
```

---

# 🚨 2. CASO REAL 1 — Port Scan (Reconhecimento)

### 🔔 Detecção (Suricata)

Alerta típico:

```
ET SCAN Nmap Scripting Engine User-Agent Detected
```

### 🔍 Investigação no Elastic

Filtro KQL:

```kql
event.module:suricata AND alert.signature:*Nmap*
```

### 🔎 Confirmação no Zeek

Buscar conexões suspeitas:

```bash
cat /opt/zeek/logs/current/conn.log | grep -E "S0|REJ"
```

📌 Indícios claros:

* Muitas conexões
* Portas diferentes
* Mesmo IP de origem

---

### 🧠 Classificação do Incidente

| Campo      | Valor          |
| ---------- | -------------- |
| Tipo       | Reconhecimento |
| Severidade | Média          |
| Impacto    | Nenhum         |
| Ação       | Monitorar      |

---

# 🌐 3. CASO REAL 2 — DNS Suspeito (Malware / C2)

### 🔔 Detecção (Zeek)

Arquivo:

```
dns.log
```

Buscar domínios estranhos:

```bash
cat /opt/zeek/logs/current/dns.log | grep -E "[a-z0-9]{20,}\."
```

📌 Indícios:

* Domínios longos
* Muitos números
* Sem TLD comum

---

### 🔍 Correlacionar no Elastic

⚠️ **Nota de auditoria**
O nome do campo DNS do Zeek pode variar conforme versão do Filebeat e do pipeline ECS.
Sempre valide os campos disponíveis no índice antes da investigação.

```kql
dns.query:*
```

Depois filtrar manualmente por:

* Tamanho do domínio
* Repetição

---

### 🧠 Classificação

| Campo           | Valor                |
| --------------- | -------------------- |
| Tipo            | Comunicação suspeita |
| Severidade      | Alta                 |
| Possível ameaça | Malware              |
| Ação            | Isolar host          |

---

# 🖥️ 4. CASO REAL 3 — Tentativa de Força Bruta (Host)

### 🔔 Detecção (Wazuh)

Evento típico:

```
sshd: Failed password for invalid user
```

### 🔍 Investigação

Filtro:

```kql
rule.groups:authentication_failed
```

📌 Indícios:

* Muitos eventos
* Mesmo IP
* Curto intervalo

---

### 🧠 Correlação (REDE + HOST)

| Fonte    | Evidência          |
| -------- | ------------------ |
| Suricata | Tentativas TCP     |
| Zeek     | Conexões repetidas |
| Wazuh    | Falha de login     |

📌 **Confirmação de ataque**

---

# ⚙️ 5. AUTOMAÇÃO BÁSICA (SEM QUEBRAR O LAB)

## 🟢 Objetivo da automação

> Quando um alerta crítico aparecer:
>
> * Gerar evidência
> * Marcar incidente
> * Ajudar o analista

---

## 🧩 Automação 1 — Script simples de alerta

📄 `/opt/soc/alert_checker.sh`

```bash
#!/bin/bash

LOG="/var/log/soc_alerts.log"
DATE=$(date)

echo "[$DATE] Verificando alertas críticos..." >> $LOG

grep -i '"severity":' /var/log/suricata/eve.json | grep -E '[3-9]' >> $LOG
```

Permissão:

```bash
chmod +x /opt/soc/alert_checker.sh
```

---

## ⏰ Agendamento com cron

```bash
crontab -e
```

Adicionar:

```cron
*/10 * * * * /opt/soc/alert_checker.sh
```

📌 A cada 10 minutos o SOC verifica alertas críticos.

---

# 📝 6. MODELO DE DOCUMENTAÇÃO DE INCIDENTE

Copie exatamente:

```md
# 📄 Incidente SOC

## 🆔 ID
SOC-2025-001

## ⏰ Data/Hora
2025-XX-XX 14:32

## 🚨 Tipo
Port Scan

## 🔍 Ferramentas
Suricata, Zeek, Elastic

## 🌐 IP Origem
192.168.1.50

## 🧠 Análise
Atividade compatível com reconhecimento de rede via Nmap.

## ⚠️ Severidade
Média

## ✅ Ação Tomada
Monitoramento contínuo.

## 📌 Status
Encerrado
```

---

# 🎯 7. COMO ISSO TE PREPARA PARA ENTREVISTA

Você agora consegue explicar:

✔️ Diferença entre IDS / NSM / SIEM / HIDS
✔️ Fluxo de eventos de rede → SIEM
✔️ Investigação real
✔️ Correlação de logs
✔️ Rotina SOC
✔️ Automação simples

📌 **Isso é exatamente o que um SOC júnior precisa saber.**

---
