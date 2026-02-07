# Análise Forense de Logs: Investigação de Acesso Não Autorizado ao Painel de Telemetria da Daikibo Industrials

> Laboratório prático baseado em cenário real de resposta a incidentes da Deloitte Cyber Risk Services

## 📌 Contexto do Incidente

A Daikibo Industrials — cliente da Deloitte — reportou vazamento de informações confidenciais após paralisação não planejada de linhas de montagem. Suspeita-se que seu painel interno de telemetria industrial tenha sido comprometido, permitindo acesso indevido aos status operacionais das fábricas globais (meiyo, seiko, shenzhen, berlin).

**Objetivo da investigação:**
1. Determinar se o acesso ocorreu via ataque direto pela internet (sem VPN)
2. Identificar padrões de atividade automatizada/suspeita nos logs de requisições web

---

## 🔍 Metodologia de Análise

Análise estruturada do arquivo `web_requests.log` com base nos critérios:

| Critério de Análise | Aplicação Prática |
|---------------------|-------------------|
| **Fluxo de navegação** | Verificação da sequência: `GET /login` → assets frontend (`/login.css`, `/login.js`) → `POST /login` → carregamento do dashboard (`/`, `/index.css`, `/index.js`) → requisições à API (`/api/factory/...`) |
| **Padrão temporal** | Busca por intervalos exatos entre requisições (ex: sempre 3.600s = 1h), indicando script automatizado |
| **Comportamento humano vs. bot** | Identificação de sequências longas (>20 requisições) sem interação com UI/frontend |
| **Horário atípico** | Atividade concentrada em madrugada (00h–06h), fora do expediente operacional |
| **Persistência pós-expiração** | Requisições contínuas mesmo após retorno `401 (UNAUTHORIZED)` (sessão expirada) |

---

## 🚨 Evidências de Atividade Suspeita

### Usuário Identificado
ID: mdB7yD2dp1BFZPontHBQ1Z

IP: 192.168.0.101 (rede interna Daikibo)

### Indicadores Forenses

| Indicador | Evidência no Log | Significado |
|-----------|------------------|-------------|
| **Automação por intervalo fixo** | Requisições exatamente às `XX:00:48` (17h, 18h, 19h... 23h do dia 25/06) | Padrão impossível para interação humana; característico de cron job/script |
| **Acesso simultâneo a todas as fábricas** | Em cada timestamp: 4 requisições paralelas (`meiyo`, `seiko`, `shenzhen`, `berlin`) | Comportamento de coleta em massa, não navegação humana |
| **Persistência após expiração** | Entre 00:00:48–16:00:48 (26/06): 64 requisições com status `401 (UNAUTHORIZED)` | Script continuou executando mesmo sem sessão válida |
| **Ausência de interação com UI** | Após login às 16:04:54 (26/06), nenhuma requisição a assets frontend antes das chamadas à API | Fluxo quebrado: humano carrega UI antes de acessar dados |

### Trecho Representativo do Log
```log
2021-06-25T17:00:48.000Z GET "/api/factory/machine/status?factory=meiyo&machine=*" {authorizedUserId: "mdB7yD2dp1BFZPontHBQ1Z"} 200 (SUCCESS)
2021-06-25T17:00:48.000Z GET "/api/factory/machine/status?factory=seiko&machine=*" {authorizedUserId: "mdB7yD2dp1BFZPontHBQ1Z"} 200 (SUCCESS)
2021-06-25T17:00:48.000Z GET "/api/factory/machine/status?factory=shenzhen&machine=*" {authorizedUserId: "mdB7yD2dp1BFZPontHBQ1Z"} 200 (SUCCESS)
2021-06-25T17:00:48.000Z GET "/api/factory/machine/status?factory=berlin&machine=*" {authorizedUserId: "mdB7yD2dp1BFZPontHBQ1Z"} 200 (SUCCESS)
[... repetição idêntica às 18:00:48, 19:00:48 ... 23:00:48 ...]
2021-06-26T00:00:48.000Z GET "/api/factory/machine/status?factory=meiyo&machine=*" {authorizedUserId: "mdB7yD2dp1BFZPontHBQ1Z"} 401 (UNAUTHORIZED)
[... 60 requisições 401 até 16:00:48 ...]
2021-06-26T16:04:54.000Z POST "/login" {authorizedUserId: "mdB7yD2dp1BFZPontHBQ1Z"} 200 (SUCCESS)
2021-06-26T17:00:48.000Z GET "/api/factory/machine/status?factory=meiyo&machine=*" {authorizedUserId: "mdB7yD2dp1BFZPontHBQ1Z"} 200 (SUCCESS)
```

## 🌐 Resposta à Primeira Pergunta: Ataque Direto pela Internet?

**Conclusão: IMPOSSÍVEL**

| Evidência Técnica | Fundamentação |
|-------------------|---------------|
| **Todos os IPs são privados** | Logs contêm apenas endereços `192.168.0.x` (RFC 1918) — rede interna da Daikibo |
| **Dashboard na intranet** | Documentação do caso confirma: *"o painel está localizado na intranet da Daikibo"* |
| **Sem IPs públicos no log** | Nenhum endereço IPv4 público (ex: 8.8.8.8, 177.128.x.x) presente nas requisições |
| **Acesso requer tunneling** | Para atingir a intranet sem VPN, seria necessário: (a) comprometimento prévio de host interno, ou (b) falha de segmentação de rede (não evidenciada nos logs) |

> ✅ **Veredito:** O acesso ocorreu **dentro da rede corporativa** ou via **VPN autenticada**. Não há evidência de ataque direto pela internet sem prévio estabelecimento de presença na rede interna.

---

## 💡 Lições Técnicas para Resposta a Incidentes

1. **Assinatura temporal é forense poderosa**: Intervalos exatos (ex: `:00:48`) são *fingerprint* inequívoca de automação
2. **Fluxo de navegação quebrado = alerta**: Requisições diretas à API sem carregar frontend indicam bypass da interface
3. **Persistência pós-expiração revela script**: Humanos param após erro 401; scripts continuam executando
4. **Correlação de horários críticos**: Atividade na madrugada + padrão repetitivo = alto risco de coleta automatizada

---

## 🔒 Recomendações Técnicas

- Implementar rate limiting na API `/api/factory/machine/status`
- Adicionar validação de *user-agent* e fingerprinting de dispositivo
- Monitorar desvios do fluxo de navegação padrão (ex: API acessada sem prévia de assets frontend)
- Configurar alertas para padrões temporais não-humanos (intervalos fixos < 5min)

---

*Relatório gerado para fins educacionais em laboratório controlado da Deloitte Cyber Risk Services. Todos os dados são simulados para treinamento de análise forense.*
