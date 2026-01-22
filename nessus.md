# 🔍 LAB PRÁTICO — Vulnerability Management com Nessus (Passo a Passo)

Este guia é **100% operacional**, focado apenas em **executar o projeto**.
Não é relatório, não é explicação teórica — é **o que fazer, na ordem certa**.

---

## 1️⃣ Preparação do Ambiente

### 1.1 Máquinas necessárias

* **Kali Linux / Kali Purple** → onde ficará o Nessus
* **Máquina alvo** (uma ou mais):

  * Metasploitable2 **ou**
  * Windows 10/11 **ou**
  * Ubuntu Server

> As máquinas devem estar na **mesma rede** (NAT ou Host-Only).

---

## 2️⃣ Instalação do Nessus

### 2.1 Criar conta Nessus Essentials

1. Acesse: [https://www.tenable.com/products/nessus/nessus-essentials](https://www.tenable.com/products/nessus/nessus-essentials)
2. Solicite a licença gratuita
3. Guarde o **Activation Code**

---

### 2.2 Download do Nessus

No Kali:

```bash
sudo apt update
wget https://www.tenable.com/downloads/api/v2/pages/nessus/files/Nessus-latest-debian10_amd64.deb
sudo dpkg -i Nessus-latest-debian10_amd64.deb
sudo systemctl start nessusd
sudo systemctl enable nessusd
```

---

### 2.3 Acessar interface web

No navegador:

```
https://localhost:8834
```

1. Escolha **Nessus Essentials**
2. Insira o Activation Code
3. Crie usuário e senha
4. **Aguarde o download dos plugins** (pode demorar)

⚠️ *Não avance enquanto os plugins não terminarem*

---

## 3️⃣ Validação do Funcionamento

1. Menu **Settings → About**
2. Verifique:

   * Plugins: ✔ Loaded
   * Feed: ✔ Current

Se não estiver assim → **não continue**.

---

## 4️⃣ Descoberta de Ativos

### 4.1 Identificar IP da máquina alvo

No alvo (Linux):

```bash
ip a
```

Ou no Kali:

```bash
ip route
```

Anote o IP.

---

## 5️⃣ Criar Scan de Vulnerabilidade

### 5.1 Criar scan

1. **Scans → New Scan**
2. Escolha:

   * *Basic Network Scan*

---

### 5.2 Configurar scan

**General**

* Name: `Lab - Vulnerability Scan`
* Targets: `IP_DO_ALVO`

**Discovery**

* Port scan: Default

**Assessment**

* Leave default

Clique **Save**

---

## 6️⃣ Executar Scan

1. Selecione o scan criado
2. Clique **Launch**
3. Aguarde finalizar (Status: Completed)

---

## 7️⃣ Análise dos Resultados (Execução)

### 7.1 Ver vulnerabilidades

1. Clique no scan finalizado
2. Analise:

   * Critical
   * High
   * Medium

---

### 7.2 Validar vulnerabilidade

1. Clique em uma vulnerabilidade
2. Verifique:

   * Description
   * CVE
   * Solution

---

## 8️⃣ Scan Autenticado (Opcional – Avançado)

### 8.1 Criar credenciais

1. **Settings → Credentials**
2. Add:

   * SSH (Linux) **ou**
   * Windows (SMB)

---

### 8.2 Associar credencial ao scan

1. Edite o scan
2. Aba **Credentials**
3. Selecione a credencial criada
4. Save

Execute novamente o scan.

---

## 9️⃣ Validação Final do Projeto

Confirme que você conseguiu:

* ✔ Instalar Nessus
* ✔ Atualizar plugins
* ✔ Executar scan
* ✔ Identificar vulnerabilidades
* ✔ Validar CVEs

---


