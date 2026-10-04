# 🛡️ Nexora Lab

**Um alvo de treino de pentest web — deliberadamente vulnerável, legal e gratuito.**

A Nexora Lab simula o portal interno de uma empresa fictícia ("Nexora Corp"):
loja/catálogo, área logada, chamados de suporte, ferramentas internas e um painel
administrativo. Por baixo dessa fachada normal há **várias falhas plantadas de
propósito** e **flags** (`flag{...}`) espalhadas para você capturar.

A proposta é simples: **treinar invasão web atacando um sistema que é seu**, em um
ambiente controlado, sem cometer crime nem depender de plataformas de terceiros.

---

## ⚖️ Aviso legal e ético (leia antes)

- Este projeto existe **exclusivamente para fins educacionais** e para você praticar
  em um ambiente **que você mesmo controla**.
- **Só ataque instâncias suas** (as que você subiu) ou um alvo que lhe deu
  **autorização explícita por escrito**.
- Atacar sistemas de terceiros sem autorização é **crime** (no Brasil, ex.: art.
  154-A do Código Penal — invasão de dispositivo informático; e legislações
  equivalentes em outros países).
- **Nunca** use este código como uma aplicação real nem reaproveite trechos dele em
  produção: ele é um alvo de tiro, cheio de buracos por design.

Usar para o bem é com você. 😉

---

## 🎯 Para quem é

- Quem está começando em segurança ofensiva e quer um laboratório próprio.
- Quem treina para **campeonatos / CTFs** de segurança web.
- Quem quer entender, na prática, por que certas construções de código são perigosas.

Não é preciso saber quais são as falhas — **essa é a graça**. Explore como um
atacante exploraria um sistema que vê pela primeira vez.

---

## 🧩 O que você vai treinar

Sem spoilers do "como": o laboratório cobre as classes de vulnerabilidade mais
cobradas em provas e no dia a dia de pentest web, entre elas:

- Injeção em banco de dados
- Falhas de autenticação e de controle de acesso
- Cross-Site Scripting (refletido e armazenado)
- Referência direta insegura a objetos (acesso a dados de outros usuários)
- Injeção no lado do servidor (templates / comandos)
- Travessia de diretórios e exposição de arquivos sensíveis
- Desserialização insegura
- Escalonamento de privilégios

Cada `flag{...}` encontrada é a **prova** de que uma técnica funcionou.

> 💡 Comece como visitante → crie uma conta comum em `/register` → veja até onde
> você consegue escalar.

---

## 🔄 O "renascimento" a cada 30 minutos

O mundo (banco de dados + arquivos) **se reconstrói sozinho**. Quando passa de 30
minutos desde o último reset, o laboratório volta ao estado inicial no próximo
acesso. Ou seja: você invade, modifica, derruba, defaça à vontade — e depois tudo
volta limpo, pronto para a próxima rodada.

Também dá para forçar um reset manual:

```
GET /__maintenance/reset?token=SEU_RESET_TOKEN
```

---

## 🧱 Stack

- **Python + Flask** (aplicação em um único `app.py`)
- **PostgreSQL** como banco
- **Gunicorn** como servidor

Dependências em [`requirements.txt`](./requirements.txt).

---

## 🚀 Suba a sua própria instância

> Recomendado rodar **a sua** instância (assim o estado é só seu). Abaixo, o
> caminho gratuito com **Neon** (banco) + **Render** (app). Também roda em qualquer
> VPS ou na sua máquina.

### 1. Banco (Neon — plano free)
1. Crie um projeto em [neon.tech](https://neon.tech).
2. Copie a **connection string** (ex.:
   `postgresql://user:senha@host.neon.tech/neondb?sslmode=require`).

### 2. App (Render — plano free)
1. Faça um **fork** deste repositório (ou use o seu).
2. No [Render](https://render.com): **New → Web Service** apontando para o repo.
3. Configure:
   - **Runtime:** Python
   - **Build Command:** `pip install -r requirements.txt`
   - **Start Command:** `gunicorn app:app --timeout 60`
4. Em **Environment**, defina as variáveis (tabela abaixo).
5. Deploy. No primeiro acesso o banco é populado automaticamente.

### 3. Rodar localmente
```bash
pip install -r requirements.txt
export DATABASE_URL="postgresql://user:senha@host/db?sslmode=require"
export RESET_TOKEN="um-token-aleatorio-forte"
gunicorn app:app --bind 0.0.0.0:5000
# abra http://localhost:5000
```

### Variáveis de ambiente

| Variável             | Obrigatória | Para quê                                             |
|----------------------|:-----------:|------------------------------------------------------|
| `DATABASE_URL`       | ✅          | Conexão com o PostgreSQL.                            |
| `RESET_TOKEN`        | ✅          | Protege o endpoint `/__maintenance/reset`.           |
| `RESET_INTERVAL_MIN` | ❌          | Intervalo do reset por validade (padrão: `30`).      |
| `DATA_DIR`           | ❌          | Pasta dos arquivos do servidor (padrão: `/tmp/...`). |
| `APP_SECRET`         | ❌          | Segredo de sessão (fraco por design no cenário).     |

---

## 🏁 Dicas para começar

- Mapeie a aplicação primeiro (recon): navegue, veja as rotas, os formulários e o
  que cada funcionalidade faz. `robots.txt` pode ajudar.
- Pense como atacante: onde a entrada do usuário chega "crua" até o banco, o
  sistema de arquivos, um template ou um comando?
- Anote cada `flag{...}` que capturar e a técnica que usou.

Travou de vez? Quem montou o seu lab pode ter deixado um **gabarito** à parte — use
só em último caso; abrir mata a graça.

---

## 📜 Licença e isenção

Projeto educacional, fornecido **"como está"**, sem garantias. O código é
**intencionalmente inseguro**. Os autores e contribuidores não se responsabilizam
por qualquer uso indevido. Ao usar, você concorda em empregá-lo apenas de forma
**legal e ética**, em ambientes próprios ou autorizados.

Bom hunting. 🎯
