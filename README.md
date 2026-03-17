# RPA Challenge — Solução em Python

Automação dos três níveis de autenticação da plataforma RPA Challenge da doc9.

> Enunciado original: `CHALLENGE.md`

---

## Abordagem técnica

**Fácil:** automação de formulário HTTP com `requests.Session` para reuso de cookies entre requisições, simulando o comportamento de um navegador.

**Difícil:** autenticação mTLS com certificado do cliente extraído do container + engenharia reversa de challenge dinâmico gerado via JavaScript (`SHA256(timestamp + random + sufixo fixo)`), replicado em Python para envio na requisição.

**Extremo:** fluxo multi-etapa com quatro camadas de segurança:
- WebSocket autenticado via `ws_ticket` para receber o Proof-of-Work
- SHA256 iterativo para encontrar o nonce que satisfaz a dificuldade exigida
- AES-256-CBC com chave derivada de `SHA256(session_id + "extreme_secret_key")` para descriptografar o OTP
- Token intermediário com TTL de 10 segundos para prevenção de replay attack

---

## Estrutura

```
rpa_challenge/
├── scripts/
│   ├── easy_login.py      # nível fácil
│   ├── hard_login.py      # nível difícil (mTLS + challenge dinâmico)
│   └── extreme_login.py   # nível extremo (WebSocket + PoW + AES-256-CBC)
├── .env.example
├── requirements.txt
└── README.md
```

---

## Pré-requisitos

- Python 3.10+
- Docker em execução

---

## Subir o ambiente

```bash
docker pull doc9cloud/rpa-challenge:latest
docker run -d -p 3000:3000 -p 3001:3001 --name rpa-challenge doc9cloud/rpa-challenge:latest
```

---

## Instalar dependências

```bash
pip install -r requirements.txt
```

---

## Configuração

Copie `.env.example` para `.env` e ajuste as credenciais se necessário:

```bash
# Linux/macOS
cp .env.example .env

# Windows
copy .env.example .env
```

Sem `.env`, os scripts utilizam os valores padrão do desafio.

### Variáveis de ambiente

| Variável          | Padrão          |
|-------------------|-----------------|
| EASY_USERNAME     | admin           |
| EASY_PASSWORD     | rpa@2026!       |
| HARD_USERNAME     | operator        |
| HARD_PASSWORD     | cert#Secure2026 |
| EXTREME_USERNAME  | root            |
| EXTREME_PASSWORD  | h4ck3r@Pr00f!   |

---

## Executar nível fácil

Execute a partir de `rpa_challenge/`:

```bash
python scripts/easy_login.py
```

### Opções

```bash
python scripts/easy_login.py --verify-tls
```

---

## Executar nível difícil

Extraia os certificados do container (na pasta pai de `rpa_challenge/`):

```bash
docker cp rpa-challenge:/app/certs/client.pfx .
docker cp rpa-challenge:/app/certs/ca.crt .
```

Execute a partir de `rpa_challenge/`:

```bash
python scripts/hard_login.py --ca-cert "..\ca.crt" --client-pfx "..\client.pfx" --pfx-password test123
```

Ou com certificado/chave em formato PEM:

```bash
python scripts/hard_login.py --ca-cert "..\ca.crt" --client-cert "<cert.pem>" --client-key "<key.pem>"
```

---

## Executar nível extremo

Execute a partir de `rpa_challenge/`:

```bash
python scripts/extreme_login.py
```

> O nível extremo pode levar alguns segundos devido ao Proof-of-Work (dificuldade 5 — ~50.000 a 500.000 iterações SHA256).

---

## Saída esperada

Todos os scripts imprimem um resumo por etapa e um resumo final padronizado com `success`, `final_token` e `elapsed_ms`.

**Nível fácil:**
```
=== Easy Challenge ===
success: True
message: Autenticação bem-sucedida!
level: easy
token: <TOKEN>
api_elapsed_ms: 44
local_elapsed_ms: 87
=== Easy Challenge (final) ===
easy_success: True
final_token: <TOKEN>
elapsed_ms: 87
```

**Nível difícil:**
```
=== Hard Challenge (final) ===
hard_success: True
final_token: <TOKEN>
elapsed_ms: 85
```

**Nível extremo:**
```
=== Extreme Challenge (final) ===
extreme_success: True
final_token: <TOKEN>
elapsed_ms: 4222
```

---

## Resultados

| Nível   | Status       | Tempo médio |
|---------|--------------|-------------|
| Fácil   | Implementado | ~87ms       |
| Difícil | Implementado | ~85ms       |
| Extremo | Implementado | ~4.2s       |

> O tempo do nível extremo varia conforme o nonce encontrado no Proof-of-Work.

---

## Observações

- Ambiente local usa certificado autoassinado (`https://localhost`). Por padrão, a validação TLS está desativada para facilitar execução; use `--verify-tls` (fácil) ou `--ca-cert` (difícil) quando a cadeia de confiança estiver configurada.
- O `elapsed_ms` reportado pelo script inclui toda a comunicação de rede. O `api_elapsed_ms` (nível fácil) representa apenas o tempo de processamento do servidor.
