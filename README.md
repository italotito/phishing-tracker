# 🛡️ Phishing Tracker

Ferramenta em **Python** para análise automatizada de **URLs** e **arquivos de e-mail (`.eml`)** com foco na detecção de *phishing*.

---

## ✨ O que a ferramenta faz

- **Análise de Domínios e URLs**: Identifica imitações de marcas (*typosquatting*), caracteres camuflados (*Punycode*) e padrões suspeitos na estrutura do link.
- **Verificação de E-mails (`.eml`)**: Avalia autenticações de remetente (`SPF`, `DKIM`, `DMARC`), inconsistências de cabeçalho e anexos potencialmente perigosos.
- **Detecção de Engenharia Social**: Identifica gatilhos de urgência, ameaças falsas e links HTML camuflados no corpo da mensagem.
- **Threat Intelligence (Opcional)**: Consulta a reputação de links e hashes de arquivos via integração externa (VirusTotal).
- **Score de Risco (0 a 100)**: Consolida os sinais encontrados em uma classificação clara: **Seguro**, **Suspeito**, **Alto Risco** ou **Crítico**.

---

## 🛠️ Tecnologias

- **Python 3.11+**
- **FastAPI** (API REST)
- **Streamlit** (Painel Visual Interativo)
- **SQLite** (Histórico local de análises)

---

## 🚀 Como Instalar

1. **Crie e ative o ambiente virtual:**
   ```powershell
   python -m venv .venv
   .\.venv\Scripts\Activate.ps1
   ```

2. **Instale as dependências:**
   ```powershell
   pip install -r requirements.txt
   ```

3. **Configure as variáveis de ambiente (opcional):**
   Copie o arquivo de exemplo para habilitar consultas externas de reputação:
   ```powershell
   Copy-Item .env.example .env
   ```
   > **Nota:** A ferramenta funciona normalmente em modo local mesmo sem chave de API externa configurada.

---

## 💻 Como Usar

### 1. Painel Web (Streamlit)
Interface visual para testar URLs, enviar arquivos `.eml` e visualizar o histórico:
```powershell
streamlit run app.py
```

### 2. API REST (FastAPI)
Inicia o servidor web com documentação interativa disponível em `/docs`:
```powershell
uvicorn src.api:app --reload
```

### 3. Linha de Comando (CLI)
```powershell
# Executar demonstração rápida
python main.py --demo

# Analisar uma URL
python main.py --url "http://exemplo-suspeito.com"

# Analisar um arquivo de e-mail (.eml)
python main.py --email samples/phishing_urgente.eml

# Exportar resultado em JSON
python main.py --email samples/phishing_urgente.eml --json
```

---

## 🧪 Testes

Para rodar os testes automatizados do projeto:
```powershell
python -m unittest discover -s tests -v
```
