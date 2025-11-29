# SecuriView 

SecuriView is an AI-ready static analysis backend for detecting common web vulnerabilities in source code.

## Features (current)

- **SQL Injection detection**
  - Flags dynamic string concatenation in SQL queries
- **Cross-Site Scripting (XSS) detection**
  - Detects dangerous DOM sinks (e.g., `innerHTML`, `document.write`)
  - Warns about raw HTML construction with unescaped variables
- **Secrets / Credentials detection**
  - AWS access keys (`AKIA...`)
  - Private key blocks
  - Hardcoded API keys, tokens, passwords

## Tech stack

- Python 3
- FastAPI
- Uvicorn

## Running locally

```bash
python -m venv .venv
source .venv/bin/activate   # Windows: .venv\Scripts\activate
python -m pip install "fastapi[standard]" python-multipart

uvicorn main:app --reload
