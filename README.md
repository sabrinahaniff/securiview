# SecuriView  
**AI-Ready Static Application Security Scanner**

SecuriView is a modular security scanner that detects high-impact vulnerabilities in source code using rule-based analysis and optional AI explanations.  
It includes a clean frontend UI, multiple detectors, and a weighted risk-scoring system—making it a lightweight mini-SAST tool.

---

## Features

### Vulnerability Detection (OWASP-aligned)
SecuriView detects:

- **SQL Injection**
- **Cross-Site Scripting (XSS)**
- **Hardcoded Secrets**
- **Command Injection**
- **Dangerous Eval / Dynamic Code Execution**
- **Path Traversal**
- **Weak / Misconfigured Crypto**
- **JWT Misuse**
- **Open Redirects**

Each finding includes:
- Severity level  
- Line number  
- Snippet  
- Rule-based recommendation  

---

### AI-Enhanced Mode (Optional)
The `/analyze/ai` endpoint produces:

- Natural-language explanations  
- Fix recommendations  
- Attack scenarios  
- Per-finding context  

LLM integration is optional—the project is already structured to plug in models like Gemini or OpenAI.

---

### Risk Scoring  
Each run returns an **overall risk score (0–100)** based on weighted severity.

---

### Modular Detector Architecture  
Each detector lives independently under `/detectors`, making the system easy to extend:
detectors/
sql_injection.py
xss.py
secrets.py
command_injection.py
dangerous_eval.py
crypto.py
jwt.py
path_traversal.py
open_redirect.py
shared.py
---

### Frontend User Interface  
A lightweight HTML/JS UI allows:

- Pasting code  
- Selecting language  
- Choosing rule-based or AI mode  
- Viewing detailed cards for each finding  

Served automatically at:
http://127.0.0.1:8000
---

## Getting Started

### 1. Install dependencies
```bash
pip install -r requirements.txt
```
### 2. Run the backend

uvicorn main:app --reload

### 3. Open the UI

http://127.0.0.1:8000


