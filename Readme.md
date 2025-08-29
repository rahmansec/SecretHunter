# 🔍 Secret Hunter – Find Hardcoded Secrets in JavaScript

A high-performance tool for **bug bounty hunters** and **security researchers** to **detect hardcoded secrets, API keys, tokens, and sensitive credentials in JavaScript and JSON files**.

---

## ✅ Features

✔ Detects:

* API keys & tokens (OpenAI, Stripe, Twilio, Telegram, etc.)
* Cloud credentials (AWS, GCP, Azure)
* Webhooks (Slack, Discord)
* JWT tokens
* SSH private keys
* Database credentials
* Financial data (Credit Cards, CVV, IBAN)

✔ **Regex-based detection** with support for custom patterns via a JSON file

✔ **Multi-threaded scanning** for speed (default: 50 threads)

✔ **Beautiful progress bars** and colorized output using [Rich](https://github.com/Textualize/rich)

✔ Designed for **Bug Bounty & Recon workflows**


---

## 🚀 Installation

Clone the repository:

```bash
git clone https://github.com/your-username/secret-hunter.git
cd secret-hunter
```

Install dependencies:

```bash
pip install -r requirements.txt
```

---

## 🔍 Usage

### **Scan URLs from a file**

```bash
python secret-hunter.py -i urls.txt -p patterns.json
```

### **Options**

| Argument         | Description                                  |
| ---------------- | -------------------------------------------- |
| `-i, --file`     | File containing URLs to scan                 |
| `-p, --patterns` | JSON file with regex patterns for secrets    |
| `-t, --threads`  | Number of threads (default: 50)              |
| `--timeout`      | HTTP request timeout in seconds (default: 6) |

---

## ✅ Example

**urls.txt**

```
https://target.com/main.js
https://target.com/config.json
```

**Run the scan**

```bash
python secret-hunter.py -i urls.txt -p patterns.json
```

**Sample Output**

```
⚠️ Secrets found in https://target.com/main.js
- Slack Token: xoxb-1234567890-abcdef
- OpenAI API Key: sk-xxxxxxxxxxxxxxxxxxxxxxxx
```

---

## 📦 Patterns JSON Example

`patterns.json` example:

```json
[
  {
    "name": "Generic API Key",
    "regex": "(api[_-]?key|token|auth|secret)[\"'\\s:=>]{1,10}[^\"'\\s]+",
    "confidence": "medium"
  },
  {
    "name": "AWS Access Key ID",
    "regex": "AKIA[0-9A-Z]{16}",
    "confidence": "high"
  },
  {
    "name": "OpenAI API Key",
    "regex": "sk-[A-Za-z0-9]{48}",
    "confidence": "high"
  }
]
```

---

## 🛠 Tech Stack

* **Python 3.8+**
* [requests](https://docs.python-requests.org/)
* [rich](https://github.com/Textualize/rich)
* [regex](https://pypi.org/project/regex/)

---

## 🔐 Why Use It for Bug Bounty?

✔ Find **exposed API keys** in public repos or JS files

✔ Detect **secrets in web application assets**

✔ Automate **credential leak detection during recon**

✔ Increase chances of valid findings in bounty programs

---

## ✅ Future Features

* [ ] Export results to JSON / CSV

