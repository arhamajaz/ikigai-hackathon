# 🛡️ SentinelEdge v1.2 — Client-Side DLP Firewall Chrome & Firefox Extension

**SentinelEdge** is a 100% client-side, zero-backend WebExtension designed to prevent accidental sensitive data leaks (API keys, Cloud secrets, Financial credentials, PII) when interacting with Generative AI platforms like **ChatGPT**, **Claude.ai**, and **Google Gemini**.

---

## ⚡ Key Features

- **⚡ Real-Time Masking & Caret Preservation**: Intercepts sensitive data the exact millisecond it is pasted or typed, seamlessly preserving caret (cursor) position and browser Undo/Redo stack.
- **🛡️ 20 DLP Rule Lexicon**: Sub-millisecond matching for:
  - **Cloud Secrets**: AWS Access Keys, OpenAI API Keys, GitHub PATs, Stripe Keys, Private Keys, Database URIs, JWT Tokens.
  - **Regional & Financial Credentials**: Indian PAN Cards, Aadhaar Cards, Driving Licenses, Mobile Numbers, Passwords, Credit Cards, SSN.
  - **Context-Aware Rules**: ATM PINs, MPINs, UPI PINs, Postal PIN Codes, Date of Birth.
- **🎯 Contextual Validation Filter (`hasSensitiveContext`)**: Eliminates false positives on generic 4-digit numbers (like years `2026`) by inspecting a 30-character look-around window for sensitive keywords (`pin`, `atm`, `upi`, `pincode`, `dob`).
- **🌐 Universal Browser Support**: Manifest V3 compliant, ready out-of-the-box for **Google Chrome**, **Brave**, **Mozilla Firefox**, **Microsoft Edge**, **Arc**, and **Comet**.

---

## 🚀 Quick Start & Installation

### 1. Build from Source
```bash
# Clone the repository
git clone https://github.com/arhamajaz/ikigai-hackathon.git
cd ikigai-hackathon

# Install dependencies
npm install

# Run DLP Engine unit tests
npm test

# Build production bundle
npm run build
```

### 2. Load Unpacked Extension in Chrome / Brave / Edge
1. Open `chrome://extensions` (or `brave://extensions` / `edge://extensions`).
2. Enable **Developer mode** toggle in top-right.
3. Click **Load unpacked** and select the `/dist` directory (`ikigai-hackathon/dist`).

### 3. Load Temporary Add-on in Mozilla Firefox
1. Open `about:debugging#/runtime/this-firefox`.
2. Click **Load Temporary Add-on...**
3. Select `dist/manifest.json`.

---

## 🧪 Testing DLP Protection

Open **ChatGPT**, **Claude**, or **Gemini**, and try pasting or typing:

1. **API Key Test**:
   - Input: `Help me fix key AKIAIOSFODNN7EXAMPLE`
   - Output: `Help me fix key [REDACTED_AWS_KEY]`
2. **False-Positive Prevention Test**:
   - Input: `The project deadline is in year 2026.`
   - Output: `The project deadline is in year 2026.` *(Unaltered 2026!)*
3. **Contextual PIN Test**:
   - Input: `My ATM pin is 2026.`
   - Output: `My ATM pin is [REDACTED_ATM_PIN].` *(Redacted!)*

---

## 🛠️ Tech Stack & Architecture

- **Language**: TypeScript (Strict ES2022)
- **Bundler**: Vite + `@crxjs/vite-plugin`
- **Manifest Version**: 3
- **Engine**: Regular Expression Engine with Look-Around Context Filters ($< 0.8\text{ ms}$ processing time)
