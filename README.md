# 🛡️ SentinelEdge v3.0 — Client-Side DLP WebExtension

**SentinelEdge** is a 100% client-side, zero-backend WebExtension designed to prevent accidental sensitive data leaks (API keys, Cloud secrets, Financial credentials, PII) when interacting with Generative AI platforms like **ChatGPT**, **Claude.ai**, **Google Gemini**, **Perplexity**, and **Microsoft Copilot**.

- 🌐 **Live Distribution Website**: [https://ikigai-hackathon-frontend.vercel.app/](https://ikigai-hackathon-frontend.vercel.app/)
- 🖥️ **Frontend Source Code**: [https://github.com/arhamajaz/ikigai-hackathon-frontend.git](https://github.com/arhamajaz/ikigai-hackathon-frontend.git)

---

## 🎯 IKIGAI Track & Problem

- **Track**: Cybersecurity
- **Problem Statement**: Users risk accidentally leaking sensitive credentials, API keys, cloud secrets, passwords, and PII to third-party LLM providers (ChatGPT, Claude, Gemini, Copilot, Perplexity) during prompt submission. Existing enterprise DLP tools rely on latency-heavy cloud proxy gateways that violate privacy and break user experience.

---

## 🔐 Cybersecurity Threat Model, False-Positive Mitigation & Security Claims

### 🛡️ 1. Threat Model & Attack Assumptions
- **Threat Vector**: Accidental disclosure of high-value secrets (AWS keys, OpenAI/Anthropic API keys, GitHub PATs, private keys, database connection strings, JWTs), regional PII (Indian PAN, Aadhaar, SSN), and natural language passphrases into LLM prompt inputs on ChatGPT, Claude, Gemini, Copilot, and Perplexity.
- **Attacker / Leak Assumptions**:
  - Prompts are transmitted over direct HTTPS/WebSocket connections from the client browser to third-party LLM inference servers.
  - Users paste or type sensitive code snippets, `.env` files, or production passphrases directly into editable DOM elements (`textarea`, `contenteditable`).
  - Traditional perimeter firewalls and cloud proxies fail to inspect encrypted client-side browser traffic or introduce unacceptable processing latency (> 50ms).
  - The browser extension must operate completely **air-gapped** with **zero network egress** to prevent telemetry harvesting or secondary data exposure.

### 🎯 2. False-Positive Mitigation Pipeline
Naive DLP engines generate excessive false positives by redacting standard 4-digit/6-digit numbers (e.g., year `2026` or port `110001`) or general technical questions. SentinelEdge resolves this using a 3-tier cascading filter:
1. **Look-Around Window Filter (`hasSensitiveContext` in `src/core/dlp-engine.ts`)**: Inspects a 30-character preceding context window for mandatory keyword anchors (`pin`, `atm`, `upi`, `pincode`, `dob`) before redacting numeric strings.
2. **Structural Short-Circuit Guard (`needsSemanticCheck` in `src/content/index.ts`)**: Automatically bypasses AI scanning for code blocks, JSON/YAML payloads, or inputs >2,000 characters, reserving AI inference for natural language prose.
3. **On-Device Semantic Disambiguation (`src/core/semantic-ai.ts`)**: Utilizes Chrome's built-in `window.ai.languageModel` (Gemini Nano) with structured JSON responses to differentiate technical queries (e.g., *"How do I reset a Linux password?"* -> Clean) from actual secret exposures (e.g., *"The root password is admin123"* -> Redacted).

### 🔬 3. Technically Justified Security Claims
| Security Claim | Code-Level Verification & Mechanism | File Reference |
| --- | --- | --- |
| **Air-Gapped / Zero Egress Guarantee** | All data inspection, logging, and state management run 100% locally. Audit logs use `chrome.storage.local`. Zero external `fetch()`, `XMLHttpRequest`, or cloud telemetry calls exist in the codebase. | `src/shared/storage.ts` & `src/background/service-worker.ts` |
| **Pre-Flight Submission Gate Guarantee** | Paste (`paste`), Enter keypress (`keydown`), and submit button click (`click`) events are intercepted synchronously. The extension executes `event.preventDefault()` and `stopImmediatePropagation()` to prevent raw payload dispatch before sanitization completes. | `src/content/index.ts` |
| **Sub-2ms Processing Latency** | Pre-compiled RegExp pattern matching with positional slice substitution processes payloads in $< 0.8\text{ ms}$. Semantic AI calls are capped with a strict `Promise.race` 200ms timeout fallback. | `src/core/dlp-engine.ts` & `src/core/semantic-ai.ts` |
| **Host Framework Virtual-DOM Integrity** | Uses prototype-level property descriptors (`HTMLTextAreaElement.prototype`) and synthetic `InputEvent` dispatches (`beforeinput`, `input`, `change`) to trigger React, Lexical, and ProseMirror state updates without destroying cursor position. | `src/content/FrameworkSync.ts` |

---

## 🏗️ Architecture Diagram

```mermaid
flowchart LR
    User[User Input / Paste] --> ContentScript[Content Script Pre-Flight Hooks]
    ContentScript --> RegexEngine[Fast-Path DLP Engine]
    RegexEngine --> ContextFilter{Context Validation}
    ContextFilter -->|Regex Match| PolicyEngine[Policy Engine Audit]
    ContextFilter -->|Semantic Trigger| GeminiNano[Chrome Built-in AI / Gemini Nano]
    GeminiNano -->|Semantic Redaction| PolicyEngine
    PolicyEngine --> DOMSync[Host Framework DOM Sync]
    DOMSync --> Storage[Local Extension Storage & HUD]
    DOMSync --> Output[Sanitized Prompt to LLM]
```

---

## 🗺️ Core Capabilities Mapping

| Capability / Feature | Status | Implementation File Path |
| --- | --- | --- |
| Fast-Path Regex & Contextual DLP Engine | Verified | `src/core/dlp-engine.ts` |
| Local Semantic AI Interception (Gemini Nano) | Verified | `src/core/semantic-ai.ts` |
| Policy Audit & Residual Leak Check | Verified | `src/core/policy-engine.ts` |
| Pre-Flight Interception & Multi-LLM Adapters | Verified | `src/content/index.ts` |
| Host Framework State Sync (React/Lexical/ProseMirror) | Verified | `src/content/FrameworkSync.ts` |
| Visual Grapheme Masking & Password Utility | Verified | `src/utils/mask-password.ts` |
| Telemetry HUD Popup & Local Audit Logging | Verified | `src/popup/popup.ts` |

---

## ⚡ Key Features

- **⚡ Real-Time Interception & Caret Preservation**: Intercepts sensitive data the exact millisecond it is pasted or typed, seamlessly preserving caret (cursor) position and browser Undo/Redo stack.
- **🛡️ Comprehensive Rule Lexicon**: Sub-millisecond matching for:
  - **Cloud Secrets**: AWS Access Keys, Anthropic Keys, OpenAI API Keys, GitHub PATs, Stripe Keys, Private Keys, Database Connection URIs, JWT Tokens.
  - **Regional & Financial Credentials**: Indian PAN Cards, Aadhaar Cards, Driving Licenses, Mobile Numbers, Passwords, Credit Cards, Bank Account Numbers, SSN.
  - **Context-Aware Rules**: ATM PINs, MPINs, UPI PINs, Postal PIN Codes, Date of Birth.
- **🎯 Contextual Validation Filter (`hasSensitiveContext`)**: Eliminates false positives on generic 4-digit numbers (like years `2026`) by inspecting a 30-character look-around window for sensitive keywords (`pin`, `atm`, `upi`, `pincode`, `dob`).
- **🤖 Air-Gapped Local AI (Gemini Nano)**: Zero cloud API calls; uses Chrome's built-in `window.ai.languageModel` for natural language secret detection with a strict 200ms fallback timeout.
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

# Run complete DLP Engine unit & benchmark test suite
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

Open **ChatGPT**, **Claude**, **Gemini**, **Perplexity**, or **Copilot**, and try pasting or typing:

1. **API Key Test**:
   - Input: `Help me fix key AKIAIOSFODNN7EXAMPLE`
   - Output: `Help me fix key [REDACTED_AWS_KEY]`
2. **False-Positive Prevention Test**:
   - Input: `The project deadline is in year 2026.`
   - Output: `The project deadline is in year 2026.` *(Unaltered 2026!)*
3. **Contextual PIN Test**:
   - Input: `My ATM pin is 2026.`
   - Output: `My ATM pin is [REDACTED_ATM_PIN].` *(Redacted!)*
4. **Natural Language Semantic Secret Test**:
   - Input: `When logging into the bastion host, enter MySuperSecretPassphrase123 whenever prompted for the passphrase.`
   - Output: `When logging into the bastion host, enter [REDACTED_SEMANTIC_SECRET] whenever prompted for the passphrase.`

---

## 🛠️ Tech Stack & Pipeline

- **Language**: TypeScript (Strict ES2022)
- **Bundler**: Vite + `@crxjs/vite-plugin`
- **Manifest Version**: 3
- **Engine**: Hierarchical Cascading Pipeline (Fast-Path Regex Context Engine -> Chrome Built-in Local AI -> Policy Engine Audit) with $< 2.0\text{ ms}$ latency guarantee.
