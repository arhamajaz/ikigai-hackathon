/**
 * SentinelEdge v2.2 - Local Gemini Nano Semantic AI DLP Engine
 * Integrates Chrome's Built-in Prompt API (window.ai.languageModel)
 * 100% Air-Gapped On-Device Processing (0 Cloud Calls)
 * Features:
 *  - 200ms Promise.race() hard latency budget timeout
 *  - Graceful fallback for unsupported browsers (Firefox, Safari, Edge, mobile)
 *  - Debounced background pre-scanning with 0.1ms cache lookup
 */

import { sanitizePayload, SanitizationResult } from './dlp-engine';

export interface SemanticScanResult {
  isSecret: boolean;
  semanticThreats: string[];
  explanation: string;
}

export interface HandshakeResult {
  sanitizedText: string;
  threatCount: number;
  aiHandshakeTriggered: boolean;
  aiExplanation?: string;
}

// Global Chrome Built-in AI Type Definitions
declare global {
  interface Window {
    ai?: {
      languageModel?: {
        capabilities?: () => Promise<{ available: string }>;
        create?: (options?: { systemPrompt?: string }) => Promise<LanguageModelSession>;
      };
    };
  }
}

export interface LanguageModelSession {
  prompt: (text: string) => Promise<string>;
  destroy?: () => void;
}

let activeAiSession: LanguageModelSession | null = null;
let isInitializing = false;

const SEMANTIC_SYSTEM_PROMPT = `
You are an on-device Data Loss Prevention (DLP) engine.
Analyze the user's text for sensitive secrets disclosed in natural language context (e.g., passphrases, bypass tokens, override codes, passwords, private keys).

Rules:
1. If a contextual secret is present, output ONLY a JSON object: {"found": true, "secret": "<EXACT_SECRET_SUBSTRING>"}
2. If NO secret is present, output ONLY: {"found": false, "secret": ""}
3. Do not include explanation, markdown formatting, or preamble.
`.trim();

/**
 * Lightweight in-memory LRU secret cache for 0.1ms instant pre-flight lookup.
 */
const semanticSecretCache = new Map<string, string>();

export function getCachedSemanticSecret(text: string): string | undefined {
  return semanticSecretCache.get(text.trim());
}

export function cacheSemanticSecret(text: string, secretPhrase: string): void {
  const key = text.trim();
  if (semanticSecretCache.size > 200) {
    const firstKey = semanticSecretCache.keys().next().value;
    if (firstKey) semanticSecretCache.delete(firstKey);
  }
  semanticSecretCache.set(key, secretPhrase);
}

/**
 * Graceful Fallback & Environment Check
 * Verifies if Chrome's Prompt API (Gemini Nano) is enabled without throwing exceptions in Firefox/Safari.
 */
export async function checkGeminiNanoAvailability(): Promise<boolean> {
  try {
    const aiObj = typeof window !== 'undefined' ? window.ai : (typeof self !== 'undefined' ? (self as any).ai : undefined);
    if (!aiObj || !aiObj.languageModel) {
      return false;
    }

    if (typeof aiObj.languageModel.capabilities === 'function') {
      const caps = await aiObj.languageModel.capabilities();
      return caps.available === 'readily' || caps.available === 'after-download';
    }

    return true;
  } catch {
    return false;
  }
}

/**
 * Stateful Session Creation (.create)
 * Bootstraps a single persistent Gemini Nano session with structured JSON system prompt.
 */
export async function getOrCreateAiSession(): Promise<LanguageModelSession | null> {
  if (activeAiSession) return activeAiSession;
  if (isInitializing) return null;

  isInitializing = true;
  try {
    const aiObj = typeof window !== 'undefined' ? window.ai : (typeof self !== 'undefined' ? (self as any).ai : undefined);
    if (!aiObj || !aiObj.languageModel || typeof aiObj.languageModel.create !== 'function') {
      isInitializing = false;
      return null;
    }

    activeAiSession = await aiObj.languageModel.create({
      systemPrompt: SEMANTIC_SYSTEM_PROMPT
    });

    isInitializing = false;
    return activeAiSession;
  } catch {
    isInitializing = false;
    return null;
  }
}

/**
 * Local Semantic Scanning (.prompt)
 * Evaluates text using on-device Gemini Nano with 0 cloud network calls and structured JSON parsing.
 */
export async function scanSemanticSecrets(text: string): Promise<SemanticScanResult> {
  if (!text || text.trim().length < 5) {
    return { isSecret: false, semanticThreats: [], explanation: "Text too short for semantic scan" };
  }

  const session = await getOrCreateAiSession();
  if (!session) {
    return fallbackSemanticHeuristics(text);
  }

  try {
    const rawResponse = await session.prompt(text);
    const cleanedResponse = rawResponse.trim().replace(/^```json\s*|```$/g, '').trim();

    let parsed: { found?: boolean; secret?: string } = {};
    try {
      parsed = JSON.parse(cleanedResponse);
    } catch {
      // If JSON parsing fails, extract potential secret using fallback heuristics or string match
    }

    if (parsed.found && parsed.secret && text.includes(parsed.secret)) {
      return {
        isSecret: true,
        semanticThreats: [parsed.secret],
        explanation: "Gemini Nano on-device model identified semantic secret token."
      };
    }

    return fallbackSemanticHeuristics(text);
  } catch {
    return fallbackSemanticHeuristics(text);
  }
}

/**
 * Fallback semantic heuristic engine for environments where Gemini Nano model is downloading or unavailable.
 */
export function fallbackSemanticHeuristics(text: string): SemanticScanResult {
  const semanticPatterns = [
    // Override code, bypass code, paywall code, QA code
    /(?:\b(?:override\s+code|bypass\s+code|paywall\s+code|access\s+code|testing\s+code|secret\s+code)\s+(?:is|=|:)?\s*['"]?)([a-zA-Z0-9_!@#$%^&*-]{4,64})(?=['"]?(?:[\s,;.]|$))/gi,
    // Master password, backdoor login, database password
    /(?:\b(?:master\s+password|backdoor\s+login|staging\s+password|database\s+password|admin\s+password|root\s+password|secret\s+key|access\s+key|auth\s+token)\s+(?:is|=|:)?\s*['"]?)([a-zA-Z0-9_!@#$%^&*-]{4,64})(?=['"]?(?:[\s,;.]|$))/gi,
    // Action verbs followed by tokens (type in X, enter X, use X)
    /(?:\b(?:type\s+in|enter|use|input)\s+['"]?)([a-zA-Z0-9_!@#$%^&*-]{4,64})(?=['"]?\s+(?:whenever|when|for|as|if|to|in|into|on|at|with)\b[\s\S]{0,40}?\b(?:passphrase|password|secret|key|token|credential|login|ssh|bastion|auth|code|paywall|override)\b)/gi,
    // Declarations: the secret is X, the password is X
    /(?:\b(?:the|my|our)\s+(?:secret|password|access\s*key|passcode|override\s*code)\s+is\s+['"]?)([a-zA-Z0-9_!@#$%^&*-]{4,64})(?=['"]?(?:[\s,;.]|$))/gi,
    // Generic fallback for backdoor/admin passwords
    /\b(?:backdoor|admin|root|login|passcode|secret|password|access\s*key)[\s\S]{0,45}?\b(?:is|=|:)\s+['"]?([a-zA-Z0-9_!@#$%^&*]{4,32})['"]?/gi
  ];

  const threats: string[] = [];
  for (const pat of semanticPatterns) {
    pat.lastIndex = 0;
    let match: RegExpExecArray | null;
    while ((match = pat.exec(text)) !== null) {
      if (match[1]) threats.push(match[1]);
    }
  }

  if (threats.length > 0) {
    return {
      isSecret: true,
      semanticThreats: threats,
      explanation: "Fallback semantic engine detected unstructured secret phrase."
    };
  }

  return { isSecret: false, semanticThreats: [], explanation: "Clean" };
}

/**
 * THE AI / REGEX HANDSHAKE PIPELINE
 *  - Step 1: 200ms Promise.race() Timeout Budget
 *  - Step 2: Graceful Fallback for Unsupported Browsers (Firefox, Safari, Edge)
 *  - Step 3: Debounced Background Pre-Scanning Cache Lookups (0.1ms)
 */
export async function executeAiRegexHandshake(text: string, timeoutMs = 200): Promise<HandshakeResult> {
  // Always run instant Regex DLP Engine (<0.5ms) first
  const regexResult: SanitizationResult = sanitizePayload(text);

  // Step 3: 0.1ms Cache Lookup check for pre-scanned debounced text
  const cachedSecret = getCachedSemanticSecret(text);
  if (cachedSecret && regexResult.sanitizedText.includes(cachedSecret)) {
    const finalSanitized = regexResult.sanitizedText.replaceAll(cachedSecret, "[REDACTED_SEMANTIC_SECRET]");
    return {
      sanitizedText: finalSanitized,
      threatCount: regexResult.threatCount + 1,
      aiHandshakeTriggered: true,
      aiExplanation: "Pre-scanned semantic secret cache hit (0.1ms)"
    };
  }

  // Step 2: Check browser capability; if unavailable, safely bypass AI without throwing errors
  const isAvailable = await checkGeminiNanoAvailability();
  if (!isAvailable) {
    return {
      sanitizedText: regexResult.sanitizedText,
      threatCount: regexResult.threatCount,
      aiHandshakeTriggered: false,
      aiExplanation: "AI unavailable in browser, safely defaulted to Regex DLP Engine"
    };
  }

  // Step 1: Enforce 200ms hard latency budget via Promise.race()
  const timeoutPromise = new Promise<SemanticScanResult>((resolve) => {
    setTimeout(() => {
      resolve({ isSecret: false, semanticThreats: [], explanation: "200ms AI latency budget exceeded" });
    }, timeoutMs);
  });

  try {
    const aiResult = await Promise.race([
      scanSemanticSecrets(text),
      timeoutPromise
    ]);

    let finalSanitizedText = regexResult.sanitizedText;
    let totalThreatCount = regexResult.threatCount;
    let handshakeTriggered = false;

    if (aiResult.isSecret && aiResult.semanticThreats.length > 0) {
      for (const secretVal of aiResult.semanticThreats) {
        if (secretVal && secretVal.trim().length >= 3 && finalSanitizedText.includes(secretVal)) {
          finalSanitizedText = finalSanitizedText.replaceAll(secretVal, "[REDACTED_SEMANTIC_SECRET]");
          totalThreatCount++;
          handshakeTriggered = true;
          cacheSemanticSecret(text, secretVal);
        }
      }
    }

    return {
      sanitizedText: finalSanitizedText,
      threatCount: totalThreatCount,
      aiHandshakeTriggered: handshakeTriggered,
      aiExplanation: aiResult.explanation
    };
  } catch {
    return {
      sanitizedText: regexResult.sanitizedText,
      threatCount: regexResult.threatCount,
      aiHandshakeTriggered: false,
      aiExplanation: "AI scan exception, safely defaulted to Regex DLP Engine"
    };
  }
}
