/**
 * SentinelEdge v2.2 - Two-Tier Local Semantic AI DLP Engine
 * Integrates Chrome's Built-in Prompt API (window.ai.languageModel) + Local Semantic Heuristics
 * 100% Air-Gapped On-Device Processing (0 Cloud Calls)
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
  aiHandshakeTriggered?: boolean;
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

export function resetAiSession(): void {
  activeAiSession = null;
  isInitializing = false;
}

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
 * Context Trigger Gate: Fast regex scan for contextual anchors.
 * Returns true if text contains natural language secret triggers.
 */
export function hasSemanticTriggers(text: string): boolean {
  return /\b(?:passphrase|password|passcode|override\s+code|bypass|secret\s+token|secret\s+key|backdoor|master\s+key|master\s+password|login\s+is|card\s+pin)\b/i.test(text);
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
 * Local Semantic Secret Extractor
 * Scans text via Chrome's Prompt API or local rule-based fallback extractor, returning array of secret strings.
 */
export async function scanForSemanticSecrets(text: string): Promise<string[]> {
  if (!text || text.trim().length < 5) return [];

  // Check LRU cache first for instant lookup
  const cachedVal = getCachedSemanticSecret(text);
  if (cachedVal) {
    return [cachedVal];
  }

  const session = await getOrCreateAiSession();
  if (session) {
    try {
      const rawResponse = await session.prompt(text);
      const cleanedResponse = rawResponse.trim().replace(/^```json\s*|```$/g, '').trim();
      let parsed: { found?: boolean; secret?: string } = {};
      try {
        parsed = JSON.parse(cleanedResponse);
      } catch {}

      if (parsed.found && parsed.secret && text.includes(parsed.secret)) {
        cacheSemanticSecret(text, parsed.secret);
        return [parsed.secret];
      }
    } catch {}
  }

  const fallbackSecrets = fallbackSemanticHeuristicsList(text);
  if (fallbackSecrets.length > 0) {
    cacheSemanticSecret(text, fallbackSecrets[0]);
  }
  return fallbackSecrets;
}

/**
 * Deterministic Local Fallback Scanner
 * Lightweight rule-based semantic extractor for local test suites and unsupported environments.
 */
export function fallbackSemanticHeuristicsList(text: string): string[] {
  const semanticPatterns = [
    // Override code, bypass code, paywall code, QA code
    /(?:\b(?:override\s+code|bypass\s+code|paywall\s+code|access\s+code|testing\s+code|secret\s+code)\s+(?:is|=|:)?\s*['"]?)([a-zA-Z0-9_!@#$%^&*-]{4,64})(?=['"]?(?:[\s,;.]|$))/gi,
    // Master password, backdoor login, database password, secret token, passcode
    /(?:\b(?:master\s+password|backdoor\s+login|staging\s+password|database\s+password|admin\s+password|root\s+password|root\s+passcode|passcode|secret\s+key|access\s+key|auth\s+token|secret\s+token)\s+(?:is|=|:)?\s*['"]?)([a-zA-Z0-9_!@#$%^&*-]{4,64})(?=['"]?(?:[\s,;.]|$))/gi,
    // Action verbs followed by tokens (type in X, enter X, use X)
    /(?:\b(?:type\s+in|enter|use|input)\s+['"]?)([a-zA-Z0-9_!@#$%^&*-]{4,64})(?=['"]?\s+(?:whenever|when|for|as|if|to|in|into|on|at|with)\b[\s\S]{0,40}?\b(?:passphrase|password|secret|key|token|credential|login|ssh|bastion|auth|code|paywall|override)\b)/gi,
    // Declarations: the secret is X, the password is X
    /(?:\b(?:the|my|our)\s+(?:secret|password|access\s*key|passcode|root\s+passcode|override\s*code|master\s+password)\s+is\s+['"]?)([a-zA-Z0-9_!@#$%^&*-]{4,64})(?=['"]?(?:[\s,;.]|$))/gi,
    // Generic fallback for backdoor/admin passwords
    /\b(?:backdoor|admin|root|login|passcode|secret|password|access\s*key)[\s\S]{0,45}?\b(?:is|=|:)\s+['"]?([a-zA-Z0-9_!@#$%^&*]{4,32})['"]?/gi
  ];

  const secrets: string[] = [];
  for (const pat of semanticPatterns) {
    pat.lastIndex = 0;
    let match: RegExpExecArray | null;
    while ((match = pat.exec(text)) !== null) {
      if (match[1] && text.includes(match[1])) {
        secrets.push(match[1]);
      }
    }
  }

  return Array.from(new Set(secrets));
}

/**
 * Backward compatible wrapper returning SemanticScanResult object.
 */
export async function scanSemanticSecrets(text: string): Promise<SemanticScanResult> {
  const secrets = await scanForSemanticSecrets(text);
  if (secrets.length > 0) {
    return { isSecret: true, semanticThreats: secrets, explanation: "Semantic secret identified." };
  }
  return { isSecret: false, semanticThreats: [], explanation: "Clean" };
}

/**
 * MASTER INFERENCE & REPLACEMENT EXECUTION: executeAiRegexHandshake(rawText)
 * 1. Runs Fast-Path Regex first
 * 2. Fast-Exits if no contextual semantic triggers are found
 * 3. On-Device AI / Fallback Extraction & Substring Replacement
 */
export async function executeAiRegexHandshake(rawText: string): Promise<HandshakeResult> {
  // 1. Run Fast-Path Regex first
  let { sanitizedText, threatCount } = sanitizePayload(rawText);

  // 2. Fast-Exit if no contextual semantic triggers are found
  if (!hasSemanticTriggers(sanitizedText)) {
    return { sanitizedText, threatCount };
  }

  // 3. On-Device AI / Fallback Extraction
  try {
    const detectedSecrets = await scanForSemanticSecrets(sanitizedText);

    for (const secret of detectedSecrets) {
      if (secret && secret.trim().length > 0 && sanitizedText.includes(secret)) {
        // Safely replace the exact sensitive substring
        sanitizedText = sanitizedText.replaceAll(secret, '[REDACTED_SEMANTIC_SECRET]');
        threatCount++;
      }
    }
  } catch (err) {
    console.warn('[SentinelEdge] Semantic scan fallback engaged:', err);
  }

  return { sanitizedText, threatCount };
}
