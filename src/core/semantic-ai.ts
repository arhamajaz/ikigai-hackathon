/**
 * SentinelEdge v3.0 - Two-Tier Local Semantic AI DLP Engine
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
Analyze the user's text for sensitive credentials or secrets disclosed in natural language context (e.g., passphrases, override codes, passwords, auth tokens, security answers, master keys).

Rules:
1. If credentials or secrets are present, output ONLY a JSON object containing an array of all exact secret substrings found: {"found": true, "secrets": ["<SECRET_1>", "<SECRET_2>"]}.
2. If NO secret is present or if the text is a general technical question without disclosing actual credentials, output ONLY: {"found": false, "secrets": []}.
3. Do not include markdown code fences, explanations, or preamble.
`.trim();

/**
 * Lightweight in-memory LRU secret cache for 0.1ms instant pre-flight lookup.
 */
const semanticSecretCache = new Map<string, string[]>();

export function getCachedSemanticSecrets(text: string): string[] | undefined {
  return semanticSecretCache.get(text.trim());
}

export function cacheSemanticSecrets(text: string, secrets: string[]): void {
  const key = text.trim();
  if (semanticSecretCache.size > 200) {
    const firstKey = semanticSecretCache.keys().next().value;
    if (firstKey) semanticSecretCache.delete(firstKey);
  }
  semanticSecretCache.set(key, secrets);
}

// Backward compatibility helpers
export function getCachedSemanticSecret(text: string): string | undefined {
  const secrets = getCachedSemanticSecrets(text);
  return secrets && secrets.length > 0 ? secrets[0] : undefined;
}

export function cacheSemanticSecret(text: string, secretPhrase: string): void {
  cacheSemanticSecrets(text, [secretPhrase]);
}

/**
 * Context Trigger Guard: Fast regex scan for contextual anchors.
 * Returns true if text contains natural language secret triggers.
 */
export function hasSemanticTriggers(text: string): boolean {
  return /\b(?:passphrase|password|passcode|override\s+code|bypass|secret\s+token|secret\s+key|backdoor|master\s+key|master\s+password|login\s+is|auth\s+token|security\s+answer|card\s+pin)\b/i.test(text);
}

export const shouldTriggerSemanticCheck = hasSemanticTriggers;

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
 * Scans text via Chrome's Prompt API or local rule-based fallback extractor, returning array of all secret strings found.
 */
export async function scanForSemanticSecrets(text: string): Promise<string[]> {
  if (!text || text.trim().length < 5) return [];

  // Check LRU cache first for instant lookup
  const cachedSecrets = getCachedSemanticSecrets(text);
  if (cachedSecrets && cachedSecrets.length > 0) {
    return cachedSecrets;
  }

  const session = await getOrCreateAiSession();
  if (session) {
    try {
      const rawResponse = await session.prompt(text);
      const cleanedResponse = rawResponse.trim().replace(/^```json\s*|```$/g, '').trim();
      let parsed: { found?: boolean; secret?: string; secrets?: string[] } = {};
      try {
        parsed = JSON.parse(cleanedResponse);
      } catch {}

      const foundSecrets: string[] = [];
      if (parsed.found) {
        if (Array.isArray(parsed.secrets)) {
          for (const s of parsed.secrets) {
            if (s && typeof s === 'string' && text.includes(s) && !s.includes("[REDACTED_")) {
              foundSecrets.push(s);
            }
          }
        }
        if (parsed.secret && typeof parsed.secret === 'string' && text.includes(parsed.secret) && !parsed.secret.includes("[REDACTED_")) {
          foundSecrets.push(parsed.secret);
        }
      }

      const uniqueFound = Array.from(new Set(foundSecrets));
      if (uniqueFound.length > 0) {
        cacheSemanticSecrets(text, uniqueFound);
        return uniqueFound;
      }
    } catch {}
  }

  const fallbackSecrets = fallbackSemanticHeuristicsList(text);
  if (fallbackSecrets.length > 0) {
    cacheSemanticSecrets(text, fallbackSecrets);
  }
  return fallbackSecrets;
}

/**
 * Deterministic Local Fallback Scanner
 * Lightweight rule-based semantic extractor for local test suites and unsupported environments.
 */
export function fallbackSemanticHeuristicsList(text: string): string[] {
  // Safe Contexts: General technical questions asking 'how to' or 'what is' without value assignments
  const isSafeContextQuestion = /\b(?:how\s+(?:to|can\s+i|do\s+i|should\s+i)|difference\s+between|what\s+is|explain|tutorial|documentation|syntax)\b/i.test(text) &&
    !/\b(?:is|=|:)\s+['"]?[a-zA-Z0-9_!@#$%^&*\-]{3,}/i.test(text);
  if (isSafeContextQuestion) {
    return [];
  }

  const semanticPatterns = [
    // Multi-Word Passphrase (e.g. 'my passphrase is correct horse battery staple')
    /(?:\b(?:my|our|the)\s+(?:passphrase|secret\s+passphrase)\s+is\s+['"]?)([a-zA-Z0-9_\s\-]{8,80}?)(?=['"]?(?:[\s,;.]|$|\b(?:for|to|whenever|when|with)\b))/gi,
    // Security answer (e.g. 'security answer is fluffy_dog_123')
    /(?:\b(?:security\s+answer|security\s+response)\s+(?:is|=|:)?\s*['"]?)([a-zA-Z0-9_!@#$%^&*\-]{3,64})(?=['"]?(?:[\s,;.]|$))/gi,
    // Override code, bypass code, paywall code, QA code
    /(?:\b(?:override\s+code|bypass\s+code|paywall\s+code|access\s+code|testing\s+code|secret\s+code)\s+(?:is|=|:)?\s*['"]?)([a-zA-Z0-9_!@#$%^&*\-]{4,64})(?=['"]?(?:[\s,;.]|$))/gi,
    // Master password, backdoor login, database password, secret token, passcode, auth token
    /(?:\b(?:master\s+password|backdoor\s+login|staging\s+password|database\s+password|admin\s+password|root\s+password|root\s+passcode|passcode|secret\s+key|access\s+key|auth\s+token|secret\s+token)\s+(?:is|=|:)?\s*['"]?)([a-zA-Z0-9_!@#$%^&*\-]{4,64})(?=['"]?(?:[\s,;.]|$))/gi,
    // Action verbs followed by tokens (type in X, enter X, use X)
    /(?:\b(?:type\s+in|enter|use|input)\s+['"]?)([a-zA-Z0-9_!@#$%^&*\-]{4,64})(?=['"]?\s+(?:whenever|when|for|as|if|to|in|into|on|at|with)\b[\s\S]{0,40}?\b(?:passphrase|password|secret|key|token|credential|login|ssh|bastion|auth|code|paywall|override)\b)/gi,
    // Declarations: the secret is X, the password is X
    /(?:\b(?:the|my|our)\s+(?:secret|password|access\s*key|passcode|root\s+passcode|override\s*code|master\s+password)\s+is\s+['"]?)([a-zA-Z0-9_!@#$%^&*\-]{4,64})(?=['"]?(?:[\s,;.]|$))/gi,
    // Generic fallback for backdoor/admin passwords
    /\b(?:backdoor|admin|root|login|passcode|secret|password|access\s*key)[\s\S]{0,45}?\b(?:is|=|:)\s+['"]?([a-zA-Z0-9_!@#$%^&*\-]{4,32})['"]?/gi
  ];

  const secrets: string[] = [];
  for (const pat of semanticPatterns) {
    pat.lastIndex = 0;
    let match: RegExpExecArray | null;
    while ((match = pat.exec(text)) !== null) {
      if (match[1] && text.includes(match[1])) {
        const rawSecret = match[1].trim();
        if (rawSecret.length >= 3 && !rawSecret.startsWith("[REDACTED_") && !rawSecret.includes("[REDACTED_")) {
          secrets.push(rawSecret);
        }
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
  if (!shouldTriggerSemanticCheck(sanitizedText)) {
    return { sanitizedText, threatCount };
  }

  // 3. On-Device AI / Fallback Extraction
  try {
    const detectedSecrets = await scanForSemanticSecrets(sanitizedText);

    for (const secret of detectedSecrets) {
      if (secret && secret.trim().length > 0 && !secret.includes("[REDACTED_") && sanitizedText.includes(secret)) {
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
