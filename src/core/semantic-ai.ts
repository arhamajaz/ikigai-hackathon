/**
 * SentinelEdge v2.1 - Local Gemini Nano Semantic AI DLP Engine
 * Integrates Chrome's Built-in Prompt API (window.ai.languageModel)
 * 100% Air-Gapped On-Device Processing (0 Cloud Calls)
 * Asynchronous AI / Regex Handshake for Unstructured Secrets
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
let isAiAvailable = false;

/**
 * STEP 1: Environment Verification & Model Availability Check
 * Verifies if Chrome's Prompt API (Gemini Nano) is enabled and model weights are ready.
 */
export async function checkGeminiNanoAvailability(): Promise<boolean> {
  try {
    const ai = typeof window !== 'undefined' ? window.ai : (typeof self !== 'undefined' ? (self as any).ai : undefined);
    if (!ai || !ai.languageModel) {
      return false;
    }

    if (typeof ai.languageModel.capabilities === 'function') {
      const caps = await ai.languageModel.capabilities();
      isAiAvailable = caps.available === 'readily' || caps.available === 'after-download';
      return isAiAvailable;
    }

    isAiAvailable = true;
    return true;
  } catch {
    isAiAvailable = false;
    return false;
  }
}

/**
 * STEP 2: Stateful Session Creation (.create)
 * Bootstraps a single persistent Gemini Nano session with a constrained system prompt.
 */
export async function getOrCreateAiSession(): Promise<LanguageModelSession | null> {
  if (activeAiSession) return activeAiSession;
  if (isInitializing) return null;

  isInitializing = true;
  try {
    const ai = typeof window !== 'undefined' ? window.ai : (typeof self !== 'undefined' ? (self as any).ai : undefined);
    if (!ai || !ai.languageModel || typeof ai.languageModel.create !== 'function') {
      isInitializing = false;
      return null;
    }

    activeAiSession = await ai.languageModel.create({
      systemPrompt: "You are a local data privacy analyzer. Does this text contain a hidden password or secret? Answer yes or no."
    });

    isInitializing = false;
    return activeAiSession;
  } catch (err) {
    isInitializing = false;
    console.warn("[SentinelEdge AI] Gemini Nano session initialization deferred:", err);
    return null;
  }
}

/**
 * STEP 3: Local Semantic Scanning (.prompt)
 * Evaluates text using on-device Gemini Nano with 0 cloud network calls.
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

    if (rawResponse.toLowerCase().includes('yes') || rawResponse.toLowerCase().includes('true')) {
      const heuristics = fallbackSemanticHeuristics(text);
      return {
        isSecret: true,
        semanticThreats: heuristics.semanticThreats.length > 0 ? heuristics.semanticThreats : [text],
        explanation: "Gemini Nano on-device model confirmed hidden secret."
      };
    }

    return { isSecret: false, semanticThreats: [], explanation: "Clean" };
  } catch (err) {
    return fallbackSemanticHeuristics(text);
  }
}

/**
 * Fallback semantic heuristic engine for environments where Gemini Nano model is downloading or unavailable.
 */
function fallbackSemanticHeuristics(text: string): SemanticScanResult {
  const semanticPatterns = [
    /\b(?:backdoor|admin|root|login|passcode|secret|password|access\s*key)[\s\S]{0,45}?\b(?:is|=|:)\s+['"]?([a-zA-Z0-9_!@#$%^&*]{4,32})['"]?/gi,
    /\b(?:the|my|our)\s+(?:secret|password|access\s*key)\s+is\s+['"]?([a-zA-Z0-9_!@#$%^&*]{4,32})['"]?/gi
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
 * Combining Lightning-Fast Regex Engine (<0.5ms) with Asynchronous Gemini Nano Semantic AI.
 */
export async function executeAiRegexHandshake(text: string): Promise<HandshakeResult> {
  // Step 1: Run instantaneous Regex DLP engine (<0.5ms budget)
  const regexResult: SanitizationResult = sanitizePayload(text);

  // Step 2: Concurrent Local Gemini Nano Semantic AI Scan
  const aiResult: SemanticScanResult = await scanSemanticSecrets(text);

  let finalSanitizedText = regexResult.sanitizedText;
  let totalThreatCount = regexResult.threatCount;
  let handshakeTriggered = false;

  if (aiResult.isSecret && aiResult.semanticThreats.length > 0) {
    for (const secretVal of aiResult.semanticThreats) {
      if (finalSanitizedText.includes(secretVal)) {
        finalSanitizedText = finalSanitizedText.replaceAll(secretVal, "[REDACTED_SEMANTIC_SECRET]");
        totalThreatCount++;
        handshakeTriggered = true;
      }
    }
  }

  return {
    sanitizedText: finalSanitizedText,
    threatCount: totalThreatCount,
    aiHandshakeTriggered: handshakeTriggered,
    aiExplanation: aiResult.explanation
  };
}
