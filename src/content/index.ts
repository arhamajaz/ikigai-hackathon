/**
 * SentinelEdge v2.2.0 Content Script
 * Hierarchical Cascading Interception Pipeline Architecture:
 * Fast-Path Regex -> Semantic Trigger Guard -> Timed Local AI Fallback -> Policy Engine -> Release
 * Multi-Platform Adapters: ChatGPT, Claude, Gemini, Perplexity, Microsoft Copilot
 */

import { sanitizePayload, SanitizationResult } from '../core/dlp-engine';
import {
  executeAiRegexHandshake,
  scanSemanticSecrets,
  cacheSemanticSecret,
  checkGeminiNanoAvailability,
  getOrCreateAiSession
} from '../core/semantic-ai';
import { PolicyEngine } from '../core/policy-engine';

console.log(
  "%c[SentinelEdge v2.2.0]%c Hierarchical Cascading DLP Pipeline Active (Fast-Path -> AI Guard -> Policy Engine).",
  "color: #10B981; font-weight: bold; font-size: 13px;",
  "color: inherit;"
);

/**
 * Re-entry lock for Pre-Flight submission gate bypass re-dispatching.
 */
let isBypassingGate = false;

/**
 * Debounce timer handle for background pre-scanning while typing.
 */
let debounceTimer: ReturnType<typeof setTimeout> | null = null;

/**
 * Universal selector list for main prompt send buttons AND edited message submit/save/update buttons across:
 * ChatGPT, Claude, Gemini, Perplexity, and Microsoft Copilot.
 */
const SUBMIT_BUTTON_SELECTORS = [
  'button[data-testid="send-button"]',
  'button[data-testid="submit-button"]',
  'button[data-testid*="send"]',
  'button[data-testid*="submit"]',
  'button[aria-label*="Send"]',
  'button[aria-label*="send"]',
  'button[aria-label*="Submit"]',
  'button[aria-label*="submit"]',
  'button[aria-label*="Update"]',
  'button[aria-label*="update"]',
  'button[aria-label*="Save"]',
  'button[aria-label*="save"]',
  'button[aria-label*="Search"]',
  'button[title*="Submit"]',
  'button[title*="Send"]',
  'button.bg-super',
  'button.send-button',
  'button.submit',
  '[role="button"][aria-label*="send"]',
  '[role="button"][aria-label*="submit"]',
  'form button[type="submit"]'
].join(', ');

/**
 * Short-Circuit Logic: Determines if the input requires Gemini Nano AI semantic scanning.
 * Bypasses AI scanning for code blocks, massive JSON/YAML payloads (>2,000 chars), or structural data to save compute cycles.
 */
export function needsSemanticCheck(text: string): boolean {
  if (!text || text.trim().length < 10) return false;

  // Short-circuit 1: Massive code/config payloads (>2000 chars) are handled by Fast-Path Regex
  if (text.length > 2000) return false;

  // Short-circuit 2: Code blocks, JSON, XML, or YAML structural blobs
  const isCodeOrJson = /^\s*[\{\[\<\#]|\`\`\`|function\s+|class\s+|import\s+|export\s+/i.test(text);
  if (isCodeOrJson) return false;

  return true;
}

/**
 * MASTER ORCHESTRATION FUNCTION: processSubmissionGate(rawText)
 * Executes the 3-Step Hierarchical Cascading Pipeline:
 *  1. Fast-Path Rule Engine (Synchronous Sub-2ms)
 *  2. AI Availability & 200ms Timeout Fallback (Promise.race)
 *  3. Policy Engine Audit & Release
 */
export async function processSubmissionGate(rawText: string): Promise<{ sanitizedText: string; totalThreats: number }> {
  // Step 1: Rule Detection (Fast Path Regex Engine - Sub-2ms)
  let { sanitizedText, threatCount } = sanitizePayload(rawText);

  // Step 2: AI Availability & Timeout Fallback Guard
  const isAiAvailable = await checkGeminiNanoAvailability();
  if (isAiAvailable && needsSemanticCheck(sanitizedText)) {
    try {
      const aiTask = executeAiRegexHandshake(sanitizedText, 200);
      const timeoutTask = new Promise<never>((_, reject) =>
        setTimeout(() => reject(new Error('AI_TIMEOUT')), 200)
      );

      // Race the AI scan against the 200ms hard latency clock
      const handshakeRes = await Promise.race([aiTask, timeoutTask]);
      sanitizedText = handshakeRes.sanitizedText;
      threatCount += (handshakeRes.threatCount - threatCount > 0 ? handshakeRes.threatCount - threatCount : 0);
    } catch (error: any) {
      if (error && error.message === 'AI_TIMEOUT') {
        console.warn('[SentinelEdge] Local AI timed out. Falling back to Rules Only.');
      } else {
        console.warn('[SentinelEdge] Local AI unavailable. Rules Only.');
      }
      // Preserve Fast-Path output from Step 1
    }
  }

  // Step 3: Policy Engine Audit
  const policyResult = PolicyEngine.evaluate(sanitizedText);
  return {
    sanitizedText: policyResult.finalText,
    totalThreats: threatCount
  };
}

/**
 * Displays a transient Neo-Brutalist toast banner on the webpage when secrets/PII are redacted.
 */
function showInterceptionToast(threatCount: number): void {
  try {
    if (typeof document === 'undefined') return;
    const existing = document.getElementById('sentinel-toast-banner');
    if (existing) existing.remove();

    const toast = document.createElement('div');
    toast.id = 'sentinel-toast-banner';
    toast.style.cssText = `
      position: fixed;
      top: 20px;
      right: 20px;
      z-index: 999999;
      background: #FFE4E6;
      color: #9F1239;
      border: 3px solid #000;
      box-shadow: 4px 4px 0px #000;
      padding: 12px 18px;
      font-family: system-ui, -apple-system, sans-serif;
      font-size: 13px;
      font-weight: 800;
      border-radius: 6px;
      display: flex;
      align-items: center;
      gap: 10px;
      pointer-events: none;
      animation: sentinelFadeIn 0.2s ease-out;
    `;

    toast.innerHTML = `
      <span style="font-size: 18px;">🛡️</span>
      <span>SentinelEdge DLP v2.2: Redacted <strong>${threatCount}</strong> sensitive threat${threatCount > 1 ? 's' : ''}!</span>
    `;

    document.body.appendChild(toast);

    setTimeout(() => {
      if (toast && toast.parentNode) {
        toast.parentNode.removeChild(toast);
      }
    }, 3200);
  } catch {
    // Ignore DOM toast injection errors in restricted frames
  }
}

/**
 * Checks if an element is an editable text input or container across all 5 AI platforms.
 */
function isEditable(el: Element | null): boolean {
  if (!el) return false;
  const tag = el.tagName.toUpperCase();
  if (tag === 'TEXTAREA' || tag === 'INPUT') return true;

  const htmlEl = el as HTMLElement;
  if (htmlEl.isContentEditable || htmlEl.getAttribute('contenteditable') === 'true') return true;
  if (el.closest && el.closest('#prompt-textarea, #searchbox, textarea, input, [contenteditable="true"], [role="textbox"]')) return true;

  return false;
}

/**
 * Finds the primary prompt input element on ChatGPT, Claude, Gemini, Perplexity, or Microsoft Copilot.
 */
function getPromptElement(): HTMLElement | null {
  if (typeof document === 'undefined') return null;
  const activeEl = document.activeElement as HTMLElement | null;
  if (activeEl && isEditable(activeEl)) {
    return activeEl;
  }
  return document.querySelector<HTMLElement>(
    '#prompt-textarea, #searchbox, textarea[placeholder*="Ask"], textarea[placeholder*="Perplexity"], textarea, div[contenteditable="true"], [role="textbox"]'
  );
}

/**
 * Finds the target send or edit-submit button on ChatGPT, Claude, Gemini, Perplexity, or Microsoft Copilot.
 */
function getSendButton(): HTMLElement | null {
  if (typeof document === 'undefined') return null;
  return document.querySelector<HTMLElement>(SUBMIT_BUTTON_SELECTORS);
}

/**
 * Extracts raw un-sanitized text from an input container.
 */
function getRawText(el: HTMLElement): string {
  if (el instanceof HTMLTextAreaElement || el instanceof HTMLInputElement) {
    return el.value;
  }
  return el.innerText || el.textContent || '';
}

/**
 * Universal browser storage accessor (Chrome, Firefox, Safari, Edge, Brave, Opera, Comet).
 */
function recordTelemetry(threatCount: number, originalLength: number, sanitizedLength: number): void {
  try {
    const storageApi = (typeof chrome !== 'undefined' && chrome.storage)
      ? chrome.storage.local
      : (typeof (window as any).browser !== 'undefined' && (window as any).browser?.storage)
        ? (window as any).browser.storage.local
        : null;

    if (storageApi) {
      storageApi.get(['totalThreatsBlocked', 'incidentsLog'], (data: any) => {
        const currentTotal = (data.totalThreatsBlocked || 0) + threatCount;
        const currentLog = data.incidentsLog || [];
        
        const newIncident = {
          timestamp: new Date().toISOString(),
          threatsBlocked: threatCount,
          originalLength,
          sanitizedLength,
          originUrl: (typeof window !== 'undefined' && window.location) ? window.location.hostname : 'local'
        };

        const updatedLog = [newIncident, ...currentLog].slice(0, 100);

        storageApi.set({
          totalThreatsBlocked: currentTotal,
          incidentsLog: updatedLog
        });
      });
    }
  } catch {
    // Ignore storage errors in restricted sandbox
  }
}

/**
 * Replaces DOM text and dispatches host framework events for ChatGPT (React), Claude/Gemini (ProseMirror/Lexical),
 * Perplexity (Slate), and Microsoft Copilot (Fluent).
 */
function syncAndReplaceDOM(inputElem: HTMLElement, sanitizedText: string): void {
  if (typeof window === 'undefined' || typeof document === 'undefined') return;

  if (inputElem instanceof HTMLTextAreaElement || inputElem instanceof HTMLInputElement) {
    const valueSetter =
      Object.getOwnPropertyDescriptor(window.HTMLTextAreaElement.prototype, 'value')?.set ||
      Object.getOwnPropertyDescriptor(window.HTMLInputElement.prototype, 'value')?.set;

    if (valueSetter) {
      valueSetter.call(inputElem, sanitizedText);
    } else {
      inputElem.value = sanitizedText;
    }

    inputElem.dispatchEvent(new InputEvent('input', { bubbles: true }));
    inputElem.dispatchEvent(new Event('change', { bubbles: true }));
  } else {
    const container = (inputElem.closest('[contenteditable="true"]') as HTMLElement) || inputElem;
    container.focus();

    const selection = window.getSelection();
    if (selection) {
      const range = document.createRange();
      range.selectNodeContents(container);
      selection.removeAllRanges();
      selection.addRange(range);
    }

    document.execCommand('insertText', false, sanitizedText);
    container.dispatchEvent(new InputEvent('input', { bubbles: true, inputType: 'insertText', data: sanitizedText }));
    container.dispatchEvent(new Event('change', { bubbles: true }));
  }
}

/**
 * INSTANT PASTE INTERCEPTION ('paste' event)
 */
function handlePasteEvent(event: ClipboardEvent): void {
  const target = (event.target as HTMLElement) || getPromptElement();
  if (!target || !isEditable(target)) return;

  const clipboardData = event.clipboardData || (window as unknown as { clipboardData?: DataTransfer }).clipboardData;
  if (!clipboardData) return;

  const rawClipboard = clipboardData.getData('text');
  if (!rawClipboard) return;

  const { sanitizedText, threatCount } = sanitizePayload(rawClipboard);

  if (threatCount > 0) {
    event.preventDefault();
    event.stopPropagation();
    event.stopImmediatePropagation();

    document.execCommand('insertText', false, sanitizedText);

    target.dispatchEvent(new InputEvent('input', {
      bubbles: true,
      cancelable: true,
      inputType: 'insertText',
      data: sanitizedText
    }));

    recordTelemetry(threatCount, rawClipboard.length, sanitizedText.length);
    showInterceptionToast(threatCount);
    console.warn(`[SentinelEdge v2.2.0] Instant Paste Intercepted: Redacted ${threatCount} threat${threatCount > 1 ? 's' : ''}.`);
  }
}

/**
 * DEBOUNCED BACKGROUND PRE-SCANNING AS USER TYPES (300ms)
 */
function handleInputDebounced(event: Event): void {
  const target = event.target as HTMLElement | null;
  if (!target || !isEditable(target)) return;

  if (debounceTimer) {
    clearTimeout(debounceTimer);
  }

  const rawText = getRawText(target);
  if (!rawText || !needsSemanticCheck(rawText)) return;

  debounceTimer = setTimeout(() => {
    scanSemanticSecrets(rawText).then((result) => {
      if (result.isSecret && result.semanticThreats.length > 0) {
        for (const threat of result.semanticThreats) {
          cacheSemanticSecret(rawText, threat);
        }
      }
    }).catch(() => {
      // Ignore background pre-scan errors
    });
  }, 300);
}

/**
 * SANITIZATION, FRAMEWORK SYNC & RELEASE PIPELINE
 */
async function executeSanitizationAndRelease(
  trigger: 'enter' | 'button',
  targetElem: HTMLElement,
  targetButton?: HTMLElement
): Promise<void> {
  const rawText = getRawText(targetElem);
  if (!rawText || rawText.trim().length === 0) return;

  // Process prompt through 3-step Hierarchical Cascading Pipeline
  const { sanitizedText, totalThreats } = await processSubmissionGate(rawText);

  if (totalThreats > 0 && sanitizedText !== rawText) {
    syncAndReplaceDOM(targetElem, sanitizedText);
    recordTelemetry(totalThreats, rawText.length, sanitizedText.length);
    showInterceptionToast(totalThreats);
    console.warn(`[SentinelEdge v2.2.0] Pipeline redacted ${totalThreats} threat${totalThreats > 1 ? 's' : ''} prior to submission.`);
  }

  isBypassingGate = true;

  setTimeout(() => {
    if (trigger === 'enter') {
      targetElem.dispatchEvent(new KeyboardEvent('keydown', {
        key: 'Enter',
        code: 'Enter',
        keyCode: 13,
        which: 13,
        bubbles: true,
        cancelable: true
      }));
    } else if (trigger === 'button') {
      const btnToClick = targetButton || getSendButton();
      if (btnToClick && typeof btnToClick.click === 'function') {
        btnToClick.click();
      }
    }

    setTimeout(() => {
      isBypassingGate = false;
    }, 100);
  }, 20);
}

/**
 * PRE-FLIGHT SUBMISSION GATE - Keyboard 'Enter' Handler
 */
function handlePreFlightKeydown(event: KeyboardEvent): void {
  if (isBypassingGate) return;

  if (event.key !== 'Enter' || event.shiftKey || event.isComposing) {
    return;
  }

  const activeEl = document.activeElement as HTMLElement | null;
  const promptEl = getPromptElement();
  const targetElem = (activeEl && isEditable(activeEl)) ? activeEl : promptEl;

  if (!targetElem) return;

  event.preventDefault();
  event.stopImmediatePropagation();

  executeSanitizationAndRelease('enter', targetElem);
}

/**
 * PRE-FLIGHT SUBMISSION GATE - Send / Edit-Submit Button Click Handler
 */
function handlePreFlightClick(event: MouseEvent): void {
  if (isBypassingGate) return;

  const targetNode = event.target as HTMLElement | null;
  if (!targetNode) return;

  const submitBtn = targetNode.closest<HTMLElement>(SUBMIT_BUTTON_SELECTORS);

  if (submitBtn) {
    const parentContainer = submitBtn.closest('form, div[class*="edit"], div[role="region"], div');
    const scopedInput = parentContainer?.querySelector<HTMLElement>(
      '#prompt-textarea, #searchbox, textarea, div[contenteditable="true"], [role="textbox"]'
    );

    const promptEl = scopedInput || getPromptElement();
    if (!promptEl) return;

    event.preventDefault();
    event.stopImmediatePropagation();

    executeSanitizationAndRelease('button', promptEl, submitBtn);
  }
}

// Attach event listeners safely in browser DOM environments
if (typeof document !== 'undefined') {
  // Pre-warm Gemini Nano session eagerly on page load for 0 cold-start latency
  checkGeminiNanoAvailability().then((available) => {
    if (available) {
      getOrCreateAiSession().catch(() => {});
    }
  });

  document.addEventListener('paste', handlePasteEvent, true);
  document.addEventListener('input', handleInputDebounced, true);
  document.addEventListener('keydown', handlePreFlightKeydown, true);
  document.addEventListener('click', handlePreFlightClick, true);

  const observer = new MutationObserver(() => {
    const prompt = getPromptElement();
    if (prompt && !prompt.dataset.sentinelActive) {
      prompt.dataset.sentinelActive = "true";
    }
  });

  if (document.body) {
    observer.observe(document.body, {
      childList: true,
      subtree: true
    });
  }
}
