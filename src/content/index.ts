import { sanitizePayload } from '../core/dlp-engine';

console.log("[SentinelEdge v1.2] Real-Time Paste & Keystroke Masking active.");

/**
 * Re-entry flag to prevent infinite loops during programmatic DOM updates.
 */
let isMasking = false;

/**
 * Timer handle for 250ms typing debounce.
 */
let debounceTimer: ReturnType<typeof setTimeout> | null = null;

/**
 * Checks if an element is an editable text input or container.
 */
function isEditable(el: Element | null): boolean {
  if (!el) return false;
  const tag = el.tagName.toUpperCase();
  if (tag === 'TEXTAREA' || tag === 'INPUT') return true;

  const htmlEl = el as HTMLElement;
  if (htmlEl.isContentEditable || htmlEl.getAttribute('contenteditable') === 'true') return true;
  if (el.closest && el.closest('#prompt-textarea, textarea, input, [contenteditable="true"], [role="textbox"]')) return true;

  return false;
}

/**
 * Finds the primary prompt input element on the active webpage.
 */
function getPromptElement(): HTMLElement | null {
  const activeEl = document.activeElement as HTMLElement | null;
  if (activeEl && isEditable(activeEl)) {
    return activeEl;
  }
  return document.querySelector<HTMLElement>(
    '#prompt-textarea, textarea, div[contenteditable="true"], [role="textbox"]'
  );
}

/**
 * Extracts raw un-sanitized string text from an input container.
 */
function getRawText(el: HTMLElement): string {
  if (el instanceof HTMLTextAreaElement || el instanceof HTMLInputElement) {
    return el.value;
  }
  return el.innerText || el.textContent || '';
}

/**
 * Synchronizes the updated DOM text with host frameworks (React, Lexical, ProseMirror).
 */
function syncHostFramework(element: HTMLElement, sanitizedText: string): void {
  if (element instanceof HTMLTextAreaElement || element instanceof HTMLInputElement) {
    const valueSetter =
      Object.getOwnPropertyDescriptor(window.HTMLTextAreaElement.prototype, "value")?.set ||
      Object.getOwnPropertyDescriptor(window.HTMLInputElement.prototype, "value")?.set;

    if (valueSetter) {
      valueSetter.call(element, sanitizedText);
    }

    element.dispatchEvent(new Event('input', { bubbles: true }));
    element.dispatchEvent(new Event('change', { bubbles: true }));
  } else {
    const container = (element.closest('[contenteditable="true"]') as HTMLElement) || element;

    try {
      container.dispatchEvent(new InputEvent('beforeinput', {
        bubbles: true,
        cancelable: true,
        inputType: 'insertText',
        data: sanitizedText
      }));
    } catch {
      // Ignore restriction
    }

    container.dispatchEvent(new InputEvent('input', {
      bubbles: true,
      inputType: 'insertText',
      data: sanitizedText
    }));
    container.dispatchEvent(new Event('change', { bubbles: true }));
  }
}

/**
 * Gets the current character offset of the caret inside a contenteditable container.
 */
function getCaretOffset(container: HTMLElement): number {
  const selection = window.getSelection();
  if (!selection || selection.rangeCount === 0) return 0;

  const range = selection.getRangeAt(0);
  const preCaretRange = range.cloneRange();
  preCaretRange.selectNodeContents(container);
  preCaretRange.setEnd(range.endContainer, range.endOffset);
  return preCaretRange.toString().length;
}

/**
 * Restores the caret at a specific character offset inside a contenteditable container.
 */
function setCaretOffset(container: HTMLElement, offset: number): void {
  const selection = window.getSelection();
  if (!selection) return;

  const range = document.createRange();
  let currentOffset = 0;
  let found = false;

  function traverseNodes(node: Node): void {
    if (found) return;
    if (node.nodeType === Node.TEXT_NODE) {
      const textLength = node.textContent?.length || 0;
      if (currentOffset + textLength >= offset) {
        const targetOffset = Math.max(0, offset - currentOffset);
        range.setStart(node, Math.min(targetOffset, textLength));
        range.collapse(true);
        found = true;
      } else {
        currentOffset += textLength;
      }
    } else {
      for (let i = 0; i < node.childNodes.length; i++) {
        traverseNodes(node.childNodes[i]);
        if (found) break;
      }
    }
  }

  traverseNodes(container);

  if (!found) {
    range.selectNodeContents(container);
    range.collapse(false);
  }

  selection.removeAllRanges();
  selection.addRange(range);
}

/**
 * Caret Preservation Masking helper for Textarea elements.
 */
function maskTextareaWithCaretPreservation(el: HTMLTextAreaElement, sanitizedText: string, delta: number): void {
  const start = el.selectionStart;
  const end = el.selectionEnd;

  const valueSetter = Object.getOwnPropertyDescriptor(window.HTMLTextAreaElement.prototype, "value")?.set;
  if (valueSetter) {
    valueSetter.call(el, sanitizedText);
  } else {
    el.value = sanitizedText;
  }

  const newStart = Math.max(0, start + delta);
  const newEnd = Math.max(0, end + delta);
  el.setSelectionRange(newStart, newEnd);
}

/**
 * STEP 1: Real-Time Flawless Paste Interception
 */
function handlePasteEvent(event: ClipboardEvent): void {
  const target = (event.target as HTMLElement) || getPromptElement();
  if (!target || !isEditable(target)) return;

  const clipboardData = event.clipboardData || (window as unknown as { clipboardData?: DataTransfer }).clipboardData;
  if (!clipboardData) return;

  const pastedText = clipboardData.getData('text');
  if (!pastedText) return;

  const { sanitizedText, threatCount } = sanitizePayload(pastedText);

  if (threatCount > 0) {
    // 1. Immediately block un-sanitized raw paste
    event.preventDefault();
    event.stopPropagation();

    isMasking = true;

    // 2. Inject sanitized text at cursor
    document.execCommand("insertText", false, sanitizedText);

    // 3. Sync host framework state
    syncHostFramework(target, sanitizedText);

    console.warn(`[SentinelEdge v1.2] Intercepted paste and masked ${threatCount} threat${threatCount > 1 ? 's' : ''}.`);

    setTimeout(() => {
      isMasking = false;
    }, 50);
  }
}

/**
 * STEP 2: Real-Time Typing Interception with Caret Preservation (Debounced 250ms)
 */
function handleTypingInput(event: Event): void {
  if (isMasking) return;

  const target = (event.target as HTMLElement) || getPromptElement();
  if (!target || !isEditable(target)) return;

  if (debounceTimer) {
    clearTimeout(debounceTimer);
  }

  debounceTimer = setTimeout(() => {
    if (isMasking) return;

    const rawText = getRawText(target);
    if (!rawText || rawText.trim().length === 0) return;

    const { sanitizedText, threatCount } = sanitizePayload(rawText);

    if (threatCount > 0 && sanitizedText !== rawText) {
      isMasking = true;
      const delta = sanitizedText.length - rawText.length;

      if (target instanceof HTMLTextAreaElement) {
        maskTextareaWithCaretPreservation(target, sanitizedText, delta);
      } else if (target instanceof HTMLInputElement) {
        const start = target.selectionStart || 0;
        target.value = sanitizedText;
        const newStart = Math.max(0, start + delta);
        target.setSelectionRange(newStart, newStart);
      } else {
        const container = (target.closest('[contenteditable="true"]') as HTMLElement) || target;
        const currentCaret = getCaretOffset(container);

        container.focus();
        container.innerText = sanitizedText;

        const newCaret = Math.max(0, currentCaret + delta);
        setCaretOffset(container, newCaret);
      }

      // Sync Host Framework
      syncHostFramework(target, sanitizedText);

      console.warn(`[SentinelEdge v1.2] Real-time keystroke masked ${threatCount} threat${threatCount > 1 ? 's' : ''}.`);

      setTimeout(() => {
        isMasking = false;
      }, 50);
    }
  }, 250);
}

// 1. Attach global capturing paste listener for immediate real-time paste masking
document.addEventListener('paste', handlePasteEvent, true);

// 2. Attach global capturing input listener for debounced real-time keystroke masking
document.addEventListener('input', handleTypingInput, true);
