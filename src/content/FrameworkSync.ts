/**
 * FrameworkSync.ts
 * SentinelEdge Host Framework State Synchronization Engine
 * 
 * Handles internal state synchronization for React, Lexical, and ProseMirror virtual DOMs
 * across ChatGPT, Claude, and Gemini prompt interfaces.
 */

/**
 * Updates an element's text content and dispatches prototype-level events to notify
 * host application state management (React state, ProseMirror transaction, Lexical model).
 *
 * @param element The target editable DOM element (Textarea, Input, or ContentEditable div).
 * @param sanitizedText Redacted text payload to sync into the input element.
 */
export function syncHostFramework(element: HTMLElement, sanitizedText: string): void {
  if (!element) return;

  if (element instanceof HTMLTextAreaElement || element instanceof HTMLInputElement) {
    const proto = element instanceof HTMLTextAreaElement 
      ? window.HTMLTextAreaElement.prototype 
      : window.HTMLInputElement.prototype;

    const valueSetter = Object.getOwnPropertyDescriptor(proto, "value")?.set;

    if (valueSetter) {
      valueSetter.call(element, sanitizedText);
    } else {
      element.value = sanitizedText;
    }

    // Fire standard input & change events for React/Vue event listeners
    element.dispatchEvent(new Event('input', { bubbles: true, cancelable: true }));
    element.dispatchEvent(new Event('change', { bubbles: true, cancelable: true }));
  } else {
    // ContentEditable container (ProseMirror / Lexical on ChatGPT & Claude)
    const container = (element.closest('[contenteditable="true"]') as HTMLElement) || element;

    try {
      // Dispatch beforeinput so ProseMirror/Lexical record transaction history
      container.dispatchEvent(new InputEvent('beforeinput', {
        bubbles: true,
        cancelable: true,
        inputType: 'insertText',
        data: sanitizedText
      }));
    } catch {
      // InputEvent polyfill fallback for restrictive targets
    }

    // Update text content if not already matching
    if (container.innerText !== sanitizedText) {
      container.innerText = sanitizedText;
    }

    container.dispatchEvent(new InputEvent('input', {
      bubbles: true,
      cancelable: true,
      inputType: 'insertText',
      data: sanitizedText
    }));
    container.dispatchEvent(new Event('change', { bubbles: true, cancelable: true }));
  }
}

/**
 * Gets caret character offset in a ContentEditable container.
 */
export function getCaretOffset(container: HTMLElement): number {
  const selection = window.getSelection();
  if (!selection || selection.rangeCount === 0) return 0;

  const range = selection.getRangeAt(0);
  const preCaretRange = range.cloneRange();
  preCaretRange.selectNodeContents(container);
  preCaretRange.setEnd(range.endContainer, range.endOffset);
  return preCaretRange.toString().length;
}

/**
 * Sets caret character offset in a ContentEditable container.
 */
export function setCaretOffset(container: HTMLElement, offset: number): void {
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
