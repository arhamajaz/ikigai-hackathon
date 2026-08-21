export interface DlpRule {
  id: string;
  pattern: RegExp;
  mask: string;
  needsContext?: boolean;
}

export interface SanitizationResult {
  sanitizedText: string;
  threatCount: number;
}

export const DLP_RULES: readonly DlpRule[] = [
  // --- CLOUD SECRETS & ENVIRONMENT VARIABLES ---
  {
    id: "AWS_ACCESS_KEY",
    pattern: /\b((?:AKIA|ASIA|ABIA|ACCA)[A-Z0-9]{16})\b/g,
    mask: "[REDACTED_AWS_KEY]",
    needsContext: false
  },
  {
    id: "OPENAI_API_KEY",
    pattern: /\b(sk-(?:proj-)?[a-zA-Z0-9_-]{20,})\b/g,
    mask: "[REDACTED_OPENAI_KEY]",
    needsContext: false
  },
  {
    id: "GITHUB_PAT",
    pattern: /\b(ghp_[a-zA-Z0-9]{36})\b/g,
    mask: "[REDACTED_GITHUB_TOKEN]",
    needsContext: false
  },
  {
    id: "STRIPE_KEY",
    pattern: /\b((?:sk|rk)_(?:test|live)_[a-zA-Z0-9]{24,})\b/g,
    mask: "[REDACTED_STRIPE_KEY]",
    needsContext: false
  },
  {
    id: "PRIVATE_KEY",
    pattern: /-----BEGIN [A-Z ]+ PRIVATE KEY-----[A-Za-z0-9+/\n\r]+={0,2}-----END [A-Z ]+ PRIVATE KEY-----/g,
    mask: "[REDACTED_PRIVATE_KEY]",
    needsContext: false
  },
  {
    id: "DATABASE_URI",
    pattern: /(?:postgres|mysql|mongodb\+srv):\/\/[^:\s]+:[^@\s]+@[^\/\s]+(?:\/[^\s]*)?/g,
    mask: "[REDACTED_DB_CONNECTION_STRING]",
    needsContext: false
  },
  {
    id: "JWT_TOKEN",
    pattern: /\beyJ[a-zA-Z0-9_-]*\.[a-zA-Z0-9_-]*\.[a-zA-Z0-9_-]*\b/g,
    mask: "[REDACTED_JWT]",
    needsContext: false
  },

  // --- REGIONAL IDENTIFIERS (EVALUATED BEFORE GENERIC NUMERIC PATTERNS) ---
  {
    id: "DRIVING_LICENSE",
    pattern: /\b(([A-Z]{2}[0-9]{2})( )|([A-Z]{2}-[0-9]{2}))((19|20)[0-9][0-9])[0-9]{7}\b/g,
    mask: "[REDACTED_DRIVING_LICENSE]",
    needsContext: false
  },
  {
    id: "PAN_CARD",
    pattern: /\b[A-Z]{5}[0-9]{4}[A-Z]{1}\b/g,
    mask: "[REDACTED_PAN]",
    needsContext: false
  },
  {
    id: "AADHAAR_CARD",
    pattern: /\b[2-9]\d{3}[ -]?\d{4}[ -]?\d{4}\b/g,
    mask: "[REDACTED_AADHAAR]",
    needsContext: false
  },
  {
    id: "MOBILE_NUMBER",
    pattern: /\b(?:\+91[\-\s]?)?[6-9]\d{9}\b/g,
    mask: "[REDACTED_MOBILE]",
    needsContext: false
  },

  // --- SPECIFIC PIN & FINANCIAL RULES ---
  {
    id: "UPI_PIN",
    pattern: /\b\d{4,6}\b/g,
    mask: "[REDACTED_UPI_PIN]",
    needsContext: true
  },
  {
    id: "MPIN",
    pattern: /\b\d{6}\b/g,
    mask: "[REDACTED_MPIN]",
    needsContext: true
  },
  {
    id: "ATM_PIN",
    pattern: /\b\d{4}\b/g,
    mask: "[REDACTED_ATM_PIN]",
    needsContext: true
  },
  {
    id: "POSTAL_PIN_CODE",
    pattern: /\b[1-9][0-9]{5}\b/g,
    mask: "[REDACTED_PIN_CODE]",
    needsContext: true
  },
  {
    id: "DATE_OF_BIRTH",
    pattern: /\b(0[1-9]|[12][0-9]|3[01])[-/.](0[1-9]|1[012])[-/.](19|20)\d\d\b/g,
    mask: "[REDACTED_DOB]",
    needsContext: true
  },
  {
    id: "PASSWORD",
    pattern: /(?:password|passwd|pwd|pass)[\s]*[:=][\s]*([^\s]{6,32})\b/gi,
    mask: "[REDACTED_PASSWORD]",
    needsContext: false
  },

  // --- GENERIC SENSITIVE PII ---
  {
    id: "CREDIT_CARD",
    pattern: /\b(?:\d[ -]*?){13,16}\b/g,
    mask: "[REDACTED_CREDIT_CARD]",
    needsContext: false
  },
  {
    id: "SSN_OR_NATIONAL_ID",
    pattern: /\b\d{3}-\d{2}-\d{4}\b/g,
    mask: "[REDACTED_NATIONAL_ID]",
    needsContext: false
  },
  {
    id: "EMAIL_ADDRESS",
    pattern: /[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}/g,
    mask: "[REDACTED_EMAIL]",
    needsContext: false
  }
];

/**
 * Contextual validation filter to prevent false positives on short numeric strings or dates.
 * Inspects a 30-character window preceding the match for sensitive context keywords.
 */
export function hasSensitiveContext(fullText: string, matchIndex: number, ruleId: string): boolean {
  // Extract a 30-character window before the match to look for clues
  const contextWindow = fullText.substring(Math.max(0, matchIndex - 30), matchIndex).toLowerCase();
  
  if (ruleId === "UPI_PIN") {
    return /(upi)/.test(contextWindow);
  }

  if (ruleId === "MPIN") {
    return /(mpin)/.test(contextWindow);
  }

  if (ruleId === "ATM_PIN") {
    return /(atm|bank|pin|passcode|secret)/.test(contextWindow);
  }
  
  if (ruleId === "POSTAL_PIN_CODE") {
    return /(address|zip|pincode|pin code|code|city|state)/.test(contextWindow);
  }

  if (ruleId === "DATE_OF_BIRTH") {
    return /(dob|birth|born|age|date)/.test(contextWindow);
  }

  return true; // If no context required, always return true
}

/**
 * Sanitizes the given input string using high-performance regex matching and contextual validation.
 * Replaces recognized cloud secrets, regional ID numbers, and sensitive PII with safe mask placeholders.
 * 
 * @param rawText Input payload text to inspect and redact.
 * @returns SanitizationResult containing redacted text and count of blocked threats.
 */
export function sanitizePayload(rawText: string): SanitizationResult {
  if (!rawText) {
    return { sanitizedText: "", threatCount: 0 };
  }

  let sanitizedText = rawText;
  let threatCount = 0;

  // Track modifications safely using string replacements
  DLP_RULES.forEach(rule => {
    let match: RegExpExecArray | null;
    // Reset regex index for global searches
    rule.pattern.lastIndex = 0; 
    
    // We execute against current sanitizedText to prevent double matching already redacted items
    while ((match = rule.pattern.exec(sanitizedText)) !== null) {
      if (rule.needsContext && !hasSensitiveContext(sanitizedText, match.index, rule.id)) {
        continue; // Skip this match; it is a false positive
      }
      
      // If it passes context (or doesn't need it), mask it
      const matchedString = match[0];
      sanitizedText = sanitizedText.replace(matchedString, rule.mask);
      threatCount++;

      // Reset lastIndex because sanitizedText changed length
      rule.pattern.lastIndex = 0;
    }
  });

  return { sanitizedText, threatCount };
}
