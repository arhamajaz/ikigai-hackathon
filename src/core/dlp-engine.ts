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
    pattern: /\b(?:AKIA|ASIA|ABIA|ACCA)[A-Z0-9]{16}\b/g,
    mask: "[REDACTED_AWS_KEY]",
    needsContext: false
  },
  {
    id: "OPENAI_API_KEY",
    pattern: /\bsk-(?:proj-)?[a-zA-Z0-9_-]{20,}\b/g,
    mask: "[REDACTED_OPENAI_KEY]",
    needsContext: false
  },
  {
    id: "GITHUB_PAT",
    pattern: /\bghp_[a-zA-Z0-9]{36}\b/g,
    mask: "[REDACTED_GITHUB_TOKEN]",
    needsContext: false
  },
  {
    id: "STRIPE_KEY",
    pattern: /\b(?:sk|rk)_(?:test|live)_[a-zA-Z0-9]{24,}\b/g,
    mask: "[REDACTED_STRIPE_KEY]",
    needsContext: false
  },
  {
    id: "PRIVATE_KEY",
    pattern: /-----BEGIN [A-Z\s]+ PRIVATE KEY[\s\S]+?-----END [A-Z\s]+ PRIVATE KEY-----/g,
    mask: "[REDACTED_PRIVATE_KEY]",
    needsContext: false
  },
  {
    id: "DATABASE_URI",
    pattern: /(?:postgres(?:ql)?|mysql|mongodb(?:\+srv)?|redis):\/\/[^\s:@]+:[^\s:@]+@[^\s\/]+(?:\/[^\s]*)?/gi,
    mask: "[REDACTED_DB_CONNECTION_STRING]",
    needsContext: false
  },
  {
    id: "JWT_TOKEN",
    pattern: /\beyJ[a-zA-Z0-9_-]*\.[a-zA-Z0-9_-]*\.[a-zA-Z0-9_-]*\b/g,
    mask: "[REDACTED_JWT]",
    needsContext: false
  },

  // --- REGIONAL & GLOBAL IDENTIFIERS ---
  {
    id: "DRIVING_LICENSE",
    pattern: /\b(?:[A-Z]{2}[0-9]{2}\s?|[A-Z]{2}-[0-9]{2})(?:19|20)[0-9]{9}\b/g,
    mask: "[REDACTED_DRIVING_LICENSE]",
    needsContext: false
  },
  {
    id: "PAN_CARD",
    pattern: /\b[A-Z]{5}[0-9]{4}[A-Z]\b/g,
    mask: "[REDACTED_PAN]",
    needsContext: false
  },
  {
    id: "AADHAAR_CARD",
    pattern: /\b[2-9]\d{3}[\s\-]?[0-9]{4}[\s\-]?[0-9]{4}\b/g,
    mask: "[REDACTED_AADHAAR]",
    needsContext: false
  },
  {
    id: "DATE_OF_BIRTH",
    pattern: /\b(?:0[1-9]|[12][0-9]|3[01])[-/.](?:0[1-9]|1[012])[-/.](?:19|20)\d\d\b/g,
    mask: "[REDACTED_DOB]",
    needsContext: true
  },
  {
    id: "GLOBAL_PHONE_NUMBER",
    pattern: /(?:(?:\+|00)[1-9]\d{0,3}[\s.\-]?)?(?:\(\d{1,5}\)[\s.\-]?)?\d{2,5}(?:[\s.\-]\d{2,5}){1,4}\b|\b[6-9]\d{9}\b/g,
    mask: "[REDACTED_PHONE_NUMBER]",
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
    id: "PASSWORD",
    pattern: /(?:password|passwd|pwd|pass)[\s]*[:=][\s]*[^\s]{6,32}\b/gi,
    mask: "[REDACTED_PASSWORD]",
    needsContext: false
  },

  // --- GENERIC SENSITIVE PII ---
  {
    id: "CREDIT_CARD",
    pattern: /\b(?:\d[ -]?){13,18}\d\b/g,
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
    pattern: /\b[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}\b/g,
    mask: "[REDACTED_EMAIL]",
    needsContext: false
  }
];

/**
 * Contextual validation filter to prevent false positives on short numeric strings or dates.
 * Inspects a 30-character window preceding the match for sensitive context keywords with word boundaries.
 */
export function hasSensitiveContext(fullText: string, matchIndex: number, ruleId: string): boolean {
  const contextWindow = fullText.substring(Math.max(0, matchIndex - 30), matchIndex).toLowerCase();
  
  if (ruleId === "UPI_PIN") {
    return /\b(upi|vpa)\b/.test(contextWindow);
  }

  if (ruleId === "MPIN") {
    return /\b(mpin|mobile\s*pin)\b/.test(contextWindow);
  }

  if (ruleId === "ATM_PIN") {
    return /\b(atm|bank|pin|passcode|secret|card)\b/.test(contextWindow);
  }
  
  if (ruleId === "POSTAL_PIN_CODE") {
    return /\b(address|zip|pincode|pin\s*code|postal\s*code|city|state)\b/.test(contextWindow);
  }

  if (ruleId === "DATE_OF_BIRTH") {
    return /\b(dob|birth|born|age|date)\b/.test(contextWindow);
  }

  return true;
}

/**
 * Sanitizes the given input string using high-performance regex matching, contextual validation,
 * positional slice substitution, and sub-5ms latency profiling.
 * 
 * @param rawText Input payload text to inspect and redact.
 * @returns SanitizationResult containing redacted text and count of blocked threats.
 */
export function sanitizePayload(rawText: string): SanitizationResult {
  if (!rawText) {
    return { sanitizedText: "", threatCount: 0 };
  }

  const t0 = typeof performance !== 'undefined' ? performance.now() : 0;
  let sanitizedText = rawText;
  let threatCount = 0;

  DLP_RULES.forEach(rule => {
    rule.pattern.lastIndex = 0; 
    
    interface MatchItem {
      index: number;
      length: number;
    }
    
    const validMatches: MatchItem[] = [];
    let match: RegExpExecArray | null;
    
    while ((match = rule.pattern.exec(sanitizedText)) !== null) {
      if (rule.needsContext && !hasSensitiveContext(sanitizedText, match.index, rule.id)) {
        continue;
      }
      validMatches.push({
        index: match.index,
        length: match[0].length
      });
    }

    // Apply replacements from right to left (highest match index to lowest match index)
    for (let i = validMatches.length - 1; i >= 0; i--) {
      const m = validMatches[i];
      sanitizedText = sanitizedText.slice(0, m.index) + rule.mask + sanitizedText.slice(m.index + m.length);
      threatCount++;
    }
  });

  if (t0 > 0 && typeof performance !== 'undefined') {
    const duration = performance.now() - t0;
    if (duration > 5.0) {
      console.warn(`[SentinelEdge Performance Warning] DLP scan took ${duration.toFixed(2)}ms (budget: <= 5.0ms)`);
    }
  }

  return { sanitizedText, threatCount };
}
