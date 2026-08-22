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
  // --- CLOUD SECRETS & LLM API KEYS ---
  {
    id: "AWS_ACCESS_KEY",
    pattern: /\b(?:A3T[A-Z0-9]|AKIA|AGPA|AIDA|AROA|AIPA|ANPA|ANVA|ASIA)[A-Z0-9]{16}\b/g,
    mask: "[REDACTED_AWS_KEY]",
    needsContext: false
  },
  {
    id: "AWS_MWS_KEY",
    pattern: /\bamzn\.mws\.[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\b/g,
    mask: "[REDACTED_AWS_MWS_KEY]",
    needsContext: false
  },
  {
    id: "ANTHROPIC_API_KEY",
    pattern: /\bsk-ant-api03-[a-zA-Z0-9_-]{80,110}\b/g,
    mask: "[REDACTED_ANTHROPIC_KEY]",
    needsContext: false
  },
  {
    id: "OPENAI_API_KEY",
    pattern: /\bsk-(?!ant-)(?:proj-)?[a-zA-Z0-9_-]{20,}\b/g,
    mask: "[REDACTED_OPENAI_KEY]",
    needsContext: false
  },
  {
    id: "HUGGINGFACE_TOKEN",
    pattern: /\bhf_[a-zA-Z0-9]{34,60}\b/g,
    mask: "[REDACTED_HUGGINGFACE_TOKEN]",
    needsContext: false
  },
  {
    id: "REPLICATE_TOKEN",
    pattern: /\br8_[a-zA-Z0-9]{32,60}\b/g,
    mask: "[REDACTED_REPLICATE_TOKEN]",
    needsContext: false
  },
  {
    id: "DATABRICKS_TOKEN",
    pattern: /\bdapi[a-f0-9]{32}\b/g,
    mask: "[REDACTED_DATABRICKS_TOKEN]",
    needsContext: false
  },
  {
    id: "GITHUB_TOKENS",
    pattern: /\b(?:ghp|gho|ghu|ghs)_[0-9a-zA-Z]{36}\b|\bghr_[0-9a-zA-Z]{76}\b|\bgithub_pat_[0-9a-zA-Z]{22}_[0-9a-zA-Z]{59}\b/g,
    mask: "[REDACTED_GITHUB_TOKEN]",
    needsContext: false
  },
  {
    id: "STRIPE_KEY",
    pattern: /\b(?:sk|rk|pk)_(?:test|live)_[a-zA-Z0-9]{24,99}\b/g,
    mask: "[REDACTED_STRIPE_KEY]",
    needsContext: false
  },
  {
    id: "PRIVATE_KEY",
    pattern: /-----BEGIN (?:(EC|PGP|DSA|RSA|OPENSSH) )?PRIVATE KEY(?: BLOCK)?-----[\s\S]+?-----END (?:(EC|PGP|DSA|RSA|OPENSSH) )?PRIVATE KEY(?: BLOCK)?-----/g,
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

  // --- KEYHACKS & GIT-LEAKS SIGNATURES ---
  {
    id: "SLACK_WEBHOOK",
    pattern: /\bhttps:\/\/hooks\.slack\.com\/services\/T[a-zA-Z0-9_]{8}\/B[a-zA-Z0-9_]{8,12}\/[a-zA-Z0-9_]{24}\b/g,
    mask: "[REDACTED_SLACK_WEBHOOK]",
    needsContext: false
  },
  {
    id: "SLACK_TOKEN",
    pattern: /\bxox[baprs]-[0-9]{10,13}-[0-9]{10,13}-[a-zA-Z0-9]{24,32}\b/g,
    mask: "[REDACTED_SLACK_TOKEN]",
    needsContext: false
  },
  {
    id: "MAILGUN_KEY",
    pattern: /\bkey-[0-9a-zA-Z]{32}\b/g,
    mask: "[REDACTED_MAILGUN_KEY]",
    needsContext: false
  },
  {
    id: "TWILIO_KEY",
    pattern: /\bSK[0-9a-fA-F]{32}\b/g,
    mask: "[REDACTED_TWILIO_KEY]",
    needsContext: false
  },
  {
    id: "SENDGRID_KEY",
    pattern: /\bSG\.[a-zA-Z0-9_-]{16,32}\.[a-zA-Z0-9_-]{16,64}\b/g,
    mask: "[REDACTED_SENDGRID_KEY]",
    needsContext: false
  },
  {
    id: "SQUARE_TOKEN",
    pattern: /\bsq0atp-[0-9A-Za-z\-_]{22}\b|\bsq0csp-[0-9A-Za-z\-_]{43}\b/g,
    mask: "[REDACTED_SQUARE_TOKEN]",
    needsContext: false
  },
  {
    id: "MAILCHIMP_KEY",
    pattern: /\b[0-9a-f]{32}-us[0-9]{1,2}\b/g,
    mask: "[REDACTED_MAILCHIMP_KEY]",
    needsContext: false
  },
  {
    id: "HEROKU_KEY",
    pattern: /\b[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}\b/g,
    mask: "[REDACTED_HEROKU_KEY]",
    needsContext: true
  },
  {
    id: "GOOGLE_API_KEY",
    pattern: /AIza[0-9A-Za-z\-_]{35,45}/g,
    mask: "[REDACTED_GOOGLE_API_KEY]",
    needsContext: false
  },
  {
    id: "BRAINTREE_TOKEN",
    pattern: /\baccess_token\$production\$[0-9a-z]{16}\$[0-9a-f]{32}\b/g,
    mask: "[REDACTED_BRAINTREE_TOKEN]",
    needsContext: false
  },
  {
    id: "PICATIC_KEY",
    pattern: /\bsk_live_[0-9a-z]{32}\b/g,
    mask: "[REDACTED_PICATIC_KEY]",
    needsContext: false
  },
  {
    id: "DYNATRACE_TOKEN",
    pattern: /\bdt0c[0-9]{2}\.[A-Z0-9]{24}\.[A-Z0-9]{64}\b|\bdt0[a-zA-Z][0-9]{2}\.[A-Z0-9]{24}\.[A-Z0-9]{64}\b/g,
    mask: "[REDACTED_DYNATRACE_TOKEN]",
    needsContext: false
  },
  {
    id: "SHOPIFY_TOKEN",
    pattern: /\bshp(?:ss|at|ca|pa)_[a-fA-F0-9]{32}\b/g,
    mask: "[REDACTED_SHOPIFY_TOKEN]",
    needsContext: false
  },
  {
    id: "PYPI_TOKEN",
    pattern: /\bpypi-AgEIcHlwaS5vcmc[A-Za-z0-9-_]{50,1000}\b/g,
    mask: "[REDACTED_PYPI_TOKEN]",
    needsContext: false
  },

  // --- SOCIAL MEDIA & CONTEXTUAL SECRETS ---
  {
    id: "FACEBOOK_KEY",
    pattern: /(?:facebook|fb)[\s\S]{0,20}?['"][0-9a-f]{32}['"]/gi,
    mask: "[REDACTED_FACEBOOK_KEY]",
    needsContext: true
  },
  {
    id: "TWITTER_KEY",
    pattern: /(?:twitter)[\s\S]{0,20}?['"][0-9a-z]{35,44}['"]/gi,
    mask: "[REDACTED_TWITTER_KEY]",
    needsContext: true
  },
  {
    id: "LINKEDIN_KEY",
    pattern: /(?:linkedin)[\s\S]{0,20}?['"][0-9a-z]{12,16}['"]/gi,
    mask: "[REDACTED_LINKEDIN_KEY]",
    needsContext: true
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
    pattern: /\b[0-9]{4}[\s-]?[0-9]{4}[\s-]?[0-9]{4}\b/g,
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
    pattern: /(?:\+|00)[1-9]\d{0,3}[\s.\-]?(?:\(\d{1,5}\)[\s.\-]?)?\d{2,4}[\s.\-]?\d{3,4}[\s.\-]?\d{3,4}\b|(?:\(\d{3}\)|\b\d{3})[\s.\-]\d{3}[\s.\-]\d{4}\b|\b[6-9]\d{9}\b/g,
    mask: "[REDACTED_PHONE_NUMBER]",
    needsContext: false
  },

  // --- PASSPHRASE & CREDENTIAL PROSE REDACTION ENGINE ---
  {
    id: "PASSPHRASE_AFTER_ACTION_VERB",
    pattern: /(?:\b(?:enter|use|type|input)\s+['"]?)([a-zA-Z0-9_-]{4,64})(?=['"]?\s+(?:whenever|when|for|as|if|to|in|into|on|at|with)\b[\s\S]{0,40}?\b(?:passphrase|password|secret|key|token|credential|login|ssh|bastion|auth)\b)/gi,
    mask: "[REDACTED_PASSPHRASE]",
    needsContext: false
  },
  {
    id: "PASSPHRASE_PROSE_DECLARATION",
    pattern: /(?:\b(?:passphrase|password|secret[_\s]*key|ssh[_\s]*key|bastion[_\s]*key|auth[_\s]*key)\s+(?:is|:|=)\s+['"]?)([a-zA-Z0-9_-]{4,64})(?=['"]?(?:[\s,;.]|$))/gi,
    mask: "[REDACTED_PASSPHRASE]",
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
  {
    id: "ENV_VAR_CREDENTIAL",
    pattern: /(?:apikey|api_key|secret|password|passwd|pwd|pass|auth|token)[\s]*[=:][\s]*['"]?[0-9a-zA-Z-_.\/+!{}/=]{6,120}['"]?/gi,
    mask: "[REDACTED_ENV_CREDENTIAL]",
    needsContext: false
  },
  {
    id: "WP_CONFIG_CREDENTIAL",
    pattern: /define\s*\(\s*['"](?:DB_PASSWORD|NONCE_SALT|LOGGED_IN_SALT|AUTH_SALT|NONCE_KEY|DB_HOST|AUTH_KEY|SECURE_AUTH_KEY|LOGGED_IN_KEY|DB_NAME|DB_USER)['"]\s*,\s*['"][^'"]{4,120}['"]\s*\)/gi,
    mask: "[REDACTED_WP_CONFIG_CREDENTIAL]",
    needsContext: false
  },

  // --- UNIVERSAL FALLBACK KEY-VALUE ASSIGNMENT REDACTION ENGINE ---
  {
    id: "GENERIC_KEY_VALUE_FALLBACK",
    pattern: /(?:\b[a-zA-Z0-9_-]*(?:key|secret|token|password|passwd|pass|auth|credential)[a-zA-Z0-9_-]*\b[\s]*[:=][\s]*['"]?)([a-zA-Z0-9_.\/+=~-]{8,128})(?=['"]?(?:[\s,;}\n]|$))/gi,
    mask: "[REDACTED_SENSITIVE_SECRET]",
    needsContext: false
  },

  // --- GENERIC SENSITIVE PII ---
  {
    id: "CREDIT_CARD",
    pattern: /\b(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14}|3[47][0-9]{13}|3(?:0[0-5]|[68][0-9])[0-9]{11}|6(?:011|5[0-9]{2})[0-9]{12}|(?:[0-9]{4}[ -]){3}[0-9]{4})\b/g,
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
 * Contextual validation filter to prevent false positives on short numeric strings, dates, or generic UUIDs.
 * Inspects a 30-character window preceding the match for sensitive context keywords with word boundaries.
 */
export function hasSensitiveContext(fullText: string, matchIndex: number, ruleId: string): boolean {
  const contextWindow = fullText.substring(Math.max(0, matchIndex - 30), matchIndex).toLowerCase();
  
  if (ruleId === "HEROKU_KEY") {
    return /\b(heroku|api[_\s]*key|token|auth|secret)\b/.test(contextWindow);
  }

  if (ruleId === "FACEBOOK_KEY") {
    return /\b(facebook|fb)\b/.test(contextWindow);
  }

  if (ruleId === "TWITTER_KEY") {
    return /\b(twitter)\b/.test(contextWindow);
  }

  if (ruleId === "LINKEDIN_KEY") {
    return /\b(linkedin)\b/.test(contextWindow);
  }

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
 * Sanitizes the given input string using pre-compiled high-performance regex matching,
 * contextual validation, positional slice substitution, and sub-2ms latency profiling.
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

  for (let r = 0; r < DLP_RULES.length; r++) {
    const rule = DLP_RULES[r];
    rule.pattern.lastIndex = 0; 
    
    interface MatchItem {
      index: number;
      length: number;
      replacementText: string;
    }
    
    const validMatches: MatchItem[] = [];
    let match: RegExpExecArray | null;
    
    while ((match = rule.pattern.exec(sanitizedText)) !== null) {
      if (rule.needsContext && !hasSensitiveContext(sanitizedText, match.index, rule.id)) {
        continue;
      }

      if ((rule.id === "GENERIC_KEY_VALUE_FALLBACK" || rule.id === "PASSPHRASE_AFTER_ACTION_VERB" || rule.id === "PASSPHRASE_PROSE_DECLARATION") && match[1]) {
        // Replace only the captured sensitive value, keeping assignment key or prose prefix intact
        const fullMatchStr = match[0];
        const secretVal = match[1];
        const valIndex = match.index + fullMatchStr.lastIndexOf(secretVal);
        validMatches.push({
          index: valIndex,
          length: secretVal.length,
          replacementText: rule.mask
        });
      } else {
        validMatches.push({
          index: match.index,
          length: match[0].length,
          replacementText: rule.mask
        });
      }
    }

    // Apply replacements from right to left (highest match index to lowest match index)
    for (let i = validMatches.length - 1; i >= 0; i--) {
      const m = validMatches[i];
      sanitizedText = sanitizedText.slice(0, m.index) + m.replacementText + sanitizedText.slice(m.index + m.length);
      threatCount++;
    }
  }

  if (t0 > 0 && typeof performance !== 'undefined') {
    const duration = performance.now() - t0;
    if (duration > 5.0) {
      console.warn(`[SentinelEdge Performance Warning] DLP scan took ${duration.toFixed(2)}ms (budget: <= 5.0ms)`);
    }
  }

  return { sanitizedText, threatCount };
}
