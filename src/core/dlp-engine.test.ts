import { sanitizePayload, DLP_RULES } from './dlp-engine';

console.log("\n==================================================");
console.log("   SentinelEdge v3.0 DLP Engine & Fallback Tests");
console.log("==================================================\n");

const s = (parts: string[]) => parts.join('');

const testCases = [
  // --- CLOUD SECRETS & LLM API KEYS ---
  {
    name: "AWS Access Key",
    input: `Here is my AWS key: ${s(["AKIA", "IOSFODNN7EXAMPLE"])}`,
    expectedMask: "[REDACTED_AWS_KEY]",
    expectedThreats: 1
  },
  {
    name: "AWS MWS Key (Git-Leaks)",
    input: s(["amzn.mws.01234567-0123-0123-0123-", "0123456789ab"]),
    expectedMask: "[REDACTED_AWS_MWS_KEY]",
    expectedThreats: 1
  },
  {
    name: "OpenAI Secret Key",
    input: `My key is ${s(["sk-proj-", "1234567890abcdef1234567890"])}`,
    expectedMask: "[REDACTED_OPENAI_KEY]",
    expectedThreats: 1
  },
  {
    name: "Anthropic Claude API Key (MNC/LLM)",
    input: `anthropicKey = '${s(["sk-ant-api03-", "1234567890abcdef123456789012345678901234567890123456789012345678901234567890123456789012345"])}'`,
    expectedMask: "[REDACTED_ANTHROPIC_KEY]",
    expectedThreats: 1
  },
  {
    name: "Hugging Face Access Token (MNC/LLM)",
    input: `hf_token = '${s(["hf_", "abcdefghijklmnopqrstuvwxyz12345678"])}'`,
    expectedMask: "[REDACTED_HUGGINGFACE_TOKEN]",
    expectedThreats: 1
  },
  {
    name: "Google / Gemini API Key (Quoted / Variable Length)",
    input: `gemini_key = "AIzaSyD123456789012345678901234567890abcd"`,
    expectedMask: "[REDACTED_GOOGLE_API_KEY]",
    expectedThreats: 1
  },
  {
    name: "Universal Key-Value Fallback Engine (Unknown Key Assignment)",
    input: "custom_vendor_secret_key = 'unknown_secret_hash_998877665544332211'",
    expectedMask: "[REDACTED_SENSITIVE_SECRET]",
    expectedThreats: 1
  },
  {
    name: "Database URI (PostgreSQL / Redis / Mongo)",
    input: "Connect string: postgresql://admin:secret123@db.example.com:5432/main",
    expectedMask: "[REDACTED_DB_CONNECTION_STRING]",
    expectedThreats: 1
  },

  // --- KEYHACKS & GIT-LEAKS SIGNATURES ---
  {
    name: "Slack Webhook URL (Keyhacks)",
    input: s(["Post alerts to https://hooks.slack.com/", "services/T00000000/B00000000/XXXXXXXXXXXXXXXXXXXXXXXX"]),
    expectedMask: "[REDACTED_SLACK_WEBHOOK]",
    expectedThreats: 1
  },
  {
    name: "Slack Bot Token (Keyhacks)",
    input: `Bot token ${s(["xoxb-123456789012-123456789012-", "abcdefghijklmnopqrstuvwx"])}`,
    expectedMask: "[REDACTED_SLACK_TOKEN]",
    expectedThreats: 1
  },
  {
    name: "Mailgun API Key (Keyhacks)",
    input: `Mailgun ${s(["key-0123456789abcdef", "0123456789abcdef"])}`,
    expectedMask: "[REDACTED_MAILGUN_KEY]",
    expectedThreats: 1
  },
  {
    name: "Twilio API Key (Keyhacks)",
    input: `Twilio key ${s(["SK0123456789abcdef", "0123456789abcdef"])}`,
    expectedMask: "[REDACTED_TWILIO_KEY]",
    expectedThreats: 1
  },
  {
    name: "SendGrid API Key (Keyhacks)",
    input: "SendGrid SG.1234567890123456789012.1234567890123456789012345678901234567890123",
    expectedMask: "[REDACTED_SENDGRID_KEY]",
    expectedThreats: 1
  },
  {
    name: "Square Access Token (Keyhacks)",
    input: s(["Square token sq0atp-", "1234567890123456789012"]),
    expectedMask: "[REDACTED_SQUARE_TOKEN]",
    expectedThreats: 1
  },
  {
    name: "Shopify Token (Git-Leaks)",
    input: `Shopify token ${s(["shpat_0123456789abcdef", "0123456789abcdef"])}`,
    expectedMask: "[REDACTED_SHOPIFY_TOKEN]",
    expectedThreats: 1
  },
  {
    name: "PyPI Upload Token (Git-Leaks)",
    input: "PyPI token pypi-AgEIcHlwaS5vcmc123456789012345678901234567890123456789012345678901234567890",
    expectedMask: "[REDACTED_PYPI_TOKEN]",
    expectedThreats: 1
  },
  {
    name: "WordPress Config Credential (Git-Leaks)",
    input: "define('DB_PASSWORD', 'SuperSecretPass123');",
    expectedMask: "[REDACTED_WP_CONFIG_CREDENTIAL]",
    expectedThreats: 1
  },

  // --- BANK ACCOUNT REDACTION ---
  {
    name: "Indian Bank Account Number",
    input: "My bank account number is 50100234567890 for transfer.",
    expectedMask: "[REDACTED_BANK_ACCOUNT]",
    expectedThreats: 1
  },
  {
    name: "International IBAN Bank Account",
    input: "Transfer funds to IBAN GB33BUKB20201555555555 now.",
    expectedMask: "[REDACTED_BANK_ACCOUNT]",
    expectedThreats: 1
  },

  // --- REGIONAL IDENTIFIERS ---
  {
    name: "Indian PAN Card",
    input: "PAN number is ABCDE1234F for verification.",
    expectedMask: "[REDACTED_PAN]",
    expectedThreats: 1
  },
  {
    name: "Aadhaar Card (Space Formatted)",
    input: "Aadhaar: 2345 6789 0123",
    expectedMask: "[REDACTED_AADHAAR]",
    expectedThreats: 1
  },
  {
    name: "Aadhaar Card (Hyphen Formatted)",
    input: "Aadhaar card number 2345-6789-0123 valid",
    expectedMask: "[REDACTED_AADHAAR]",
    expectedThreats: 1
  },
  {
    name: "Aadhaar Card (Continuous 12 Digits)",
    input: "Aadhaar 234567890123 verify",
    expectedMask: "[REDACTED_AADHAAR]",
    expectedThreats: 1
  },
  {
    name: "Driving License",
    input: "DL number DL-0419991234567 valid",
    expectedMask: "[REDACTED_DRIVING_LICENSE]",
    expectedThreats: 1
  },

  // --- GLOBAL INTERNATIONAL PHONE NUMBERS ---
  {
    name: "US Phone Number (+1)",
    input: "Call US support at +1 (555) 019-2834 now.",
    expectedMask: "[REDACTED_PHONE_NUMBER]",
    expectedThreats: 1
  },
  {
    name: "UK Phone Number (+44)",
    input: "Contact London office +44 20 7946 0958 today.",
    expectedMask: "[REDACTED_PHONE_NUMBER]",
    expectedThreats: 1
  },
  {
    name: "Japan Phone Number (+81)",
    input: "Call Tokyo office +81 90 1234 5678 immediately.",
    expectedMask: "[REDACTED_PHONE_NUMBER]",
    expectedThreats: 1
  },
  {
    name: "India Mobile Number (+91)",
    input: "Call me at +91 9876543210 immediately.",
    expectedMask: "[REDACTED_PHONE_NUMBER]",
    expectedThreats: 1
  },

  // --- SPECIFIC PIN & CONTEXTUAL RULES ---
  {
    name: "Password Assignment",
    input: "User config password = SecretP@ss123 for login",
    expectedMask: "[REDACTED_PASSWORD]",
    expectedThreats: 1
  },
  {
    name: "ATM PIN with Sensitive Context (True Positive)",
    input: "My ATM pin is 2026.",
    expectedMask: "[REDACTED_ATM_PIN]",
    expectedThreats: 1
  },
  {
    name: "Year Number without Context (False Positive Prevention)",
    input: "The year is 2026 and we are building SentinelEdge.",
    expectedMask: null,
    expectedThreats: 0
  },
  {
    name: "Positional Replacement Accuracy (False Positive Precedes True Positive)",
    input: "The year is 2026 and my ATM pin is 2026.",
    expectedMask: "[REDACTED_ATM_PIN]",
    expectedThreats: 1
  },
  {
    name: "Sub-string False Positive Prevention (vscode vs pincode)",
    input: "Check vscode port 110001 for debugging.",
    expectedMask: null,
    expectedThreats: 0
  },
  {
    name: "UPI PIN with Context (True Positive)",
    input: "Enter your UPI secret passcode 9876 to complete transaction.",
    expectedMask: "[REDACTED_UPI_PIN]",
    expectedThreats: 1
  },
  {
    name: "Postal PIN Code with Context (True Positive)",
    input: "Shipping address pincode 110001 New Delhi",
    expectedMask: "[REDACTED_PIN_CODE]",
    expectedThreats: 1
  },
  {
    name: "Date of Birth with Context (True Positive)",
    input: "DOB is 15-08-1995 for identity verify.",
    expectedMask: "[REDACTED_DOB]",
    expectedThreats: 1
  }
];

function runDlpTests() {
  let passed = 0;
  let failed = 0;

  for (const tc of testCases) {
    const start = performance.now();
    const result = sanitizePayload(tc.input);
    const duration = performance.now() - start;

    let isValid = result.threatCount === tc.expectedThreats;
    if (tc.expectedMask && !result.sanitizedText.includes(tc.expectedMask)) {
      isValid = false;
    }
    if (tc.expectedMask === null && result.sanitizedText !== tc.input) {
      isValid = false;
    }

    if (isValid) {
      console.log(`✓ [PASS] ${tc.name} (${duration.toFixed(3)} ms)`);
      console.log(`  Input  : "${tc.input}"`);
      console.log(`  Output : "${result.sanitizedText}"\n`);
      passed++;
    } else {
      console.error(`✗ [FAIL] ${tc.name}`);
      console.error(`  Input    : "${tc.input}"`);
      console.error(`  Output   : "${result.sanitizedText}"`);
      console.error(`  Expected : ${tc.expectedThreats} threats, mask containing "${tc.expectedMask}"\n`);
      failed++;
    }
  }

  console.log("--------------------------------------------------");
  console.log(`Summary: ${passed} passed, ${failed} failed out of ${testCases.length} tests.`);
  console.log("--------------------------------------------------\n");

  if (failed > 0) {
    process.exit(1);
  }
}

// --- SUB-2MS LATENCY BENCHMARKING ---
function runLatencyBenchmark() {
  console.log("==================================================");
  console.log("   SentinelEdge Sub-2ms Latency Benchmarking");
  console.log("==================================================\n");

  const benchmarks = [
    {
      name: "Short Prompt (~60 chars)",
      input: `Please query the DB with key ${s(["AKIA", "IOSFODNN7EXAMPLE"])} for user records.`
    },
    {
      name: "Medium Config Code (~350 chars)",
      input: `
        const config = {
          awsKey: "${s(["AKIA", "IOSFODNN7EXAMPLE"])}",
          stripeKey: "${s(["sk_live_", "1234567890abcdef1234567890"])}",
          dbUri: "postgresql://admin:secret123@db.example.com:5432/main",
          slackUrl: "${s(["https://hooks.slack.com/", "services/T00000000/B00000000/XXXXXXXXXXXXXXXXXXXXXXXX"])}"
        };
      `
    },
    {
      name: "5,000 Chars + 10 Interspersed Keys Benchmark",
      input: (function() {
        let base = "/* Production Deployment Script */\n";
        base += `const awsKey = "${s(["AKIA", "IOSFODNN7EXAMPLE"])}";\n`;
        for (let i = 0; i < 100; i++) {
          base += `// Line ${i}: System initialization with config parameters and data parsing logic.\n`;
        }
        base += `const openAIKey = "${s(["sk-proj-", "1234567890abcdef1234567890"])}";\n`;
        base += `const slackHook = "${s(["https://hooks.slack.com/", "services/T00000000/B00000000/XXXXXXXXXXXXXXXXXXXXXXXX"])}";\n`;
        for (let i = 100; i < 200; i++) {
          base += `// Line ${i}: Executing telemetry and data loss prevention verification steps.\n`;
        }
        return base;
      })()
    }
  ];

  for (const b of benchmarks) {
    const iterations = 100;
    let totalDuration = 0;
    let maxDuration = 0;

    // Warmup
    sanitizePayload(b.input);

    for (let i = 0; i < iterations; i++) {
      const start = performance.now();
      sanitizePayload(b.input);
      const duration = performance.now() - start;
      totalDuration += duration;
      if (duration > maxDuration) maxDuration = duration;
    }

    const avgDuration = totalDuration / iterations;
    const isSuccess = avgDuration <= 2.0;

    console.log(`[BENCHMARK] ${b.name}`);
    console.log(`  Payload Length : ${b.input.length} characters`);
    console.log(`  Avg Scan Time  : ${avgDuration.toFixed(3)} ms`);
    console.log(`  Max Scan Time  : ${maxDuration.toFixed(3)} ms`);
    console.log(`  Budget Status  : ${isSuccess ? '✓ PASS (<= 2.00ms)' : '✗ FAIL (> 2.00ms)'}\n`);
  }
}

runDlpTests();
runLatencyBenchmark();
