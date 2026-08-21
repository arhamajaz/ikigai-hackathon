import { sanitizePayload, hasSensitiveContext } from './dlp-engine';

console.log("\n==================================================");
console.log("   SentinelEdge v1.1 DLP Engine & Context Tests");
console.log("==================================================\n");

const testCases = [
  // --- CLOUD SECRETS ---
  {
    name: "AWS Access Key",
    input: "Here is my AWS key: AKIAIOSFODNN7EXAMPLE",
    expectedMask: "[REDACTED_AWS_KEY]",
    expectedThreats: 1
  },
  {
    name: "OpenAI Secret Key",
    input: "My key is sk-proj-1234567890abcdef1234567890",
    expectedMask: "[REDACTED_OPENAI_KEY]",
    expectedThreats: 1
  },

  // --- REGIONAL & FINANCIAL DATA (NEW V1.1) ---
  {
    name: "Indian PAN Card",
    input: "PAN number is ABCDE1234F for verification.",
    expectedMask: "[REDACTED_PAN]",
    expectedThreats: 1
  },
  {
    name: "Aadhaar Card",
    input: "Aadhaar: 2345 6789 0123",
    expectedMask: "[REDACTED_AADHAAR]",
    expectedThreats: 1
  },
  {
    name: "Driving License",
    input: "DL number DL-0419991234567 valid",
    expectedMask: "[REDACTED_DRIVING_LICENSE]",
    expectedThreats: 1
  },
  {
    name: "Mobile Number",
    input: "Call me at +91 9876543210 immediately.",
    expectedMask: "[REDACTED_MOBILE]",
    expectedThreats: 1
  },
  {
    name: "Password Assignment",
    input: "User config password = SecretP@ss123 for login",
    expectedMask: "[REDACTED_PASSWORD]",
    expectedThreats: 1
  },

  // --- CONTEXTUAL VALIDATION TESTS (TRUE POSITIVES vs FALSE POSITIVES) ---
  {
    name: "ATM PIN with Sensitive Context (True Positive)",
    input: "My ATM pin is 2026.",
    expectedMask: "[REDACTED_ATM_PIN]",
    expectedThreats: 1
  },
  {
    name: "Year Number without Context (False Positive Prevention)",
    input: "The year is 2026 and we are building SentinelEdge.",
    expectedMask: null, // Should NOT be redacted!
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

let passed = 0;
let failed = 0;

for (const tc of testCases) {
  const start = performance.now();
  const res = sanitizePayload(tc.input);
  const duration = performance.now() - start;

  let isValid = res.threatCount === tc.expectedThreats;
  if (tc.expectedMask && !res.sanitizedText.includes(tc.expectedMask)) {
    isValid = false;
  }
  if (tc.expectedMask === null && res.sanitizedText !== tc.input) {
    isValid = false;
  }

  if (isValid) {
    console.log(`✓ [PASS] ${tc.name} (${duration.toFixed(3)} ms)`);
    console.log(`  Input  : "${tc.input}"`);
    console.log(`  Output : "${res.sanitizedText}"\n`);
    passed++;
  } else {
    console.error(`✗ [FAIL] ${tc.name}`);
    console.error(`  Expected ${tc.expectedThreats} threats, got ${res.threatCount}`);
    console.error(`  Output : "${res.sanitizedText}"\n`);
    failed++;
  }
}

console.log("--------------------------------------------------");
console.log(`Summary: ${passed} passed, ${failed} failed out of ${testCases.length} tests.`);
console.log("--------------------------------------------------\n");

if (failed > 0) {
  process.exit(1);
}
