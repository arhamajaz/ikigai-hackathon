import { sanitizePayload } from './dlp-engine';

console.log("\n==================================================");
console.log("   SentinelEdge v2.0 DLP Engine & Context Tests");
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
  {
    name: "Database URI (PostgreSQL / Redis / Mongo)",
    input: "Connect string: postgresql://admin:secret123@db.example.com:5432/main",
    expectedMask: "[REDACTED_DB_CONNECTION_STRING]",
    expectedThreats: 1
  },

  // --- REGIONAL & GLOBAL IDENTIFIERS ---
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
  {
    name: "Password Assignment",
    input: "User config password = SecretP@ss123 for login",
    expectedMask: "[REDACTED_PASSWORD]",
    expectedThreats: 1
  },

  // --- CONTEXTUAL VALIDATION & POSITIONAL REPLACEMENT TESTS ---
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
    name: "Positional Replacement Accuracy (False Positive Precedes True Positive)",
    input: "The year is 2026 and my ATM pin is 2026.",
    expectedMask: "The year is 2026 and my ATM pin is [REDACTED_ATM_PIN].",
    expectedThreats: 1
  },
  {
    name: "Sub-string False Positive Prevention (vscode vs pincode)",
    input: "Check vscode port 110001 for debugging.",
    expectedMask: null, // Should NOT be redacted as pincode because 'vscode' is not 'code'
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

// --- SECTION 3: BENCHMARK SUITE (SUB-2MS BUDGET ENFORCEMENT) ---
console.log("==================================================");
console.log("   SentinelEdge Sub-2ms Latency Benchmarking");
console.log("==================================================\n");

const shortPrompt = "Here is my secret AWS key: AKIAIOSFODNN7EXAMPLE for deploy.";
const mediumPrompt = `
  const config = {
    awsKey: "AKIAIOSFODNN7EXAMPLE",
    dbUrl: "postgresql://admin:secret123@db.example.com:5432/main",
    email: "developer@company.com",
    pan: "ABCDE1234F"
  };
`;

let largePayload = "function auditEngine() {\n";
for (let i = 0; i < 50; i++) {
  largePayload += `  // Line ${i}: System initialization with config parameters and data parsing logic.\n`;
}
largePayload += '  const secretKey = "sk-proj-1234567890abcdef1234567890";\n';
largePayload += '  const connString = "mongodb+srv://admin:pass123@cluster.mongodb.net/prod";\n';
largePayload += '  const supportPhone = "+1 (555) 019-2834";\n';
for (let i = 50; i < 100; i++) {
  largePayload += `  // Line ${i}: Executing telemetry and data loss prevention verification steps.\n`;
}
largePayload += "}\n";

const benchmarks = [
  { name: "Short Prompt (~60 chars)", input: shortPrompt },
  { name: "Medium Config Code (~250 chars)", input: mediumPrompt },
  { name: "Large Code Payload (8,300 chars)", input: largePayload }
];

let allSub2ms = true;

for (const b of benchmarks) {
  sanitizePayload(b.input);

  const iterations = 50;
  let totalTime = 0;
  let maxTime = 0;

  for (let i = 0; i < iterations; i++) {
    const t0 = performance.now();
    sanitizePayload(b.input);
    const dt = performance.now() - t0;
    totalTime += dt;
    if (dt > maxTime) maxTime = dt;
  }

  const avgTime = totalTime / iterations;
  const isBudgetPassed = avgTime <= 2.0;
  if (!isBudgetPassed) allSub2ms = false;

  console.log(`[BENCHMARK] ${b.name}`);
  console.log(`  Payload Length : ${b.input.length} characters`);
  console.log(`  Avg Scan Time  : ${avgTime.toFixed(3)} ms`);
  console.log(`  Max Scan Time  : ${maxTime.toFixed(3)} ms`);
  console.log(`  Budget Status  : ${isBudgetPassed ? '✓ PASS (<= 2.0ms)' : '✗ FAIL (> 2.0ms)'}\n`);
}

if (failed > 0 || !allSub2ms) {
  process.exit(1);
}
