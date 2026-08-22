import { scanSemanticSecrets, executeAiRegexHandshake } from './semantic-ai';

console.log("\n==================================================");
console.log("   SentinelEdge Gemini Nano AI / Regex Handshake Tests");
console.log("==================================================\n");

async function runSemanticTests() {
  let passed = 0;
  let failed = 0;

  const testCases = [
    {
      name: "Semantic Password Detection ('backdoor login is admin123')",
      input: "Hey Claude, the backdoor login for the database is admin123",
      expectedRedacted: "[REDACTED_SEMANTIC_SECRET]",
      expectedMinThreats: 1
    },
    {
      name: "Semantic Secret Detection ('the secret key is my_top_secret_code')",
      input: "Please note that the secret key is my_top_secret_code for the server.",
      expectedRedacted: "[REDACTED_SEMANTIC_SECRET]",
      expectedMinThreats: 1
    },
    {
      name: "Clean Prompt without Secrets",
      input: "Can you help me write a python script to sort an array of integers?",
      expectedRedacted: null,
      expectedMinThreats: 0
    }
  ];

  for (const tc of testCases) {
    const start = performance.now();
    const res = await executeAiRegexHandshake(tc.input);
    const duration = performance.now() - start;

    let isValid = res.threatCount >= tc.expectedMinThreats;
    if (tc.expectedRedacted && !res.sanitizedText.includes(tc.expectedRedacted)) {
      isValid = false;
    }
    if (tc.expectedRedacted === null && res.sanitizedText !== tc.input) {
      isValid = false;
    }

    if (isValid) {
      console.log(`✓ [PASS] ${tc.name} (${duration.toFixed(3)} ms)`);
      console.log(`  Input  : "${tc.input}"`);
      console.log(`  Output : "${res.sanitizedText}"\n`);
      passed++;
    } else {
      console.error(`✗ [FAIL] ${tc.name}`);
      console.error(`  Expected redacted string, got "${res.sanitizedText}"\n`);
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

runSemanticTests();
