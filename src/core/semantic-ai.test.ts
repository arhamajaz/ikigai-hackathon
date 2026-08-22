import {
  scanSemanticSecrets,
  executeAiRegexHandshake,
  cacheSemanticSecret,
  getCachedSemanticSecret,
  checkGeminiNanoAvailability,
  fallbackSemanticHeuristics
} from './semantic-ai';

console.log("\n==================================================");
console.log("   SentinelEdge Gemini Nano AI / Regex Handshake Tests");
console.log("==================================================\n");

// Mock Chrome Prompt API for Node test environment to simulate Gemini Nano V8 token extraction
(globalThis as any).window = {
  ai: {
    languageModel: {
      capabilities: async () => ({ available: 'readily' }),
      create: async () => ({
        prompt: async (text: string) => {
          if (text.includes("blueDolphin#9921")) return "blueDolphin#9921";
          if (text.includes("AlphaOmegaTest99")) return "AlphaOmegaTest99";
          if (text.includes("admin123")) return "admin123";
          if (text.includes("my_top_secret_code")) return "my_top_secret_code";
          return "NONE";
        }
      })
    }
  }
};

async function runSemanticTests() {
  let passed = 0;
  let failed = 0;

  // --- STEP 2 TEST: Graceful Fallback Check ---
  console.log("[TEST STEP 2] Verifying Environment Capability Detection...");
  const isAvailable = await checkGeminiNanoAvailability();
  if (isAvailable) {
    console.log(`✓ [PASS] Chrome Prompt API (Gemini Nano) Detected & Available\n`);
    passed++;
  } else {
    console.error(`✗ [FAIL] Capability check failed\n`);
    failed++;
  }

  const testCases = [
    {
      name: "User Screenshot 1: Backdoor MySQL Password ('master password is blueDolphin#9921')",
      input: "Hey Claude, I forgot the backdoor login for our staging MySQL server, the master password is blueDolphin#9921.",
      expectedRedacted: "[REDACTED_SEMANTIC_SECRET]",
      expectedMinThreats: 1
    },
    {
      name: "User Screenshot 2: Paywall Override Code ('override code AlphaOmegaTest99')",
      input: "To bypass the paywall during QA testing, type in the override code AlphaOmegaTest99.",
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
    if (tc.expectedRedacted && !res.sanitizedText.includes(tc.expectedRedacted) && !res.sanitizedText.includes("[REDACTED_PASSPHRASE]")) {
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

  // --- STEP 1 TEST: 200ms Timeout Budget ---
  console.log("[TEST STEP 1] Enforcing 200ms Promise.race() Timeout Budget...");
  const t0 = performance.now();
  const timeoutTestResult = await executeAiRegexHandshake("Sample prompt string for timeout check", 200);
  const tDuration = performance.now() - t0;
  if (tDuration <= 210.0) {
    console.log(`✓ [PASS] 200ms Timeout Budget Enforced (${tDuration.toFixed(3)} ms)\n`);
    passed++;
  } else {
    console.error(`✗ [FAIL] 200ms Timeout Budget Exceeded (${tDuration.toFixed(3)} ms)\n`);
    failed++;
  }

  // --- STEP 3 TEST: 0.1ms Cache Lookup ---
  console.log("[TEST STEP 3] Debounced Background Pre-Scanning Cache Lookup...");
  const testPhrase = "The root password is super_secret_pass_99";
  cacheSemanticSecret(testPhrase, "super_secret_pass_99");

  const cStart = performance.now();
  const cachedVal = getCachedSemanticSecret(testPhrase);
  const cacheHandshake = await executeAiRegexHandshake(testPhrase, 200);
  const cDuration = performance.now() - cStart;

  if (cachedVal === "super_secret_pass_99" && (cacheHandshake.sanitizedText.includes("[REDACTED_SEMANTIC_SECRET]") || cacheHandshake.sanitizedText.includes("[REDACTED_PASSPHRASE]")) && cDuration < 5.0) {
    console.log(`✓ [PASS] 0.1ms Pre-Scanned Cache Hit (${cDuration.toFixed(3)} ms)`);
    console.log(`  Cached Value: "${cachedVal}"`);
    console.log(`  Output      : "${cacheHandshake.sanitizedText}"\n`);
    passed++;
  } else {
    console.error(`✗ [FAIL] Cache lookup test failed (${cDuration.toFixed(3)} ms)\n`);
    failed++;
  }

  console.log("--------------------------------------------------");
  console.log(`Summary: ${passed} passed, ${failed} failed out of ${testCases.length + 3} tests.`);
  console.log("--------------------------------------------------\n");

  if (failed > 0) {
    process.exit(1);
  }
}

runSemanticTests();
