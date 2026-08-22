import { processSubmissionGate, needsSemanticCheck } from '../content/index';
import { cacheSemanticSecret, resetAiSession } from './semantic-ai';

console.log("\n==================================================");
console.log("   SentinelEdge v2.2 Master Pipeline Integration Tests");
console.log("==================================================\n");

// Mock Chrome Prompt API for Node test environment to simulate Gemini Nano V8 JSON token extraction
(globalThis as any).window = {
  ai: {
    languageModel: {
      capabilities: async () => ({ available: 'readily' }),
      create: async () => ({
        prompt: async (text: string) => {
          if (text.includes("admin123")) return JSON.stringify({ found: true, secret: "admin123" });
          if (text.includes("admin_root_secret_99")) return JSON.stringify({ found: true, secret: "admin_root_secret_99" });
          return JSON.stringify({ found: false, secret: "" });
        }
      })
    }
  }
};

const s = (parts: string[]) => parts.join('');

async function runPipelineMasterTests() {
  let passed = 0;
  let failed = 0;

  // --- 1. DETERMINISTIC FAST-PATH SUB-2MS BENCHMARK ---
  console.log("[PIPELINE STEP 1] Fast-Path Regex Sub-2ms Latency Benchmark...");
  let largePayload = "/* Production Deployment Script */\n";
  largePayload += `const awsKey = "${s(["AKIA", "IOSFODNN7EXAMPLE"])}";\n`;
  for (let i = 0; i < 50; i++) {
    largePayload += `// Line ${i}: System initialization with config parameters and data parsing logic.\n`;
  }
  largePayload += `const openAIKey = "${s(["sk-proj-", "1234567890abcdef1234567890"])}";\n`;
  largePayload += `const slackHook = "${s(["https://hooks.slack.", "com/services/T00000000/B00000000/XXXXXXXXXXXXXXXXXXXXXXXX"])}";\n`;
  for (let i = 50; i < 100; i++) {
    largePayload += `// Line ${i}: Executing telemetry and data loss prevention verification steps.\n`;
  }

  // Warmup run for JIT compilation
  await processSubmissionGate(largePayload);

  const start1 = performance.now();
  const res1 = await processSubmissionGate(largePayload);
  const dur1 = performance.now() - start1;

  if (dur1 <= 2.0 && res1.totalThreats >= 3) {
    console.log(`✓ [PASS] Fast-Path Regex Processing (${dur1.toFixed(3)} ms)`);
    console.log(`  Payload Length : ${largePayload.length} characters`);
    console.log(`  Threats Blocked: ${res1.totalThreats}\n`);
    passed++;
  } else {
    console.error(`✗ [FAIL] Fast-Path processing latency failed (${dur1.toFixed(3)} ms, threats: ${res1.totalThreats})\n`);
    failed++;
  }

  // --- 2. SHORT-CIRCUIT GUARD TEST ---
  console.log("[PIPELINE STEP 2] Short-Circuit Guard Optimization...");
  const jsonBlob = `{\n  "config": "large_blob",\n  "data": "${"A".repeat(2100)}"\n}`;
  const shouldCheckAi = needsSemanticCheck(jsonBlob);

  const start2 = performance.now();
  const res2 = await processSubmissionGate(jsonBlob);
  const dur2 = performance.now() - start2;

  if (!shouldCheckAi && dur2 <= 1.0) {
    console.log(`✓ [PASS] Short-Circuit Bypassed AI for >2000 Char Structural Payload (${dur2.toFixed(3)} ms)\n`);
    passed++;
  } else {
    console.error(`✗ [FAIL] Short-circuit failed (shouldCheck: ${shouldCheckAi}, duration: ${dur2.toFixed(3)} ms)\n`);
    failed++;
  }

  // --- 3. TIMED LOCAL AI FALLBACK (200MS TIMEOUT BUDGET) ---
  console.log("[PIPELINE STEP 3] Timed Local AI Fallback (200ms Timeout Enforcement)...");
  resetAiSession();
  (globalThis as any).window.ai.languageModel.create = async () => ({
    prompt: () => new Promise(resolve => setTimeout(() => resolve("slow"), 350))
  });

  const slowPrompt = "Hey Claude, the backdoor login for the database is admin123";
  const start3 = performance.now();
  const res3 = await processSubmissionGate(slowPrompt);
  const dur3 = performance.now() - start3;

  // Should timeout at 200ms and return Fast-Path result without crashing
  if (dur3 <= 220.0) {
    console.log(`✓ [PASS] AI 200ms Timeout Enforced Cleanly (${dur3.toFixed(3)} ms)`);
    console.log(`  Fallback Output : "${res3.sanitizedText}"\n`);
    passed++;
  } else {
    console.error(`✗ [FAIL] Timeout enforcement failed (${dur3.toFixed(3)} ms)\n`);
    failed++;
  }

  // Restore fast mock prompt
  resetAiSession();
  (globalThis as any).window.ai.languageModel.create = async () => ({
    prompt: async (text: string) => {
      if (text.includes("admin123")) return JSON.stringify({ found: true, secret: "admin123" });
      if (text.includes("admin_root_secret_99")) return JSON.stringify({ found: true, secret: "admin_root_secret_99" });
      return JSON.stringify({ found: false, secret: "" });
    }
  });

  // --- 4. DEBOUNCED PRE-SCAN CACHE LOOKUP (<0.1MS) ---
  console.log("[PIPELINE STEP 4] Pre-Scanned Cache Hit (<0.1ms Lookup)...");
  const cachePrompt = "The server root passcode is admin_root_secret_99";
  cacheSemanticSecret(cachePrompt, "admin_root_secret_99");

  const start4 = performance.now();
  const res4 = await processSubmissionGate(cachePrompt);
  const dur4 = performance.now() - start4;

  if (dur4 <= 2.0 && res4.sanitizedText.includes("[REDACTED_SEMANTIC_SECRET]")) {
    console.log(`✓ [PASS] Pre-Scanned Cache Lookup Hit (${dur4.toFixed(3)} ms)`);
    console.log(`  Sanitized Output : "${res4.sanitizedText}"\n`);
    passed++;
  } else {
    console.error(`✗ [FAIL] Cache lookup failed (${dur4.toFixed(3)} ms, output: "${res4.sanitizedText}")\n`);
    failed++;
  }

  console.log("--------------------------------------------------");
  console.log(`Summary: ${passed} passed, ${failed} failed out of 4 pipeline master tests.`);
  console.log("--------------------------------------------------\n");

  if (failed > 0) {
    process.exit(1);
  }
}

runPipelineMasterTests();
