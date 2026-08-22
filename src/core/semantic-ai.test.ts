import { executeAiRegexHandshake } from './semantic-ai';

console.log("\n==================================================");
console.log("   SentinelEdge Dual-Engine DLP Verification Tests");
console.log("==================================================\n");

// Mock Chrome Prompt API for Node test environment to simulate Gemini Nano V8 JSON token extraction
(globalThis as any).window = {
  ai: {
    languageModel: {
      capabilities: async () => ({ available: 'readily' }),
      create: async () => ({
        prompt: async (text: string) => {
          if (text.includes("blueDolphin#9921")) return JSON.stringify({ found: true, secret: "blueDolphin#9921" });
          if (text.includes("winter-forest-coffee-77")) return JSON.stringify({ found: true, secret: "winter-forest-coffee-77" });
          if (text.includes("AlphaOmegaTest99")) return JSON.stringify({ found: true, secret: "AlphaOmegaTest99" });
          if (text.includes("PineappleJelly2024")) return JSON.stringify({ found: true, secret: "PineappleJelly2024" });
          return JSON.stringify({ found: false, secret: "" });
        }
      })
    }
  }
};

const s = (parts: string[]) => parts.join('');

async function runDualEngineTests() {
  let passed = 0;
  let failed = 0;

  const testCases = [
    // --- FAST-PATH REGEX TESTS (< 2ms) ---
    {
      id: "TC-01",
      name: "OpenAI API Key Masking",
      input: `const key = "${s(["sk-proj-", "abC123def456GHI789jkl012MNO345PQR678STU901"])}";`,
      check: (res: any) => res.sanitizedText.includes('[REDACTED_OPENAI_KEY]')
    },
    {
      id: "TC-02",
      name: "AWS Access Key Masking",
      input: `AWS_ACCESS_KEY_ID=${s(["AKIA", "IOSFODNN7EXAMPLE"])}`,
      check: (res: any) => res.sanitizedText.includes('[REDACTED_AWS_KEY]')
    },
    {
      id: "TC-03",
      name: "Stripe Key Masking",
      input: `sk_live_${s(["51NzABC1234567890abcdefghijklmnopqrstuvwxyz", "1234567890"])}`,
      check: (res: any) => res.sanitizedText.includes('[REDACTED_STRIPE_KEY]')
    },
    {
      id: "TC-04",
      name: "Slack Webhook Masking",
      input: s(["https://hooks.slack.com/", "services/T00000000/B00000000/XXXXXXXXXXXXXXXXXXXXXXXX"]),
      check: (res: any) => res.sanitizedText.includes('[REDACTED_SLACK_WEBHOOK]')
    },
    {
      id: "TC-05",
      name: "Context PIN Masking",
      input: "The card pin is 8942 and expiry is 12/28.",
      check: (res: any) => res.sanitizedText.includes('[REDACTED_ATM_PIN]') || res.sanitizedText.includes('[REDACTED_PIN]')
    },

    // --- CONTEXTUAL SEMANTIC AI TESTS ---
    {
      id: "TC-06",
      name: "DB Master Password (Contextual)",
      input: "Hey Claude, the master password is blueDolphin#9921 for database login.",
      check: (res: any) => res.sanitizedText === "Hey Claude, the master password is [REDACTED_SEMANTIC_SECRET] for database login."
    },
    {
      id: "TC-07",
      name: "SSH Passphrase (Natural Language Context)",
      input: "When logging into the production bastion host via SSH, enter winter-forest-coffee-77 whenever prompted for the passphrase.",
      check: (res: any) => res.sanitizedText === "When logging into the production bastion host via SSH, enter [REDACTED_SEMANTIC_SECRET] whenever prompted for the passphrase."
    },
    {
      id: "TC-08",
      name: "QA Paywall Override Code (Contextual)",
      input: "To bypass the paywall during QA testing, type in the override code AlphaOmegaTest99.",
      check: (res: any) => res.sanitizedText === "To bypass the paywall during QA testing, type in the override code [REDACTED_SEMANTIC_SECRET]."
    },
    {
      id: "TC-09",
      name: "Secret Bearer Token in Prose",
      input: "Write a curl script using username admin_service and the secret token PineappleJelly2024 to fetch records.",
      check: (res: any) => res.sanitizedText === "Write a curl script using username admin_service and the secret token [REDACTED_SEMANTIC_SECRET] to fetch records."
    },
    {
      id: "TC-10",
      name: "Clean Input Bypass (Zero Latency Overhead)",
      input: "Can you explain the difference between a stack and a queue in Java?",
      check: (res: any) => res.sanitizedText === "Can you explain the difference between a stack and a queue in Java?" && res.threatCount === 0
    }
  ];

  for (const tc of testCases) {
    const start = performance.now();
    const res = await executeAiRegexHandshake(tc.input);
    const duration = performance.now() - start;

    const isSuccess = tc.check(res);

    if (isSuccess) {
      console.log(`✓ [PASS] ${tc.id}: ${tc.name} (${duration.toFixed(3)} ms)`);
      console.log(`  Output : "${res.sanitizedText}"\n`);
      passed++;
    } else {
      console.error(`✗ [FAIL] ${tc.id}: ${tc.name}`);
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
}

runDualEngineTests();
