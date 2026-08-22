import { PolicyEngine } from './policy-engine';

console.log("\n==================================================");
console.log("   SentinelEdge v2.1 Policy Engine Audit Tests");
console.log("==================================================\n");

function runPolicyTests() {
  let passed = 0;
  let failed = 0;

  const testCases = [
    {
      name: "Clean Redacted Text Audit",
      input: "Here is my AWS key: [REDACTED_AWS_KEY]",
      expectedCompliant: true,
      expectedResiduals: 0
    },
    {
      name: "Unredacted AWS Secret Violation Detection",
      input: "Here is my AWS key: AKIAIOSFODNN7EXAMPLE",
      expectedCompliant: false,
      expectedResiduals: 1
    }
  ];

  for (const tc of testCases) {
    const start = performance.now();
    const res = PolicyEngine.evaluate(tc.input);
    const duration = performance.now() - start;

    let isValid = res.isCompliant === tc.expectedCompliant && res.residualThreatsCount === tc.expectedResiduals;

    if (isValid) {
      console.log(`✓ [PASS] ${tc.name} (${duration.toFixed(3)} ms)`);
      console.log(`  Input     : "${tc.input}"`);
      console.log(`  Compliant : ${res.isCompliant}\n`);
      passed++;
    } else {
      console.error(`✗ [FAIL] ${tc.name}`);
      console.error(`  Expected compliant ${tc.expectedCompliant}, got ${res.isCompliant}\n`);
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

runPolicyTests();
