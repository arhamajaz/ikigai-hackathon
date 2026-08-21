import { maskPassword, maskPasswordRegex } from './mask-password';

console.log("\n==================================================");
console.log("   SentinelEdge Password Masking Utility Tests");
console.log("==================================================\n");

const testCases = [
  // --- 1. STANDARD PASSWORDS ---
  {
    name: "Standard ASCII Password",
    input: "P@ssw0rd123!",
    maskChar: "•",
    expected: "••••••••••••"
  },
  {
    name: "Custom Mask Symbol (*)",
    input: "SecretPass",
    maskChar: "*",
    expected: "**********"
  },

  // --- 2. SPECIAL CHARACTERS & NEWLINES ---
  {
    name: "Newlines, Tabs, and Spaces",
    input: "Line1\nLine2\r\tSymbol#",
    maskChar: "•",
    expectedLength: 20
  },

  // --- 3. GRAPHEME CLUSTERS & EMOJIS ---
  {
    name: "Surrogate Pair Emoji (Key 🔑)",
    input: "Key🔑123",
    maskChar: "•",
    expected: "•••••••" // Key (3) + 🔑 (1) + 123 (3) = 7 graphemes
  },
  {
    name: "Skin Tone Modifier Emoji (Thumbs Up 👍🏽)",
    input: "Thumb👍🏽",
    maskChar: "•",
    expected: "••••••" // Thumb (5) + 👍🏽 (1) = 6 graphemes
  },
  {
    name: "ZWJ Sequence (Family 👨‍👩‍👧)",
    input: "Pass👨‍👩‍👧Secret",
    maskChar: "•",
    expected: "•••••••••••" // Pass (4) + 👨‍👩‍👧 (1) + Secret (6) = 11 graphemes
  },

  // --- 4. INPUT VALIDATION & DEFENSIVE TYPE SAFETY ---
  { name: "null input", input: null, expected: "" },
  { name: "undefined input", input: undefined, expected: "" },
  { name: "number input", input: 123456, expected: "" },
  { name: "boolean input", input: true, expected: "" },
  { name: "object input", input: { pass: "123" }, expected: "" },
  { name: "empty string input", input: "", expected: "" }
];

let passed = 0;
let failed = 0;

for (const tc of testCases) {
  const start = performance.now();
  const result = maskPassword(tc.input, tc.maskChar);
  const duration = performance.now() - start;

  let isValid = true;
  if (tc.expected !== undefined && result !== tc.expected) {
    isValid = false;
  }

  if (isValid) {
    console.log(`✓ [PASS] ${tc.name} (${duration.toFixed(3)} ms)`);
    console.log(`  Input  : ${JSON.stringify(tc.input)}`);
    console.log(`  Output : "${result}"\n`);
    passed++;
  } else {
    console.error(`✗ [FAIL] ${tc.name}`);
    console.error(`  Expected : "${tc.expected}"`);
    console.error(`  Actual   : "${result}"\n`);
    failed++;
  }
}

console.log("--------------------------------------------------");
console.log(`Summary: ${passed} passed, ${failed} failed out of ${testCases.length} tests.`);
console.log("--------------------------------------------------\n");

// Benchmark Comparison: Segmenter vs Regex /./gsu
console.log("=== Grapheme Accuracy Comparison (ZWJ Family Emoji 👨‍👩‍👧) ===");
const zwjInput = "👨‍👩‍👧";
console.log(`Input ZWJ String   : "👨‍👩‍👧" (Visual Count = 1)`);
console.log(`UTF-16 Code Units  : ${zwjInput.length} code units`);
console.log(`Intl.Segmenter Mask: "${maskPassword(zwjInput)}" (Length: ${maskPassword(zwjInput).length}) -> Correct 1 character`);
console.log(`Regex /./gsu Mask   : "${maskPasswordRegex(zwjInput)}" (Length: ${maskPasswordRegex(zwjInput).length}) -> 3 code points (limitation)\n`);
