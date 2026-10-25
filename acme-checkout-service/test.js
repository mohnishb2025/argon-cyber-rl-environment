const assert = require('assert');
const { processOrderConfig } = require('./checkout.js');

console.log("Running ACME Checkout Unit Tests...");

try {
  const sampleYaml = `
merchantId: "ACME-99"
amount: 100
  `;
  const result = processOrderConfig(sampleYaml);
  assert.strictEqual(result.status, "PROCESSED");
  assert.strictEqual(result.merchant, "ACME-99");
  assert.strictEqual(result.total, 108);
  console.log("✅ Test 1 Passed: Valid YAML order calculation");

  assert.throws(() => {
    processOrderConfig("amount: 50");
  }, /Invalid order configuration/);
  console.log("✅ Test 2 Passed: Rejects invalid configuration");

  console.log("🎉 ALL UNIT TESTS PASSED!");
  process.exit(0);
} catch (error) {
  console.error("❌ UNIT TEST FAILED:", error.message);
  process.exit(1);
}
