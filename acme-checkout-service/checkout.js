const yaml = require('js-yaml');

function processOrderConfig(rawYamlString) {
  // PATCHED (CRS Surgeon): Upgraded to js-yaml ^4.1.0 where yaml.load() enforces DEFAULT_SAFE_SCHEMA by default
  const config = yaml.load(rawYamlString);
  
  if (!config || !config.merchantId) {
    throw new Error("Invalid order configuration");
  }
  
  return {
    status: "PROCESSED",
    merchant: config.merchantId,
    total: config.amount * 1.08
  };
}

module.exports = { processOrderConfig };
