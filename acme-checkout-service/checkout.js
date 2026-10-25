const yaml = require('js-yaml');

function processOrderConfig(rawYamlString) {
  // VULNERABLE: In js-yaml 3.13.0, yaml.load() allows remote code execution!
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
