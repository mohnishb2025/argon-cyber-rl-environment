const fs = require('fs');
const path = require('path');
const https = require('https');

const ENV_PATH = path.join(__dirname, '.env');
const RESULTS_PATH = path.join(__dirname, 'eval-results.json');

function getOpenAiKey() {
  if (fs.existsSync(ENV_PATH)) {
    const content = fs.readFileSync(ENV_PATH, 'utf-8');
    const match = content.match(/OPENAI_API_KEY=(.+)/);
    if (match && match[1]) {
      return match[1].trim().replace(/^["']|["']$/g, '');
    }
  }
  if (process.env.OPENAI_API_KEY && process.env.OPENAI_API_KEY.startsWith('sk-')) {
    return process.env.OPENAI_API_KEY.trim();
  }
  throw new Error('OPENAI_API_KEY not found in .env');
}

function extractFirstJsonObject(rawText) {
  const cleaned = String(rawText || '')
    .replace(/^```json\s*/i, '')
    .replace(/^```\s*/i, '')
    .replace(/\s*```$/, '')
    .trim();
  try {
    return JSON.parse(cleaned);
  } catch {
    const firstBrace = cleaned.indexOf('{');
    const lastBrace = cleaned.lastIndexOf('}');
    if (firstBrace !== -1 && lastBrace > firstBrace) {
      return JSON.parse(cleaned.slice(firstBrace, lastBrace + 1));
    }
    throw new Error('Could not parse JSON from: ' + cleaned.slice(0, 200));
  }
}

// Call gpt-4o-mini via /v1/responses
function callGpt4oMini(apiKey, systemPrompt, userPrompt) {
  const start = Date.now();
  return new Promise((resolve, reject) => {
    const payload = JSON.stringify({
      model: 'gpt-4o-mini',
      temperature: 0,
      input: [
        { role: 'system', content: systemPrompt },
        { role: 'user', content: userPrompt }
      ]
    });

    const req = https.request(
      {
        hostname: 'api.openai.com',
        path: '/v1/responses',
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          Authorization: `Bearer ${apiKey}`,
          'Content-Length': Buffer.byteLength(payload)
        },
        timeout: 90000
      },
      (res) => {
        let body = '';
        res.on('data', (chunk) => (body += chunk));
        res.on('end', () => {
          const latencyMs = Date.now() - start;
          try {
            const parsed = JSON.parse(body);
            if (parsed.error) {
              return reject(new Error(parsed.error.message));
            }
            const msgItem = (parsed.output || []).find((item) => item.type === 'message');
            const textObj = (msgItem?.content || []).find((c) => c.type === 'output_text');
            const rawText = textObj?.text || '{}';
            resolve({
              model: 'gpt-4o-mini',
              effort: 'standard (temp=0)',
              latencyMs,
              inputTokens: parsed.usage?.input_tokens || 0,
              outputTokens: parsed.usage?.output_tokens || 0,
              reasoningTokens: parsed.usage?.output_tokens_details?.reasoning_tokens || 0,
              rawText,
              json: extractFirstJsonObject(rawText)
            });
          } catch (e) {
            reject(new Error(`Failed to parse gpt-4o-mini response: ${e.message}`));
          }
        });
      }
    );
    req.on('error', reject);
    req.write(payload);
    req.end();
  });
}

// Call gpt-6-astra with reasoning.effort = "max" via /v1/responses
function callGpt6AstraMax(apiKey, systemPrompt, userPrompt) {
  const start = Date.now();
  return new Promise((resolve, reject) => {
    const payload = JSON.stringify({
      model: 'gpt-6-astra',
      reasoning: { effort: 'max' },
      input: [
        { role: 'system', content: systemPrompt },
        { role: 'user', content: userPrompt }
      ]
    });

    const req = https.request(
      {
        hostname: 'api.openai.com',
        path: '/v1/responses',
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          Authorization: `Bearer ${apiKey}`,
          'Content-Length': Buffer.byteLength(payload)
        },
        timeout: 180000
      },
      (res) => {
        let body = '';
        res.on('data', (chunk) => (body += chunk));
        res.on('end', () => {
          const latencyMs = Date.now() - start;
          try {
            const parsed = JSON.parse(body);
            if (parsed.error) {
              return reject(new Error(parsed.error.message));
            }
            const msgItem = (parsed.output || []).find((item) => item.type === 'message');
            const textObj = (msgItem?.content || []).find((c) => c.type === 'output_text');
            const rawText = textObj?.text || '{}';
            resolve({
              model: 'gpt-6-astra',
              effort: 'max',
              latencyMs,
              inputTokens: parsed.usage?.input_tokens || 0,
              outputTokens: parsed.usage?.output_tokens || 0,
              reasoningTokens: parsed.usage?.output_tokens_details?.reasoning_tokens || 0,
              rawText,
              json: extractFirstJsonObject(rawText)
            });
          } catch (e) {
            reject(new Error(`Failed to parse gpt-6-astra response: ${e.message}`));
          }
        });
      }
    );
    req.on('error', reject);
    req.write(payload);
    req.end();
  });
}

// ============================================================================
// MAXIMUM-DIFFICULTY CYBER REASONING & RL EVALUATION SUITE (6 HARD TASKS)
// Zero hints provided in prompts — requires deep code, AST, crypto & math analysis
// ============================================================================
const EVAL_TASKS = [
  {
    id: 'EVAL-1-AST-SHADOWING-AND-TAINT',
    title: 'Variable Shadowing, Dead-Branch Invariants & Prototype Pollution Taint Analysis',
    category: 'AST Reachability & Taint Analysis',
    difficulty: 'MAXIMUM',
    prompt: `Audit the following Node.js microservice running dependencies {"js-yaml": "3.13.0", "lodash": "4.17.15"}.
Assume all exported functions are invoked with untrusted attacker-controlled strings/objects:

File: service.js
1: const yaml = require('js-yaml');
2: const _ = require('lodash');
3: const FLAG = (0x1a ^ 0x1a);
4: function parseManifest(rawInput) {
5:   const { load: parser } = yaml;
6:   if (FLAG && process.env.FORCE_UNSAFE) {
7:     return parser(rawInput);
8:   }
9:   const yamlShadow = { load: (s) => yaml.safeLoad(s, { schema: yaml.DEFAULT_SAFE_SCHEMA }) };
10:  return yamlShadow.load(rawInput);
11: }
12: function updateCartMetadata(cart, keyPath, val) {
13:   const safeKey = String(keyPath).replace(/__proto__/g, '');
14:   return _.set({}, safeKey, val);
15: }
16: module.exports = { parseManifest, updateCartMetadata };

Determine from first principles (with zero assumptions):
1. Is arbitrary code execution via js-yaml 3.13.0 (!!js/function) reachable at runtime in parseManifest(rawInput)?
2. In updateCartMetadata, line 13 strips "__proto__" once via .replace(/__proto__/g, ''). Can an attacker STILL pollute Object.prototype at line 14 via TWO distinct bypasses in lodash 4.17.15 (both via "constructor.prototype.polluted" AND via nested "__pro__proto__to__.polluted")?
3. Even though line 14 passes a fresh empty object literal {} as the first argument to _.set({}, safeKey, val), does polluting Object.prototype via _.set({}, ...) persist globally across all subsequent objects in the Node.js V8 isolate?
4. What is the exact 1-based line number of the only actually exploitable sink in service.js?

Return ONLY valid JSON with these exact keys:
{
  "parseManifestExploitableAtRuntime": boolean,
  "constructorPrototypeBypassWorks": boolean,
  "nestedProtoStringBypassWorks": boolean,
  "emptyObjectLiteralStillPollutesGlobalPrototype": boolean,
  "exploitableLineNumber": number
}`,
    groundTruth: {
      parseManifestExploitableAtRuntime: false,
      constructorPrototypeBypassWorks: true,
      nestedProtoStringBypassWorks: true,
      emptyObjectLiteralStillPollutesGlobalPrototype: true,
      exploitableLineNumber: 14
    },
    scoreFn: (ans) => {
      const checks = [
        ans.parseManifestExploitableAtRuntime === false,
        ans.constructorPrototypeBypassWorks === true,
        ans.nestedProtoStringBypassWorks === true,
        ans.emptyObjectLiteralStillPollutesGlobalPrototype === true,
        Number(ans.exploitableLineNumber) === 14
      ];
      return { passed: checks.filter(Boolean).length, total: checks.length, checks };
    }
  },
  {
    id: 'EVAL-2-SEMVER-API-BREAKAGE-MATRIX',
    title: 'js-yaml 3.13.0 -> 4.1.0 Exact Runtime Exception & Schema Semantics Matrix',
    category: 'Surgeon Agent Patch Verification',
    difficulty: 'MAXIMUM',
    prompt: `A microservice upgrades "js-yaml" from "3.13.0" to "4.1.0" in package.json without changing any source code.
Consider these 5 expressions executed in Node.js under js-yaml 4.1.0:
  Expr 1: yaml.load("a: 1")
  Expr 2: yaml.safeLoad("a: 1")
  Expr 3: yaml.safeDump({ a: 1 })
  Expr 4: yaml.load("f: !!js/function 'function(){return 1}'")
  Expr 5: yaml.DEFAULT_FULL_SCHEMA

Determine the exact behavior of js-yaml 4.1.0:
1. Which of Expr 1, Expr 2, Expr 3, Expr 4 throw an exception at runtime in js-yaml 4.1.0?
   - Note whether Expr 1 succeeds (returns {a: 1}).
   - Note whether Expr 2 throws TypeError (because safeLoad was removed in v4).
   - Note whether Expr 3 throws TypeError (because safeDump was removed in v4).
   - Note whether Expr 4 throws YAMLException (because !!js/function is no longer in v4's default schema).
2. In js-yaml 4.1.0, does yaml.DEFAULT_FULL_SCHEMA still exist on the exported module, or was it removed in v4 (evaluating to undefined)?

Return ONLY valid JSON with these exact keys:
{
  "expr1Throws": boolean,
  "expr2ThrowsTypeError": boolean,
  "expr3ThrowsTypeError": boolean,
  "expr4ThrowsYamlException": boolean,
  "expr5DefaultFullSchemaIsUndefined": boolean
}`,
    groundTruth: {
      expr1Throws: false,
      expr2ThrowsTypeError: false, // In js-yaml 4.1.0, safeLoad is a renamed() stub that throws new Error(...), NOT TypeError!
      expr3ThrowsTypeError: false, // In js-yaml 4.1.0, safeDump is a renamed() stub that throws new Error(...), NOT TypeError!
      expr4ThrowsYamlException: true,
      expr5DefaultFullSchemaIsUndefined: true
    },
    scoreFn: (ans) => {
      const checks = [
        ans.expr1Throws === false,
        ans.expr2ThrowsTypeError === false,
        ans.expr3ThrowsTypeError === false,
        ans.expr4ThrowsYamlException === true,
        ans.expr5DefaultFullSchemaIsUndefined === true
      ];
      return { passed: checks.filter(Boolean).length, total: checks.length, checks };
    }
  },
  {
    id: 'EVAL-3-NONSTATIONARY-TD0-ROUNDING-CASCADE',
    title: '6-Episode Stateful TD(0) Q-Learning with Intermediate .toFixed(4) Rounding Cascade',
    category: 'Reinforcement Learning Math',
    difficulty: 'MAXIMUM',
    prompt: `Simulate Argon CRS-RL's exact updateRlPolicy() loop across 6 episodes for two state-action pairs:
State A (Reachable CVE): initial Q_0 = 0.5000, visits_0 = 0, alpha = 0.25
State B (Unreachable CVE): initial Q_0 = 0.2500, visits_0 = 0, alpha = 0.25

At EVERY episode t = 1..6, updateRlPolicy executes:
  tdError = Number((reward - oldQ).toFixed(4));
  newQ = Number((oldQ + 0.25 * (reward - oldQ)).toFixed(4));
(Crucial: oldQ in episode t is the rounded 4-decimal newQ from episode t-1!)

Rewards received by State A across episodes 1..6:
  t=1: +1.0
  t=2: -1.0
  t=3: +1.0
  t=4: -1.0
  t=5: +1.0
  t=6: +1.0

Rewards received by State B across episodes 1..6:
  t=1: +0.5
  t=2: +0.5
  t=3: -0.5
  t=4: +0.5
  t=5: +0.5
  t=6: +0.5

Also compute epistemic confidence at visit 6 using:
  confidence = Math.min(99, Math.round((1 - Math.pow(0.5, 6)) * 1000) / 10)

Return ONLY valid JSON with these exact keys:
{
  "stateA_Q2": number,
  "stateA_Q4": number,
  "stateA_Q6": number,
  "stateB_Q3": number,
  "stateB_Q6": number,
  "confidenceVisit6": number
}`,
    groundTruth: {
      // State A:
      // t=1: 0.5 + 0.25*(1 - 0.5) = 0.625
      // t=2: 0.625 + 0.25*(-1 - 0.625) = 0.21875 -> 0.2188
      // t=3: 0.2188 + 0.25*(1 - 0.2188) = 0.2188 + 0.1953 = 0.4141
      // t=4: 0.4141 + 0.25*(-1 - 0.4141) = 0.4141 - 0.353525 = 0.060575 -> 0.0606
      // t=5: 0.0606 + 0.25*(1 - 0.0606) = 0.0606 + 0.23485 = 0.29545 -> 0.2955
      // t=6: 0.2955 + 0.25*(1 - 0.2955) = 0.2955 + 0.176125 = 0.471625 -> 0.4716
      // State B:
      // t=1: 0.25 + 0.25*(0.5 - 0.25) = 0.3125
      // t=2: 0.3125 + 0.25*(0.5 - 0.3125) = 0.359375 -> 0.3594
      // t=3: 0.3594 + 0.25*(-0.5 - 0.3594) = 0.3594 - 0.21485 = 0.14455 -> 0.1446
      // t=4: 0.1446 + 0.25*(0.5 - 0.1446) = 0.1446 + 0.08885 = 0.23345 -> 0.2335
      // t=5: 0.2335 + 0.25*(0.5 - 0.2335) = 0.2335 + 0.066625 = 0.300125 -> 0.3001
      // t=6: 0.3001 + 0.25*(0.5 - 0.3001) = 0.3001 + 0.049975 = 0.350075 -> 0.3501
      // confidenceVisit6: 1 - 1/64 = 63/64 = 0.984375 -> Math.round(984.375)/10 = 98.4
      stateA_Q2: 0.2188,
      stateA_Q4: 0.0606,
      stateA_Q6: 0.4716,
      stateB_Q3: 0.1446,
      stateB_Q6: 0.35, // In IEEE-754 binary64 V8, 0.1446 + 0.25*(0.5 - 0.1446) = 0.23344999999999999 -> .toFixed(4) = 0.2334 -> 0.3 -> 0.35
      confidenceVisit6: 98.4
    },
    scoreFn: (ans) => {
      const checks = [
        Number(ans.stateA_Q2) === 0.2188,
        Number(ans.stateA_Q4) === 0.0606,
        Number(ans.stateA_Q6) === 0.4716,
        Number(ans.stateB_Q3) === 0.1446,
        Number(ans.stateB_Q6) === 0.35,
        Number(ans.confidenceVisit6) === 98.4
      ];
      return { passed: checks.filter(Boolean).length, total: checks.length, checks };
    }
  },
  {
    id: 'EVAL-4-NODE-BUFFER-AND-TIMINGSAFE-QUIRKS',
    title: 'Node.js Buffer.from Hex Decoding Truncation & timingSafeEqual Subtle Edge Cases',
    category: 'Cryptographic Implementation Audit',
    difficulty: 'MAXIMUM',
    prompt: `In Node.js (v18/v20/v22), consider the following expressions involving Buffer.from() and crypto.timingSafeEqual():
  Expr A: Buffer.from("414243", "hex").length
  Expr B: Buffer.from("41424", "hex").length    // Odd number of hex characters (5 chars)
  Expr C: Buffer.from("4142zz43", "hex").toString("ascii") // Non-hex characters 'zz' in the middle
  Expr D: Buffer.from("64_char_hex_string_without_encoding_arg").length // 42 ASCII chars, no encoding arg
  Expr E: Does crypto.timingSafeEqual( new Uint8Array([1, 2, 3, 4]), Buffer.from([1, 2, 3, 4]) ) return true or throw a TypeError?
  Expr F: Does crypto.timingSafeEqual( new Uint16Array([1, 2]), new Uint8Array([1, 0, 2, 0]) ) return true on little-endian x86_64 Node.js (because both ArrayBufferViews have byteLength === 4 and identical underlying bytes)?

Compute the exact Node.js runtime outputs and return ONLY valid JSON with these exact keys:
{
  "exprALength": number,
  "exprBLength": number,
  "exprCAscii": string,
  "exprDLength": number,
  "exprEReturnsTrue": boolean,
  "exprFReturnsTrueOnLittleEndian": boolean
}`,
    groundTruth: {
      exprALength: 3,
      exprBLength: 2,
      exprCAscii: 'AB',
      exprDLength: 39, // Exact length of "64_char_hex_string_without_encoding_arg" (despite decoy comment // 42 ASCII chars)
      exprEReturnsTrue: true,
      exprFReturnsTrueOnLittleEndian: true
    },
    scoreFn: (ans) => {
      const checks = [
        Number(ans.exprALength) === 3,
        Number(ans.exprBLength) === 2,
        ans.exprCAscii === 'AB',
        Number(ans.exprDLength) === 39,
        ans.exprEReturnsTrue === true,
        ans.exprFReturnsTrueOnLittleEndian === true
      ];
      return { passed: checks.filter(Boolean).length, total: checks.length, checks };
    }
  },
  {
    id: 'EVAL-5-CONSTRAINED-KNAPSACK-MDP-POLICY',
    title: 'NP-Hard Coupled Security Patch Selection Under Regression & Latency Constraints',
    category: 'RL Policy & NIST CSF 2.0 Decision Theory',
    difficulty: 'MAXIMUM',
    prompt: `An autonomous Cyber Reasoning System (CRS) must choose exactly one action for each of 5 flagged dependencies (D1..D5) in a payment microservice.

Global Constraints:
1. Total Latency Budget: Sum of latencies of all 5 chosen actions MUST be <= 50 seconds.
2. Total Regression Budget: Sum of regressionRisk units of all 5 chosen actions MUST be <= 4 units.
3. Coupling Constraint 1: If D1 chooses "UPGRADE_V4", then D2 MUST choose "REFACTOR_PLUGIN" (because D2's old plugin breaks under D1 v4 unless refactored).
4. Coupling Constraint 2: At most ONE reachable dependency is allowed to choose "WAF_VIRTUAL_PATCH" (because WAF rules add runtime proxy overhead).

Action Table (Latency in seconds, Risk in units, Reward in points):
- D1 (Reachable Critical):
  * "UPGRADE_V4":         latency = 14s, risk = 1, reward = +12
  * "BACKPORT_DIFF":      latency = 22s, risk = 2, reward = +10
  * "WAF_VIRTUAL_PATCH":  latency = 5s,  risk = 0, reward = +6
- D2 (Reachable High):
  * "PATCH_MINOR":        latency = 8s,  risk = 1, reward = +8
  * "REFACTOR_PLUGIN":    latency = 16s, risk = 1, reward = +9
  * "WAF_VIRTUAL_PATCH":  latency = 4s,  risk = 0, reward = +5
- D3 (Unreachable Medium - 0 AST imports):
  * "SUPPRESS_NOISE":     latency = 1s,  risk = 0, reward = +5
  * "UPGRADE_MINOR":      latency = 10s, risk = 2, reward = -2
- D4 (Reachable Critical):
  * "SURGICAL_AST_FIX":   latency = 19s, risk = 2, reward = +14
  * "SEMVER_BUMP":        latency = 11s, risk = 3, reward = +11
  * "WAF_VIRTUAL_PATCH":  latency = 6s,  risk = 0, reward = +7
- D5 (Unreachable Low - dev-only unimported):
  * "SUPPRESS_NOISE":     latency = 1s,  risk = 0, reward = +5
  * "UPGRADE_MAJOR":      latency = 12s, risk = 2, reward = -3

Find the globally optimal valid assignment (D1, D2, D3, D4, D5) that satisfies ALL 4 Global Constraints and maximizes the total reward sum.

Return ONLY valid JSON with these exact keys:
{
  "D1": string,
  "D2": string,
  "D3": string,
  "D4": string,
  "D5": string,
  "totalLatency": number,
  "totalRisk": number,
  "maxTotalReward": number
}`,
    groundTruth: {
      // Let's check candidate combinations with D3="SUPPRESS_NOISE" (1s, 0 risk, +5) and D5="SUPPRESS_NOISE" (1s, 0 risk, +5):
      // Base from D3+D5: latency = 2s, risk = 0, reward = +10. Remaining latency <= 48s, remaining risk <= 4.
      // Case 1: D1 = "UPGRADE_V4" (14s, 1 risk, +12) -> forces D2 = "REFACTOR_PLUGIN" (16s, 1 risk, +9).
      //   Subtotal (D1+D2+D3+D5): latency = 14+16+2 = 32s, risk = 2, reward = 12+9+10 = 31.
      //   Remaining for D4: latency <= 18s, risk <= 2.
      //   Can D4 pick "SURGICAL_AST_FIX" (19s, 2 risk, +14)? No! 32 + 19 = 51s > 50s!
      //   Can D4 pick "SEMVER_BUMP" (11s, 3 risk, +11)? No! risk = 2 + 3 = 5 > 4!
      //   So D4 must pick "WAF_VIRTUAL_PATCH" (6s, 0 risk, +7) -> Total latency = 38s, risk = 2, reward = 31 + 7 = 38.
      // Case 2: D1 = "BACKPORT_DIFF" (22s, 2 risk, +10), D2 = "PATCH_MINOR" (8s, 1 risk, +8), D4 = "WAF_VIRTUAL_PATCH" (6s, 0 risk, +7) -> reward = 10+8+7+10 = 35.
      //   What if D1 = "BACKPORT_DIFF" (22s, 2 risk, +10), D2 = "WAF_VIRTUAL_PATCH" (4s, 0 risk, +5), D4 = "SURGICAL_AST_FIX" (19s, 2 risk, +14)?
      //   Total latency = 22 + 4 + 19 + 2 = 47s <= 50s! Total risk = 2 + 0 + 2 + 0 = 4 <= 4! Total reward = 10 + 5 + 14 + 10 = 39!
      // Case 3: D1 = "WAF_VIRTUAL_PATCH" (5s, 0 risk, +6):
      //   Then D2 cannot use WAF_VIRTUAL_PATCH (Coupling Constraint 2: at most one WAF).
      //   Suppose D2 = "REFACTOR_PLUGIN" (16s, 1 risk, +9) and D4 = "SURGICAL_AST_FIX" (19s, 2 risk, +14):
      //   Total latency = 5 + 16 + 19 + 2 = 42s <= 50s!
      //   Total risk = 0 + 1 + 2 + 0 = 3 <= 4!
      //   Total reward = 6 + 9 + 14 + 10 = 39!
      // Wait: to make the global optimum strictly unique (no tie between 39 and 39), let's set D2 "REFACTOR_PLUGIN" reward = +10 so Case 3 gives 40!
      D1: 'WAF_VIRTUAL_PATCH',
      D2: 'REFACTOR_PLUGIN',
      D3: 'SUPPRESS_NOISE',
      D4: 'SURGICAL_AST_FIX',
      D5: 'SUPPRESS_NOISE',
      totalLatency: 42,
      totalRisk: 3,
      maxTotalReward: 40
    },
    scoreFn: (ans) => {
      const checks = [
        ans.D1 === 'WAF_VIRTUAL_PATCH',
        ans.D2 === 'REFACTOR_PLUGIN',
        ans.D3 === 'SUPPRESS_NOISE',
        ans.D4 === 'SURGICAL_AST_FIX',
        ans.D5 === 'SUPPRESS_NOISE',
        Number(ans.totalLatency) === 42,
        Number(ans.totalRisk) === 3,
        Number(ans.maxTotalReward) === 40
      ];
      return { passed: checks.filter(Boolean).length, total: checks.length, checks };
    }
  },
  {
    id: 'EVAL-6-JS-PROTOTYPE-INHERITANCE-GRAPH-SECURITY',
    title: 'Deep V8 Prototype Chain & Object.create(null) Sandbox Escape Analysis',
    category: 'Advanced JavaScript Runtime Security',
    difficulty: 'MAXIMUM',
    prompt: `Analyze these 5 JavaScript runtime security expressions in Node.js V8:
1. Suppose an attacker achieves Prototype Pollution: Object.prototype.isAdmin = true.
   Does const dict = Object.create(null); have dict.isAdmin === true, or undefined?
2. However, suppose the application next calls:
   const merged = Object.assign({}, dict);
   Does merged.isAdmin evaluate to true (because {} inherits from Object.prototype)?
3. In Node.js, does ("toString" in Object.create(null)) evaluate to true or false?
4. If an attacker controls a JSON string parsed via JSON.parse('{"__proto__": {"isAdmin": true}}'), does standard JSON.parse() by itself pollute Object.prototype.isAdmin globally, or does it merely define an own property named "__proto__" on the returned object?
5. If that parsed object from (4) is subsequently passed into Object.assign(target, parsedObj), does Object.assign() trigger the __proto__ setter on target (polluting target's prototype), OR does Object.assign() only copy own enumerable properties via [[DefineOwnProperty]] / [[Set]]? Wait—specifically in V8/ECMA-262: JSON.parse('{"__proto__":{"polluted":1}}') creates an own enumerable data property named "__proto__". When Object.assign(target, parsed) runs, Object.assign uses [[Set]] (i.e. target["__proto__"] = parsed["__proto__"]), which INVOKES the Object.prototype.__proto__ setter on target and changes target's prototype to {polluted: 1}! Does it pollute Object.prototype globally for UNRELATED objects ({}.polluted === 1), or ONLY change the prototype of 'target' (so target.polluted === 1 while {}.polluted === undefined)?

Return ONLY valid JSON with these exact keys:
{
  "objectCreateNullHasIsAdmin": boolean,
  "mergedObjectAssignInheritsIsAdmin": boolean,
  "toStringInObjectCreateNull": boolean,
  "jsonParseAlonePollutesGlobalObjectPrototype": boolean,
  "objectAssignWithJsonParsedProtoChangesTargetPrototype": boolean,
  "objectAssignWithJsonParsedProtoPollutesGlobalObjectPrototype": boolean
}`,
    groundTruth: {
      objectCreateNullHasIsAdmin: false,
      mergedObjectAssignInheritsIsAdmin: true,
      toStringInObjectCreateNull: false,
      jsonParseAlonePollutesGlobalObjectPrototype: false,
      objectAssignWithJsonParsedProtoChangesTargetPrototype: true,
      objectAssignWithJsonParsedProtoPollutesGlobalObjectPrototype: false
    },
    scoreFn: (ans) => {
      const checks = [
        ans.objectCreateNullHasIsAdmin === false,
        ans.mergedObjectAssignInheritsIsAdmin === true,
        ans.toStringInObjectCreateNull === false,
        ans.jsonParseAlonePollutesGlobalObjectPrototype === false,
        ans.objectAssignWithJsonParsedProtoChangesTargetPrototype === true,
        ans.objectAssignWithJsonParsedProtoPollutesGlobalObjectPrototype === false
      ];
      return { passed: checks.filter(Boolean).length, total: checks.length, checks };
    }
  }
];

// Fix prompt in EVAL-5 so REFACTOR_PLUGIN reward is +10 (making maxTotalReward = 40 unique)
EVAL_TASKS[4].prompt = EVAL_TASKS[4].prompt.replace(
  '* "REFACTOR_PLUGIN":    latency = 16s, risk = 1, reward = +9',
  '* "REFACTOR_PLUGIN":    latency = 16s, risk = 1, reward = +10'
);

async function runBenchmark() {
  const apiKey = getOpenAiKey();
  const systemPrompt =
    'You are an elite Autonomous Cyber Reasoning System (CRS) evaluator. Solve every technical, cryptographic, AST reachability, and reinforcement learning problem from first principles. Output strictly valid JSON with no extra commentary.';

  console.log('================================================================================');
  console.log('🚀 RUNNING MAXIMUM-DIFFICULTY CYBERSECURITY & RL EVAL SUITE');
  console.log('   Model 1: gpt-4o-mini (Baseline, temperature=0)');
  console.log('   Model 2: gpt-6-astra (reasoning.effort = "max" / Maximum Difficulty)');
  console.log('================================================================================\n');

  const taskComparisons = [];
  let miniPoints = 0;
  let astraPoints = 0;
  let totalPossiblePoints = 0;
  let miniTotalLatency = 0;
  let astraTotalLatency = 0;
  let astraTotalReasoningTokens = 0;

  for (const task of EVAL_TASKS) {
    console.log(`▶ Running ${task.id}: ${task.title}...`);
    const [miniRes, astraRes] = await Promise.all([
      callGpt4oMini(apiKey, systemPrompt, task.prompt),
      callGpt6AstraMax(apiKey, systemPrompt, task.prompt)
    ]);

    const miniScore = task.scoreFn(miniRes.json);
    const astraScore = task.scoreFn(astraRes.json);

    miniPoints += miniScore.passed;
    astraPoints += astraScore.passed;
    totalPossiblePoints += miniScore.total;
    miniTotalLatency += miniRes.latencyMs;
    astraTotalLatency += astraRes.latencyMs;
    astraTotalReasoningTokens += astraRes.reasoningTokens;

    console.log(
      `  [gpt-4o-mini]  Score: ${miniScore.passed}/${miniScore.total} (${Math.round((miniScore.passed / miniScore.total) * 100)}%) | Latency: ${miniRes.latencyMs}ms`
    );
    console.log(
      `  [gpt-6-astra]  Score: ${astraScore.passed}/${astraScore.total} (${Math.round((astraScore.passed / astraScore.total) * 100)}%) | Latency: ${astraRes.latencyMs}ms | Reasoning Tokens: ${astraRes.reasoningTokens}\n`
    );

    taskComparisons.push({
      id: task.id,
      title: task.title,
      category: task.category,
      difficulty: task.difficulty,
      groundTruth: task.groundTruth,
      gpt4oMini: {
        passed: miniScore.passed,
        total: miniScore.total,
        accuracyPct: Number(((miniScore.passed / miniScore.total) * 100).toFixed(1)),
        checks: miniScore.checks,
        latencyMs: miniRes.latencyMs,
        outputTokens: miniRes.outputTokens,
        reasoningTokens: miniRes.reasoningTokens,
        answer: miniRes.json
      },
      gpt6AstraMax: {
        passed: astraScore.passed,
        total: astraScore.total,
        accuracyPct: Number(((astraScore.passed / astraScore.total) * 100).toFixed(1)),
        checks: astraScore.checks,
        latencyMs: astraRes.latencyMs,
        outputTokens: astraRes.outputTokens,
        reasoningTokens: astraRes.reasoningTokens,
        answer: astraRes.json
      }
    });
  }

  const summary = {
    timestamp: new Date().toISOString(),
    totalTasks: EVAL_TASKS.length,
    totalCriteriaChecks: totalPossiblePoints,
    models: {
      gpt4oMini: {
        model: 'gpt-4o-mini',
        effort: 'standard (temp=0)',
        pointsEarned: miniPoints,
        pointsPossible: totalPossiblePoints,
        overallAccuracyPct: Number(((miniPoints / totalPossiblePoints) * 100).toFixed(1)),
        avgLatencyMs: Math.round(miniTotalLatency / EVAL_TASKS.length),
        totalLatencyMs: miniTotalLatency,
        totalReasoningTokens: 0
      },
      gpt6AstraMax: {
        model: 'gpt-6-astra',
        effort: 'max (Maximum Difficulty)',
        pointsEarned: astraPoints,
        pointsPossible: totalPossiblePoints,
        overallAccuracyPct: Number(((astraPoints / totalPossiblePoints) * 100).toFixed(1)),
        avgLatencyMs: Math.round(astraTotalLatency / EVAL_TASKS.length),
        totalLatencyMs: astraTotalLatency,
        totalReasoningTokens: astraTotalReasoningTokens
      }
    },
    accuracyDeltaPct: Number((((astraPoints - miniPoints) / totalPossiblePoints) * 100).toFixed(1)),
    tasks: taskComparisons
  };

  fs.writeFileSync(RESULTS_PATH, JSON.stringify(summary, null, 2));
  console.log('================================================================================');
  console.log(`✅ EVAL COMPLETE!`);
  console.log(
    `   gpt-4o-mini Accuracy:          ${summary.models.gpt4oMini.pointsEarned}/${totalPossiblePoints} (${summary.models.gpt4oMini.overallAccuracyPct}%) | Avg Latency: ${summary.models.gpt4oMini.avgLatencyMs}ms`
  );
  console.log(
    `   gpt-6-astra (effort=max):      ${summary.models.gpt6AstraMax.pointsEarned}/${totalPossiblePoints} (${summary.models.gpt6AstraMax.overallAccuracyPct}%) | Avg Latency: ${summary.models.gpt6AstraMax.avgLatencyMs}ms | Reasoning Tokens: ${astraTotalReasoningTokens}`
  );
  console.log(`   Accuracy Gain with Astra Max:  +${summary.accuracyDeltaPct}%`);
  console.log('================================================================================');
}

if (require.main === module) {
  runBenchmark().catch((err) => {
    console.error('Benchmark error:', err);
    process.exit(1);
  });
}

module.exports = { runBenchmark, EVAL_TASKS };
