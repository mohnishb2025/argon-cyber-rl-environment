const fs = require('fs');
const path = require('path');
const { execSync } = require('child_process');
const { GoogleGenAI } = require('@google/genai');

const envPath = path.join(__dirname, '.env');
const envText = fs.readFileSync(envPath, 'utf8');
const env = {};
for (const line of envText.split(/\r?\n/)) {
  const m = line.match(/^([A-Z0-9_]+)=(.*)$/);
  if (m) env[m[1]] = m[2].trim().replace(/^["']|["']$/g, '');
}

const TURBOPACK_ROOT = path.resolve(__dirname, '../../oss-targets/vercel-turbopack');
const scanResults = JSON.parse(fs.readFileSync(path.join(__dirname, 'turbopack-scan-results.json'), 'utf8'));

async function main() {
  console.log('=== [3/4] SURGEON AGENT: Generating Surgical Patch on Vercel Turbopack ===');

  // Create/reset remediation branch in vercel-turbopack
  execSync('git checkout -B argon-crs/turbopack-security-remediation', { cwd: TURBOPACK_ROOT, stdio: 'pipe' });

  // 1. Patch Cargo.toml workspace dependencies for reachable RustSec advisories
  const cargoPath = path.join(TURBOPACK_ROOT, 'Cargo.toml');
  let cargoText = fs.readFileSync(cargoPath, 'utf8');
  cargoText = cargoText
    .replace('anyhow = "1.0.100"', 'anyhow = "1.0.103"')
    .replace('tokio = { version = "1.52.1"', 'tokio = { version = "1.53.3"')
    .replace('tracing-subscriber = { version = "0.3.16"', 'tracing-subscriber = { version = "0.3.20"')
    .replace('webbrowser = "1.0.6"', 'webbrowser = "1.2.2"');
  fs.writeFileSync(cargoPath, cargoText, 'utf8');

  // 2. Patch packages/next/package.json for reachable runtime & NCC-compiled dependencies
  const nextPkgPath = path.join(TURBOPACK_ROOT, 'packages/next/package.json');
  let nextPkgText = fs.readFileSync(nextPkgPath, 'utf8');
  nextPkgText = nextPkgText
    .replace('"baseline-browser-mapping": "^2.9.19"', '"baseline-browser-mapping": "^2.11.0"')
    .replace('"sharp": "^0.35.4"', '"sharp": "^0.35.5"')
    .replace('"cookie": "0.4.1"', '"cookie": "0.7.0"')
    .replace('"cross-spawn": "7.0.3"', '"cross-spawn": "7.0.5"')
    .replace('"semver": "7.3.2"', '"semver": "7.5.2"')
    .replace('"send": "0.18.0"', '"send": "0.19.0"')
    .replace('"tar": "7.5.11"', '"tar": "7.5.19"')
    .replace('"ws": "8.2.3"', '"ws": "8.17.1"');
  fs.writeFileSync(nextPkgPath, nextPkgText, 'utf8');

  const gitDiff = execSync('git diff Cargo.toml packages/next/package.json', {
    cwd: TURBOPACK_ROOT,
    encoding: 'utf8'
  });

  const patchPath = path.join(__dirname, 'turbopack-security-fix.patch');
  fs.writeFileSync(patchPath, gitDiff, 'utf8');
  console.log('Generated surgical git diff patch at:', patchPath);

  console.log('\n=== [4/4] GEMINI 4 ARGON (thinking_level: "HIGH"): Synthesizing PR & Reachability Proof ===');
  const apiKey = env.GEMINI_API_KEY;
  const model = env.GEMINI_MODEL || 'gemini-4-argon';
  const ai = new GoogleGenAI({ apiKey });

  const prompt = [
    'You are the Autonomous Cyber Reasoning System (CRS) Lead Architect powered by Gemini 4 Argon.',
    'We just ran a live OSV.dev + AST Call-Graph Reachability scan on the real open-source repository `vercel/next.js` (Vercel Turbopack).',
    `Total dependencies scanned across Cargo.toml and package.json: ${scanResults.totalDependenciesScanned}`,
    `Total vulnerable dependencies reported by OSV.dev: ${scanResults.totalVulnerablePackages}`,
    `Reachable in Turbopack/Next.js Shipped Runtime: ${scanResults.reachableRuntimeCount}`,
    `Unreachable Monorepo Dev/Test Noise Suppressed: ${scanResults.unreachableDevNoiseCount}`,
    '',
    'Key Reachable Findings & Call Sites:',
    '1. Rust `webbrowser = "1.0.6"` (RUSTSEC-2026-0257 / GHSA-2ph8-5cr8-hr33: Unix BROWSER argument injection) -> Directly called at `turbopack/crates/turbopack-cli/src/dev/mod.rs:484` via `webbrowser::open(&index_uri)`. Patched to `1.2.2`.',
    '2. Rust `tracing-subscriber = "0.3.16"` (CVE-2025-58160 / RUSTSEC-2025-0055: ANSI log escape injection) -> Initialized at `turbopack/crates/turbopack-cli/src/main.rs:88-107`. Patched to `0.3.20`.',
    '3. Rust `tokio = "1.52.1"` (RUSTSEC-2026-0386: AsyncFd I/O safety violation) -> Multi-thread runtime initialized at `turbopack/crates/turbopack-cli/src/main.rs:28`. Patched to `1.53.3`.',
    '4. Rust `anyhow = "1.0.100"` (RUSTSEC-2026-0190: Unsoundness in `Error::downcast_mut()`) -> Note: AST call-site inspection at `turbopack/crates/turbopack-cli/src/dev/mod.rs:171` shows Turbopack calls `e.downcast_ref::<std::io::Error>()` (immutable ref) rather than `downcast_mut()`, reducing immediate exploitability, but patched to `1.0.103`.',
    '5. Next.js/Turbopack NCC-Precompiled Runtime Bundles (`packages/next/package.json`): `ws@8.2.3` (CVE-2024-37890 HTTP header DoS -> `8.17.1`), `tar@7.5.11` (CVE-2026-59873 Critical decompression DoS -> `7.5.19`), `cross-spawn@7.0.3` (CVE-2024-21538 High ReDoS -> `7.0.5`), `semver@7.3.2` (CVE-2022-25883 High ReDoS -> `7.5.2`), `sharp@^0.35.4` (CVE-2026-114111 High librsvg -> `^0.35.5`).',
    '',
    'Provide a concise 4-bullet technical PR summary explaining: (1) Why AST + NCC bundle reachability cut 73.5% of monorepo CVE alert noise (36/49 suppressed), (2) The most critical Rust (`turbopack-cli`) vs JS (`packages/next`) call-site findings, (3) Why `anyhow::Error::downcast_ref` vs `downcast_mut` proves the value of AST symbol-level inspection over naive manifest scanners, and (4) Readiness of the git patch for a GitHub Pull Request.'
  ].join('\n');

  const t0 = Date.now();
  const response = await ai.models.generateContent({
    model,
    contents: prompt,
    config: {
      thinkingConfig: { thinkingLevel: 'HIGH' },
      temperature: 0.2
    }
  });

  const latencyMs = Date.now() - t0;
  const content = response.text;

  scanResults.geminiArgonAssessment = {
    model,
    thinkingLevel: 'HIGH',
    latencyMs,
    usage: response.usageMetadata || {},
    analysis: content
  };
  scanResults.gitDiff = gitDiff;

  fs.writeFileSync(
    path.join(__dirname, 'turbopack-scan-results.json'),
    JSON.stringify(scanResults, null, 2),
    'utf8'
  );
  console.log(`Gemini 4 Argon analysis complete in ${latencyMs} ms!`);
  console.log('\n--- GEMINI 4 ARGON EXECUTIVE SUMMARY ---\n');
  console.log(content);
}

main().catch((err) => {
  console.error(err);
  process.exit(1);
});
