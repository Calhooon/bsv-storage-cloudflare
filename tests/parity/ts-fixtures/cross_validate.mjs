// cross_validate.mjs — Layer 3 cross-validator oracle shim.
//
// Reads JSON cases from stdin, for each case synthesizes a minimal
// transaction whose single output carries the supplied
// `locking_script_hex`, serializes it to BEEF, then runs the REAL
// TS `UHRPTopicManager.identifyAdmissibleOutputs(beef, [])` from
// `@bsv/overlay 0.6.0` + `@bsv/sdk 1.10.1` (the exact versions
// nanostore.babbage.systems runs) and reports whether the output
// was admitted.
//
// The Rust integration test at
// `~/bsv/rust-overlay/crates/overlay-discovery/tests/cross_validator.rs`
// invokes this shim once with the full corpus; verdicts are diffed
// against `UHRPTopicManager::validate_uhrp_output` in Rust. Any
// divergence is an admission-rule drift bug.
//
// Stdin schema:
//   { "cases": [
//       { "label": "...", "locking_script_hex": "<hex>", "satoshis": 1 },
//       ...
//   ] }
//
// Stdout schema:
//   { "verdicts": [
//       { "label": "...", "admitted": true|false, "reason": "...",
//         "output_count": <number of admitted outputs> },
//       ...
//   ] }
//
// UHRPTopicManager.identifyAdmissibleOutputs catches all errors and
// returns `{outputsToAdmit:[], coinsToRetain:[]}` on failure. To surface
// a reason, we monkey-patch `console.error` during each call and capture
// whatever the TS logs via `console.error('Error with output', i, error)`.

import {
  Transaction,
  LockingScript,
  UnlockingScript,
} from '@bsv/sdk';
import UHRPTopicManager from './tm_uhrp_local.mjs';

async function readStdin() {
  return new Promise((resolve, reject) => {
    const chunks = [];
    process.stdin.on('data', (c) => chunks.push(c));
    process.stdin.on('end', () => resolve(Buffer.concat(chunks).toString('utf8')));
    process.stdin.on('error', reject);
  });
}

/**
 * Build a synthetic Transaction whose sole output is the one under test.
 *
 * A Bitcoin tx needs >=1 input for BEEF to make sense; we attach one with
 * a null source-txid and a trivial source-transaction so `toBEEF(true)`
 * can serialize. UHRPTopicManager does not inspect inputs (only
 * `tx.outputs.entries()`), so the synthetic input is inert.
 */
function buildSyntheticTransaction(lockingScriptHex, satoshis) {
  // Minimal source tx: 1-output placeholder so Transaction.fromBEEF
  // doesn't choke. The source tx itself has no inputs + a P2PKH-style
  // dummy output. We won't actually verify scripts — the topic manager
  // only inspects output shapes.
  const sourceTx = new Transaction(
    1,
    [],
    [{ satoshis: 1000, lockingScript: LockingScript.fromHex('51') }], // OP_1
    0,
  );

  const input = {
    sourceTransaction: sourceTx,
    sourceTXID: sourceTx.id('hex'),
    sourceOutputIndex: 0,
    unlockingScript: UnlockingScript.fromHex(''),
    sequence: 0xffffffff,
  };

  const output = {
    satoshis,
    lockingScript: LockingScript.fromHex(lockingScriptHex),
  };

  return new Transaction(1, [input], [output], 0);
}

async function validateCase(mgr, c) {
  // UHRPTopicManager's `console.error('Error with output', i, error)`
  // is our only reason signal. Capture it per-case.
  const capturedErrors = [];
  const origError = console.error;
  const origLog = console.log;
  console.error = (...args) => {
    try {
      capturedErrors.push(
        args
          .map((a) =>
            a instanceof Error ? (a.message || a.toString()) : (typeof a === 'string' ? a : JSON.stringify(a)),
          )
          .join(' '),
      );
    } catch {
      capturedErrors.push('<unformattable>');
    }
  };
  console.log = () => {}; // suppress 'previous UTXOs' line

  let admitted = false;
  let outputCount = 0;
  let reason = '';

  try {
    const tx = buildSyntheticTransaction(c.locking_script_hex, c.satoshis ?? 1);
    const beef = tx.toBEEF(true); // allowPartial — no ancestors required
    const result = await mgr.identifyAdmissibleOutputs(beef, []);
    outputCount = Array.isArray(result.outputsToAdmit) ? result.outputsToAdmit.length : 0;
    admitted = outputCount > 0;
    if (!admitted && capturedErrors.length > 0) {
      reason = capturedErrors.join(' | ');
    }
  } catch (e) {
    // Should never happen — UHRPTopicManager swallows its own errors.
    // But if BEEF construction blows up, surface that.
    reason = `shim_error: ${e && e.message ? e.message : String(e)}`;
    admitted = false;
  } finally {
    console.error = origError;
    console.log = origLog;
  }

  return {
    label: c.label,
    admitted,
    reason,
    output_count: outputCount,
  };
}

async function main() {
  const input = await readStdin();
  if (!input.trim()) {
    process.stderr.write('cross_validate.mjs: empty stdin\n');
    process.exit(2);
  }
  let parsed;
  try {
    parsed = JSON.parse(input);
  } catch (e) {
    process.stderr.write(`cross_validate.mjs: bad JSON: ${e.message}\n`);
    process.exit(2);
  }

  const cases = Array.isArray(parsed.cases) ? parsed.cases : [];
  const mgr = new UHRPTopicManager();
  const verdicts = [];
  for (const c of cases) {
    verdicts.push(await validateCase(mgr, c));
  }

  process.stdout.write(JSON.stringify({ verdicts }, null, 2) + '\n');
}

main().catch((e) => {
  process.stderr.write(`cross_validate.mjs: fatal: ${e && e.stack ? e.stack : e}\n`);
  process.exit(1);
});
