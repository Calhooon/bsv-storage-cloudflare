// generate.mjs — produces canonical byte fixtures from @bsv/sdk 1.10.1
// (the exact version nanostore.babbage.systems runs).
//
// OUTPUT: JSON files written to ../fixtures/parity/*.json, each with
// a _meta header logging the ts-sdk version + timestamp + generator script
// + deterministic seed used. Rust tests load these and assert
// byte-equality against our implementations.
//
// The fixtures are CANONICAL ORACLE OUTPUT — if our Rust code disagrees,
// OUR code is wrong. Regenerate only when the pinned TS version bumps.

import {
  PrivateKey,
  PublicKey,
  PushDrop,
  KeyDeriver,
  ProtoWallet,
  Utils,
  Transaction,
  TransactionSignature,
  LockingScript,
  UnlockingScript,
  P2PKH,
  Beef,
  Hash,
  OP,
} from '@bsv/sdk';
import { writeFileSync, mkdirSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';
import { readFileSync } from 'node:fs';

const HERE = dirname(fileURLToPath(import.meta.url));
const FIXTURES = join(HERE, '..', 'fixtures', 'parity');
mkdirSync(FIXTURES, { recursive: true });

const PKG = JSON.parse(readFileSync(join(HERE, 'node_modules', '@bsv', 'sdk', 'package.json'), 'utf8'));
const SDK_VERSION = PKG.version;

function meta(seed, note) {
  return {
    _meta: {
      ts_sdk_version: SDK_VERSION,
      generated_at: new Date().toISOString(),
      generator_script: 'tests/parity/ts-fixtures/generate.mjs',
      seed,
      note,
    },
  };
}

function writeFixture(name, data) {
  const path = join(FIXTURES, `${name}.json`);
  writeFileSync(path, JSON.stringify(data, null, 2) + '\n');
  console.log(`  wrote ${name}.json`);
}

// Deterministic admin key — same root across all fixtures so Rust tests
// can cross-reference. Value is the standard BIP-32 test scalar (1).
const ADMIN_PRIV_HEX = '0000000000000000000000000000000000000000000000000000000000000001';
const admin = PrivateKey.fromHex(ADMIN_PRIV_HEX);
const adminPubCompressedHex = admin.toPublicKey().toString();
const adminIdentityBytes = Utils.toArray(adminPubCompressedHex, 'hex');

// =============================================================================
// 1. UHRP PushDrop fixtures — 5 diverse inputs
// =============================================================================

async function genUhrpPushDrops() {
  console.log('UHRP PushDrop fixtures…');
  const wallet = new ProtoWallet(admin);
  const pushdrop = new PushDrop(wallet);
  const protocolID = [2, 'uhrp advertisement'];
  const keyID = '1';
  const counterparty = 'anyone';

  const cases = [
    {
      name: 'uhrp_baseline_small_cdn_url',
      url: 'https://pub-abc.r2.dev/cdn/short',
      hash: new Uint8Array(32).fill(0xAA),
      expiry_time: 1800000000,
      content_length: 42,
    },
    {
      name: 'uhrp_url_at_253_byte_varint_boundary',
      url: 'https://pub-abc.r2.dev/cdn/' + 'x'.repeat(226), // total 253 bytes
      hash: new Uint8Array(32).fill(0xBB),
      expiry_time: 1900000000,
      content_length: 1024,
    },
    {
      name: 'uhrp_url_over_varint_u16_boundary',
      url: 'https://pub-abc.r2.dev/cdn/' + 'y'.repeat(500),
      hash: new Uint8Array(32).fill(0xCC),
      expiry_time: 2000000000,
      content_length: 4_000_000_000, // > u32 max/2 — exercises varint u64 path
    },
    {
      name: 'uhrp_zero_hash_edge',
      url: 'https://pub-abc.r2.dev/cdn/zerohash',
      hash: new Uint8Array(32), // all zeros
      expiry_time: 1800000001,
      content_length: 1,
    },
    {
      name: 'uhrp_past_expiry_ts_parity',
      // Past-expiry is ADMITTED per TS spec (see tm_uhrp relax, 2026-04-21).
      url: 'https://pub-abc.r2.dev/cdn/expired',
      hash: new Uint8Array(32).fill(0x01),
      expiry_time: 1700000000, // 2023-11 — well in the past
      content_length: 100,
    },
  ];

  for (const c of cases) {
    const hashArr = Array.from(c.hash);
    const urlBytes = Utils.toArray(c.url, 'utf8');
    const expiryW = new Utils.Writer();
    expiryW.writeVarIntNum(c.expiry_time);
    const expiryBytes = expiryW.toArray();
    const lenW = new Utils.Writer();
    lenW.writeVarIntNum(c.content_length);
    const lenBytes = lenW.toArray();

    const lockingScript = await pushdrop.lock(
      [adminIdentityBytes, hashArr, urlBytes, expiryBytes, lenBytes],
      protocolID,
      keyID,
      counterparty,
      /* forSelf */ true,
      /* includeSignature */ true,
      'before'
    );
    const scriptHex = lockingScript.toHex();

    writeFixture(c.name, {
      ...meta(c.name, 'UHRP advertisement PushDrop — protocol=[2,"uhrp advertisement"] keyID="1" counterparty="anyone" forSelf=true'),
      admin_priv_hex: ADMIN_PRIV_HEX,
      admin_pub_hex: adminPubCompressedHex,
      input: {
        url: c.url,
        hash_hex: Buffer.from(c.hash).toString('hex'),
        expiry_time: c.expiry_time,
        content_length: c.content_length,
      },
      expected: {
        locking_script_hex: scriptHex,
        script_length: scriptHex.length / 2,
      },
    });
  }
}

// =============================================================================
// 2. SHIP PushDrop fixtures
// =============================================================================

async function genShipPushDrops() {
  console.log('SHIP PushDrop fixtures…');
  const wallet = new ProtoWallet(admin);
  const pushdrop = new PushDrop(wallet);
  const protocolID = [2, 'service host interconnect'];
  const keyID = '1';
  const counterparty = 'anyone';

  const cases = [
    { name: 'ship_tm_uhrp', domain: 'https://overlay.example.com', topic: 'tm_uhrp' },
    { name: 'ship_tm_ship', domain: 'https://overlay.example.com', topic: 'tm_ship' },
    { name: 'ship_long_topic', domain: 'https://overlay.example.com', topic: 'tm_some_very_specific_descriptor_topic' },
  ];

  for (const c of cases) {
    const fields = [
      Utils.toArray('SHIP', 'utf8'),
      adminIdentityBytes,
      Utils.toArray(c.domain, 'utf8'),
      Utils.toArray(c.topic, 'utf8'),
    ];
    const lockingScript = await pushdrop.lock(
      fields, protocolID, keyID, counterparty, true, true, 'before'
    );
    writeFixture(c.name, {
      ...meta(c.name, 'SHIP advertisement PushDrop — protocol=[2,"service host interconnect"]'),
      admin_priv_hex: ADMIN_PRIV_HEX,
      input: { domain: c.domain, topic: c.topic },
      expected: { locking_script_hex: lockingScript.toHex() },
    });
  }
}

// =============================================================================
// 3. SLAP PushDrop fixtures
// =============================================================================

async function genSlapPushDrops() {
  console.log('SLAP PushDrop fixtures…');
  const wallet = new ProtoWallet(admin);
  const pushdrop = new PushDrop(wallet);
  const protocolID = [2, 'service lookup availability'];
  const keyID = '1';
  const counterparty = 'anyone';

  const cases = [
    { name: 'slap_ls_uhrp', domain: 'https://overlay.example.com', service: 'ls_uhrp' },
    { name: 'slap_ls_ship', domain: 'https://overlay.example.com', service: 'ls_ship' },
  ];

  for (const c of cases) {
    const fields = [
      Utils.toArray('SLAP', 'utf8'),
      adminIdentityBytes,
      Utils.toArray(c.domain, 'utf8'),
      Utils.toArray(c.service, 'utf8'),
    ];
    const lockingScript = await pushdrop.lock(
      fields, protocolID, keyID, counterparty, true, true, 'before'
    );
    writeFixture(c.name, {
      ...meta(c.name, 'SLAP advertisement PushDrop — protocol=[2,"service lookup availability"]'),
      admin_priv_hex: ADMIN_PRIV_HEX,
      input: { domain: c.domain, service: c.service },
      expected: { locking_script_hex: lockingScript.toHex() },
    });
  }
}

// =============================================================================
// 4. BRC-42 derived pubkey fixtures (UHRP locking key)
// =============================================================================

function genBrc42Derivations() {
  console.log('BRC-42 derivation fixtures…');
  const deriver = new KeyDeriver(admin);

  const cases = [
    {
      name: 'brc42_uhrp_anyone_locking',
      protocol: [2, 'uhrp advertisement'],
      keyID: '1',
      counterparty: 'anyone',
      forSelf: true,
    },
    {
      name: 'brc42_ship_anyone_locking',
      protocol: [2, 'service host interconnect'],
      keyID: '1',
      counterparty: 'anyone',
      forSelf: true,
    },
    {
      name: 'brc42_brc29_payment_to_admin',
      protocol: [2, '3241645161d8'],
      keyID: 'prefix1 suffix1',
      counterparty: adminPubCompressedHex, // self-send
      forSelf: false,
    },
  ];

  for (const c of cases) {
    const derived = deriver.derivePublicKey(c.protocol, c.keyID, c.counterparty, c.forSelf);
    writeFixture(c.name, {
      ...meta(c.name, 'BRC-42 child pubkey derivation'),
      admin_priv_hex: ADMIN_PRIV_HEX,
      input: {
        protocol: c.protocol,
        key_id: c.keyID,
        counterparty: c.counterparty,
        for_self: c.forSelf,
      },
      expected: {
        derived_pubkey_hex: derived.toString(),
      },
    });
  }
}

// =============================================================================
// 5. PushDrop decode + tm_uhrp-shape admit/reject transcript (legacy — kept
//    intact for existing Rust consumers; new per-case fixtures added below).
// =============================================================================

async function genAdmissionTranscripts() {
  console.log('tm_uhrp admission transcripts…');
  const wallet = new ProtoWallet(admin);
  const pushdrop = new PushDrop(wallet);
  const protocolID = [2, 'uhrp advertisement'];
  const keyID = '1';

  // Canonical VALID advert — every field correct.
  const validCase = async () => {
    const url = 'https://pub-abc.r2.dev/cdn/valid';
    const hash = Array.from(new Uint8Array(32).fill(0xAB));
    const expiry_time = 1800000000;
    const content_length = 500;

    const expiryW = new Utils.Writer();
    expiryW.writeVarIntNum(expiry_time);
    const lenW = new Utils.Writer();
    lenW.writeVarIntNum(content_length);

    const lockingScript = await pushdrop.lock(
      [adminIdentityBytes, hash, Utils.toArray(url, 'utf8'), expiryW.toArray(), lenW.toArray()],
      protocolID, keyID, 'anyone', true, true, 'before'
    );
    return {
      label: 'valid_future_expiry',
      locking_script_hex: lockingScript.toHex(),
      expected_admit: true,
      reason: 'all fields correct, https url, sig valid, linkage valid',
    };
  };

  // Past expiry — TS spec ADMITS (only rejects expiry < 1).
  const pastExpiryCase = async () => {
    const url = 'https://pub-abc.r2.dev/cdn/past';
    const hash = Array.from(new Uint8Array(32).fill(0xCD));
    const expiryW = new Utils.Writer();
    expiryW.writeVarIntNum(1700000000);
    const lenW = new Utils.Writer();
    lenW.writeVarIntNum(100);
    const lockingScript = await pushdrop.lock(
      [adminIdentityBytes, hash, Utils.toArray(url, 'utf8'), expiryW.toArray(), lenW.toArray()],
      protocolID, keyID, 'anyone', true, true, 'before'
    );
    return {
      label: 'past_expiry_still_admits',
      locking_script_hex: lockingScript.toHex(),
      expected_admit: true,
      reason: 'TS tm_uhrp rejects only expiry<1 (UHRPTopicManager.ts:55); past expiry admits',
    };
  };

  const cases = [await validCase(), await pastExpiryCase()];

  writeFixture('admission_transcript', {
    ...meta('admission_transcript', 'tm_uhrp admit decisions on valid + edge PushDrops. Rust cross-validator runs these.'),
    admin_pub_hex: adminPubCompressedHex,
    cases,
  });
}

// =============================================================================
// 6. AtomicBEEF wrapping goldens — 3 cases
//
// Builds a synthetic ancestor P2PKH tx and a child spending it with a UHRP
// PushDrop output, then wraps via @bsv/sdk `Beef.mergeRawTx` + `toBinaryAtomic`.
// These exercise the AtomicBEEF magic prefix + txid + BEEF_V2 wire format
// that `bsv_rs::transaction::Beef::from_binary` must parse.
// =============================================================================

// Build a P2PKH UTXO-providing ancestor tx with known txid.
// We don't need it to be mined — the AtomicBEEF carries it unproven (no BUMP
// index) and the consumer only needs the raw tx bytes. No inputs
// (coinbase-style, but we don't claim coinbase semantics — just a detached
// funding source).
function syntheticAncestor(lockingScriptHex, satoshis) {
  const tx = new Transaction(
    1,
    [], // no inputs — makes this like a coinbase but without the coinbase marker;
        // it's a "detached" synthetic parent. Real code would have a chain,
        // but the Rust parser only cares the bytes roundtrip.
    [
      {
        lockingScript: LockingScript.fromHex(lockingScriptHex),
        satoshis,
      },
    ],
    0,
  );
  return tx;
}

// Build a child spending `parent`'s output 0. Uses a dummy unlocking script
// (not signed — AtomicBEEF wrapping is about serialization, not validation).
function syntheticChild(parent, childOutputs, unlockingScriptHex = '00') {
  const inputs = [
    {
      sourceTransaction: parent,
      sourceOutputIndex: 0,
      unlockingScript: UnlockingScript.fromHex(unlockingScriptHex),
      sequence: 0xffffffff,
    },
  ];
  return new Transaction(1, inputs, childOutputs, 0);
}

// Also supports multi-input children
function syntheticChildMulti(parents, outputs, unlockingScriptHex = '00') {
  const inputs = parents.map((p) => ({
    sourceTransaction: p,
    sourceOutputIndex: 0,
    unlockingScript: UnlockingScript.fromHex(unlockingScriptHex),
    sequence: 0xffffffff,
  }));
  return new Transaction(1, inputs, outputs, 0);
}

async function genAtomicBeefFixtures() {
  console.log('AtomicBEEF wrapping fixtures…');

  // A canonical UHRP PushDrop output script — reused as the "interesting
  // payload" carried by the child tx.
  const wallet = new ProtoWallet(admin);
  const pushdrop = new PushDrop(wallet);
  const url = 'https://pub-abc.r2.dev/cdn/beef_child';
  const hash = Array.from(new Uint8Array(32).fill(0xE1));
  const expiryW = new Utils.Writer();
  expiryW.writeVarIntNum(1900000000);
  const lenW = new Utils.Writer();
  lenW.writeVarIntNum(777);
  const uhrpLock = await pushdrop.lock(
    [adminIdentityBytes, hash, Utils.toArray(url, 'utf8'), expiryW.toArray(), lenW.toArray()],
    [2, 'uhrp advertisement'], '1', 'anyone', true, true, 'before'
  );
  const uhrpLockHex = uhrpLock.toHex();

  // A simple P2PKH lock for the ancestor tx — pays to admin's pubkey hash.
  const adminAddress = admin.toPublicKey().toAddress();
  const p2pkhLock = new P2PKH().lock(adminAddress);
  const p2pkhLockHex = p2pkhLock.toHex();

  const cases = [];

  // -------- Case A: 1-input P2PKH ancestor → child with UHRP PushDrop output
  {
    const parent = syntheticAncestor(p2pkhLockHex, 100_000);
    const parentTxid = parent.id('hex');
    const child = syntheticChild(parent, [
      { lockingScript: uhrpLock, satoshis: 1 },
      { lockingScript: p2pkhLock, satoshis: 99_000 },
    ]);
    const childTxid = child.id('hex');

    const beef = new Beef();
    beef.mergeRawTx(parent.toBinary());
    beef.mergeRawTx(child.toBinary());
    const atomic = beef.toBinaryAtomic(childTxid);

    cases.push({
      name: 'atomic_beef_1input_p2pkh',
      note: 'one P2PKH ancestor → child spends it, child output[0] is UHRP PushDrop',
      parent_txid: parentTxid,
      child_txid: childTxid,
      beef_bytes: atomic,
      parent_raw_hex: parent.toHex(),
      child_raw_hex: child.toHex(),
      uhrp_locking_script_hex: uhrpLockHex,
    });
  }

  // -------- Case B: 2-input P2PKH (two ancestors) → child
  {
    const parentA = syntheticAncestor(p2pkhLockHex, 50_000);
    // Give parentB a slight size difference so its txid differs — any byte
    // perturbation will do; using a different satoshi value trivially diverges.
    const parentB = syntheticAncestor(p2pkhLockHex, 75_000);
    const child = syntheticChildMulti([parentA, parentB], [
      { lockingScript: uhrpLock, satoshis: 1 },
      { lockingScript: p2pkhLock, satoshis: 124_000 },
    ]);
    const childTxid = child.id('hex');

    const beef = new Beef();
    beef.mergeRawTx(parentA.toBinary());
    beef.mergeRawTx(parentB.toBinary());
    beef.mergeRawTx(child.toBinary());
    const atomic = beef.toBinaryAtomic(childTxid);

    cases.push({
      name: 'atomic_beef_2input_p2pkh',
      note: 'two P2PKH ancestors → child spends both',
      parent_txids: [parentA.id('hex'), parentB.id('hex')],
      child_txid: childTxid,
      beef_bytes: atomic,
    });
  }

  // -------- Case C: 1-input with BRC-29-derived P2PKH source (wallet payment)
  //   Simulates receiving a BRC-29 payment and then spending it in a child tx.
  {
    const deriver = new KeyDeriver(admin);
    // BRC-29 derivation: receiver (us=admin) derives child pubkey with
    // counterparty = sender, protocol=[2,"3241645161d8"], keyID=<prefix> <suffix>.
    // For this synthetic, sender == admin itself (self-send) so we use
    // adminPubCompressedHex as counterparty.
    const derivedPub = deriver.derivePublicKey(
      [2, '3241645161d8'],
      'brc29-pfx brc29-sfx',
      adminPubCompressedHex,
      false, // receiver-side derivation (for_self=false computes counterparty's child)
    );
    const derivedAddr = derivedPub.toAddress();
    const brc29Lock = new P2PKH().lock(derivedAddr);

    const parent = syntheticAncestor(brc29Lock.toHex(), 10_000);
    const child = syntheticChild(parent, [
      { lockingScript: uhrpLock, satoshis: 1 },
    ]);
    const childTxid = child.id('hex');

    const beef = new Beef();
    beef.mergeRawTx(parent.toBinary());
    beef.mergeRawTx(child.toBinary());
    const atomic = beef.toBinaryAtomic(childTxid);

    cases.push({
      name: 'atomic_beef_1input_brc29_source',
      note: 'ancestor tx has BRC-29 derived P2PKH output; child spends it',
      brc29: {
        derivation_prefix: 'brc29-pfx',
        derivation_suffix: 'brc29-sfx',
        sender_identity_key: adminPubCompressedHex,
        derived_pubkey_hex: derivedPub.toString(),
      },
      parent_txid: parent.id('hex'),
      child_txid: childTxid,
      beef_bytes: atomic,
    });
  }

  for (const c of cases) {
    writeFixture(c.name, {
      ...meta(c.name, `AtomicBEEF wrapping: ${c.note}`),
      admin_priv_hex: ADMIN_PRIV_HEX,
      ...c,
    });
  }
}

// =============================================================================
// 7. BRC-29 payment tx goldens — 2 cases
//
// Simulates a sender producing a wallet-payment output to a receiver. The
// receiver's wallet will later derive the matching child private key using
// `derive_brc29_input_key` to spend it. We pin:
//   - the derived child pubkey hex
//   - the expected P2PKH locking script hex
// so our Rust `derive_brc29_input_key` can be asserted byte-exact.
// =============================================================================

function genBrc29PaymentFixtures() {
  console.log('BRC-29 payment fixtures…');

  // Pinned sender + receiver roots.
  const SENDER_PRIV_HEX = '0000000000000000000000000000000000000000000000000000000000000002';
  const RECEIVER_PRIV_HEX = '0000000000000000000000000000000000000000000000000000000000000003';
  const sender = PrivateKey.fromHex(SENDER_PRIV_HEX);
  const receiver = PrivateKey.fromHex(RECEIVER_PRIV_HEX);
  const senderPubHex = sender.toPublicKey().toString();
  const receiverPubHex = receiver.toPublicKey().toString();

  const cases = [
    {
      name: 'brc29_payment_basic',
      derivation_prefix: 'pfx-basic',
      derivation_suffix: 'sfx-basic',
      satoshis: 1_000,
    },
    {
      name: 'brc29_payment_large_keyid',
      derivation_prefix: 'prefix-with-some-length-AAAAAAAA',
      derivation_suffix: 'suffix-with-some-length-BBBBBBBB',
      satoshis: 42_000,
    },
  ];

  for (const c of cases) {
    // Sender derives the RECEIVER's child: protocol=[2,"3241645161d8"],
    // keyID="<prefix> <suffix>", counterparty=receiver, forSelf=false.
    // This matches `ScriptTemplateBRC29` in @bsv/wallet-toolbox —
    // the sender puts the receiver's derived pubkey into the P2PKH.
    const senderDeriver = new KeyDeriver(sender);
    const keyID = `${c.derivation_prefix} ${c.derivation_suffix}`;
    const derivedPub = senderDeriver.derivePublicKey(
      [2, '3241645161d8'],
      keyID,
      receiverPubHex,
      false,
    );
    const derivedPubHex = derivedPub.toString();
    const derivedAddr = derivedPub.toAddress();
    const lockingScript = new P2PKH().lock(derivedAddr);
    const lockingScriptHex = lockingScript.toHex();

    // Build a toy single-output tx paying the derived pubkey. Input is
    // synthetic (no real funding source); consumers only care about the
    // output locking script. This mirrors what wallet-toolbox emits for
    // outputs in a wallet-payment-output.
    const tx = new Transaction(
      1,
      [],
      [{ lockingScript, satoshis: c.satoshis }],
      0,
    );
    const txHex = tx.toHex();

    writeFixture(c.name, {
      ...meta(c.name, 'BRC-29 payment: sender derives receiver child, builds P2PKH to it'),
      sender_priv_hex: SENDER_PRIV_HEX,
      sender_pub_hex: senderPubHex,
      receiver_priv_hex: RECEIVER_PRIV_HEX,
      receiver_pub_hex: receiverPubHex,
      derivation: {
        protocol: [2, '3241645161d8'],
        key_id: keyID,
        derivation_prefix: c.derivation_prefix,
        derivation_suffix: c.derivation_suffix,
        counterparty: receiverPubHex,
        for_self: false,
      },
      expected: {
        derived_pubkey_hex: derivedPubHex,
        locking_script_hex: lockingScriptHex,
        tx_hex: txHex,
        satoshis: c.satoshis,
      },
    });
  }
}

// =============================================================================
// 8. Sighash preimage goldens — 4 cases
//
// Uses `TransactionSignature.format` from @bsv/sdk to compute the BIP-143
// preimage and the sighash digest. Scope = SIGHASH_ALL | SIGHASH_FORKID (0x41).
// =============================================================================

function buildSighashCase({
  name,
  note,
  inputs,    // [{sourceTXID, sourceOutputIndex, satoshis, lockingScriptHex, sequence}]
  outputs,   // [{lockingScriptHex, satoshis}]
  inputIndex,
  locktime = 0,
  version = 1,
  scope = TransactionSignature.SIGHASH_ALL | TransactionSignature.SIGHASH_FORKID,
}) {
  // Preimage format needs otherInputs (excluding the one at inputIndex).
  const tsInputs = inputs.map((i) => ({
    sourceTXID: i.sourceTXID,
    sourceOutputIndex: i.sourceOutputIndex,
    unlockingScript: UnlockingScript.fromHex(''),
    sequence: i.sequence ?? 0xffffffff,
  }));
  const tsOutputs = outputs.map((o) => ({
    lockingScript: LockingScript.fromHex(o.lockingScriptHex),
    satoshis: o.satoshis,
  }));

  const signingInput = inputs[inputIndex];
  const otherInputs = tsInputs.filter((_, idx) => idx !== inputIndex);

  const preimage = TransactionSignature.format({
    sourceTXID: signingInput.sourceTXID,
    sourceOutputIndex: signingInput.sourceOutputIndex,
    sourceSatoshis: signingInput.satoshis,
    transactionVersion: version,
    otherInputs,
    outputs: tsOutputs,
    inputIndex,
    subscript: LockingScript.fromHex(signingInput.lockingScriptHex),
    inputSequence: signingInput.sequence ?? 0xffffffff,
    lockTime: locktime,
    scope,
  });

  // Digest: sha256d(preimage). hash256 returns number[].
  const digest = Hash.hash256(preimage);

  // Serialize the unsigned tx for Rust parity reference.
  const txInputs = inputs.map((i) => ({
    sourceTXID: i.sourceTXID,
    sourceOutputIndex: i.sourceOutputIndex,
    unlockingScript: UnlockingScript.fromHex(''),
    sequence: i.sequence ?? 0xffffffff,
  }));
  const tx = new Transaction(version, txInputs, tsOutputs, locktime);
  const txHex = tx.toHex();

  return {
    ...meta(name, note),
    input: {
      tx_hex: txHex,
      inputs: inputs.map((i) => ({
        source_txid: i.sourceTXID,
        source_vout: i.sourceOutputIndex,
        source_satoshis: i.satoshis,
        source_locking_script_hex: i.lockingScriptHex,
        sequence: i.sequence ?? 0xffffffff,
      })),
      outputs: outputs.map((o) => ({
        satoshis: o.satoshis,
        locking_script_hex: o.lockingScriptHex,
      })),
      input_index: inputIndex,
      version,
      locktime,
      scope,
    },
    expected: {
      preimage_hex: Buffer.from(preimage).toString('hex'),
      sighash_digest_hex: Buffer.from(digest).toString('hex'),
    },
  };
}

function genSighashPreimageFixtures() {
  console.log('Sighash preimage fixtures…');

  // Two synthetic P2PKH scripts; content doesn't matter for preimage maths —
  // only bytes + satoshis + indices.
  const p2pkhA = '76a914' + 'aa'.repeat(20) + '88ac';
  const p2pkhB = '76a914' + 'bb'.repeat(20) + '88ac';
  const p2pkhOut = '76a914' + 'cc'.repeat(20) + '88ac';

  // Deterministic-looking txids (ascending byte patterns). They're opaque
  // references in the preimage — no actual tx needs to exist.
  const TXID_A = '1111111111111111111111111111111111111111111111111111111111111111';
  const TXID_B = '2222222222222222222222222222222222222222222222222222222222222222';

  writeFixture(
    'sighash_p2pkh_1input',
    buildSighashCase({
      name: 'sighash_p2pkh_1input',
      note: 'BIP-143 sighash preimage: single P2PKH input, SIGHASH_ALL|FORKID',
      inputs: [
        { sourceTXID: TXID_A, sourceOutputIndex: 0, satoshis: 100_000, lockingScriptHex: p2pkhA },
      ],
      outputs: [
        { lockingScriptHex: p2pkhOut, satoshis: 99_000 },
      ],
      inputIndex: 0,
    }),
  );

  writeFixture(
    'sighash_p2pkh_2inputs_sign_first',
    buildSighashCase({
      name: 'sighash_p2pkh_2inputs_sign_first',
      note: 'BIP-143 sighash preimage: two inputs, signing input 0',
      inputs: [
        { sourceTXID: TXID_A, sourceOutputIndex: 0, satoshis: 100_000, lockingScriptHex: p2pkhA },
        { sourceTXID: TXID_B, sourceOutputIndex: 1, satoshis: 50_000, lockingScriptHex: p2pkhB },
      ],
      outputs: [
        { lockingScriptHex: p2pkhOut, satoshis: 149_000 },
      ],
      inputIndex: 0,
    }),
  );

  writeFixture(
    'sighash_p2pkh_2inputs_sign_second',
    buildSighashCase({
      name: 'sighash_p2pkh_2inputs_sign_second',
      note: 'BIP-143 sighash preimage: two inputs, signing input 1',
      inputs: [
        { sourceTXID: TXID_A, sourceOutputIndex: 0, satoshis: 100_000, lockingScriptHex: p2pkhA },
        { sourceTXID: TXID_B, sourceOutputIndex: 1, satoshis: 50_000, lockingScriptHex: p2pkhB },
      ],
      outputs: [
        { lockingScriptHex: p2pkhOut, satoshis: 149_000 },
      ],
      inputIndex: 1,
    }),
  );

  // Deferred: PushDrop-spend sighash case. Reason:
  // `PushDrop::unlock` in @bsv/sdk 1.10.1 returns a closure that signs via
  // `wallet.createSignature` — there's no standalone "give me the preimage"
  // entry point for the PushDrop-lock subscript. But `TransactionSignature.format`
  // is script-agnostic (just takes a subscript byte slice), so the
  // p2pkh fixtures already exercise the sighash path byte-identically for
  // any subscript. Adding a PushDrop-subscript case just to prove the
  // script-agnostic claim.
  const samplePushDropHex =
    '2102e14da90ec43a7c1b7898cc9d1fe0e1d2c4e4e7d6f8d1c5e5f7e9d3c5e7f9a1b3ac20aabbccddeeff001122334455667788aabbccddeeff001122334455667788aabb6d6d';
  writeFixture(
    'sighash_pushdrop_subscript',
    buildSighashCase({
      name: 'sighash_pushdrop_subscript',
      note: 'BIP-143 sighash preimage with non-P2PKH subscript (PushDrop-shaped bytes)',
      inputs: [
        { sourceTXID: TXID_A, sourceOutputIndex: 0, satoshis: 1, lockingScriptHex: samplePushDropHex },
      ],
      outputs: [
        { lockingScriptHex: p2pkhOut, satoshis: 1 },
      ],
      inputIndex: 0,
    }),
  );
}

// =============================================================================
// 9. Expanded admission transcripts — per-case fixtures under transcripts/
//
// Each fixture captures one input script + the expected `UHRPTopicManager`
// admit/reject decision from @bsv/sdk+overlay TS reference. Cases are chosen
// to exercise every branch in `UHRPTopicManager.identifyAdmissibleOutputs`.
// =============================================================================

async function genAdmissionTranscriptCases() {
  console.log('tm_uhrp per-case transcripts…');
  const TRANSCRIPT_DIR = join(FIXTURES, 'transcripts');
  mkdirSync(TRANSCRIPT_DIR, { recursive: true });

  const wallet = new ProtoWallet(admin);
  const pushdrop = new PushDrop(wallet);
  const protocolID = [2, 'uhrp advertisement'];
  const keyID = '1';

  // Helper: produce a valid UHRP PushDrop locking script with the given fields.
  async function validPushdrop(fields) {
    return (await pushdrop.lock(fields, protocolID, keyID, 'anyone', true, true, 'before')).toHex();
  }

  // Helper: force a specific set of 5 data fields and append a random (junk)
  // signature so the PushDrop decoder yields 6 pushed fields. Useful when we
  // want the structural gates (hash length, URI, varint) to fire before the
  // signature gate.
  function rawSixFieldPushdrop(fields, lockingPubBytes, junkSig) {
    // Reproduce PushDrop.lock(...)'s layout:
    // [lockingPubPush] OP_CHECKSIG  { field pushes }  (OP_DROP|OP_2DROP)*
    // We build it by hand to bypass the BRC-42 derivation and signing logic.
    // The produced script still decodes via PushDrop.decode to 6 fields.
    const writer = new Utils.Writer();

    // Push the locking pubkey (33 bytes).
    writer.write([lockingPubBytes.length, ...lockingPubBytes]);
    // OP_CHECKSIG
    writer.writeUInt8(OP.OP_CHECKSIG);

    const allFields = [...fields, junkSig];
    for (const f of allFields) {
      const chunk = pushChunk(f);
      for (const b of chunk) writer.writeUInt8(b);
    }
    // Append the OP_DROP / OP_2DROP tail matching @bsv/sdk PushDrop.lock():
    // emit OP_2DROP until only 0 or 1 fields remain, then a final OP_DROP if 1.
    let notYetDropped = allFields.length;
    while (notYetDropped > 1) {
      writer.writeUInt8(OP.OP_2DROP);
      notYetDropped -= 2;
    }
    if (notYetDropped !== 0) {
      writer.writeUInt8(OP.OP_DROP);
    }
    return Buffer.from(writer.toArray()).toString('hex');
  }

  function pushChunk(data) {
    if (data.length === 0) return [0];
    if (data.length <= 75) return [data.length, ...data];
    if (data.length <= 255) return [0x4c, data.length, ...data];
    if (data.length <= 65535) return [0x4d, data.length & 0xff, (data.length >> 8) & 0xff, ...data];
    return [
      0x4e,
      data.length & 0xff,
      (data.length >> 8) & 0xff,
      (data.length >> 16) & 0xff,
      (data.length >> 24) & 0xff,
      ...data,
    ];
  }

  function varint(n) {
    const w = new Utils.Writer();
    w.writeVarIntNum(n);
    return w.toArray();
  }

  const cases = [];

  // ---- 1. Valid happy path ----
  cases.push({
    label: 'valid_admit',
    expected_admit: true,
    reason: 'all fields correct, https url, sig valid, linkage valid',
    locking_script_hex: await validPushdrop([
      adminIdentityBytes,
      Array.from(new Uint8Array(32).fill(0x11)),
      Utils.toArray('https://pub-abc.r2.dev/cdn/ok', 'utf8'),
      varint(1_900_000_000),
      varint(500),
    ]),
  });

  // ---- 2. Past expiry (TS admits per 2026-04 fix) ----
  cases.push({
    label: 'past_expiry_admits',
    expected_admit: true,
    reason: 'TS tm_uhrp only rejects expiry<1; past expiry admits',
    locking_script_hex: await validPushdrop([
      adminIdentityBytes,
      Array.from(new Uint8Array(32).fill(0x22)),
      Utils.toArray('https://pub-abc.r2.dev/cdn/past', 'utf8'),
      varint(1_000_000_000), // 2001
      varint(500),
    ]),
  });

  // ---- 3. Zero expiry ----
  cases.push({
    label: 'zero_expiry_rejects',
    expected_admit: false,
    reason: 'expiry_time=0 fails TS check `expiry_time < 1`',
    locking_script_hex: await validPushdrop([
      adminIdentityBytes,
      Array.from(new Uint8Array(32).fill(0x33)),
      Utils.toArray('https://pub-abc.r2.dev/cdn/zero', 'utf8'),
      varint(0),
      varint(500),
    ]),
  });

  // ---- 4. http:// (non-https) scheme — rejects ----
  cases.push({
    label: 'http_scheme_rejects',
    expected_admit: false,
    reason: 'URL scheme must be https; http:// rejects',
    locking_script_hex: await validPushdrop([
      adminIdentityBytes,
      Array.from(new Uint8Array(32).fill(0x44)),
      Utils.toArray('http://pub-abc.r2.dev/cdn/insecure', 'utf8'),
      varint(1_900_000_000),
      varint(500),
    ]),
  });

  // ---- 5. ftp:// scheme — rejects ----
  cases.push({
    label: 'ftp_scheme_rejects',
    expected_admit: false,
    reason: 'URL scheme must be https; ftp:// rejects',
    locking_script_hex: await validPushdrop([
      adminIdentityBytes,
      Array.from(new Uint8Array(32).fill(0x55)),
      Utils.toArray('ftp://pub-abc.r2.dev/cdn/oldschool', 'utf8'),
      varint(1_900_000_000),
      varint(500),
    ]),
  });

  // ---- 6. Bad hash length (31 bytes) ----
  // Need a raw PushDrop here so we don't get auto-corrected; the signing flow
  // doesn't enforce field[1].length == 32. Use a junk signature.
  cases.push({
    label: 'bad_hash_length_31_rejects',
    expected_admit: false,
    reason: 'field[1] hash must be 32 bytes',
    locking_script_hex: rawSixFieldPushdrop(
      [
        adminIdentityBytes,
        Array.from(new Uint8Array(31).fill(0x66)), // 31 bytes
        Utils.toArray('https://pub-abc.r2.dev/cdn/badhash', 'utf8'),
        varint(1_900_000_000),
        varint(500),
      ],
      adminIdentityBytes,
      [0x30, 0x06, 0x02, 0x01, 0x01, 0x02, 0x01, 0x01], // 8-byte junk DER
    ),
  });

  // ---- 7. Bad identity key (32 bytes, not 33) ----
  cases.push({
    label: 'bad_identity_key_32_bytes_rejects',
    expected_admit: false,
    reason: 'field[0] identity pubkey must be 33 bytes (compressed)',
    locking_script_hex: rawSixFieldPushdrop(
      [
        Array.from(new Uint8Array(32).fill(0x77)), // 32 bytes — wrong
        Array.from(new Uint8Array(32).fill(0x66)),
        Utils.toArray('https://pub-abc.r2.dev/cdn/badid', 'utf8'),
        varint(1_900_000_000),
        varint(500),
      ],
      adminIdentityBytes,
      [0x30, 0x06, 0x02, 0x01, 0x01, 0x02, 0x01, 0x01],
    ),
  });

  // ---- 8. Bad varint for expiry (first byte is 0xFF — signals 8-byte value
  //         but we only give one garbage byte after). This trips the Reader's
  //         varint decoder.
  cases.push({
    label: 'bad_varint_expiry_rejects',
    expected_admit: false,
    reason: 'expiry varint byte sequence does not decode',
    locking_script_hex: rawSixFieldPushdrop(
      [
        adminIdentityBytes,
        Array.from(new Uint8Array(32).fill(0x88)),
        Utils.toArray('https://pub-abc.r2.dev/cdn/badvarint', 'utf8'),
        [0xFF], // claims 8-byte varint but has zero remaining bytes
        varint(500),
      ],
      adminIdentityBytes,
      [0x30, 0x06, 0x02, 0x01, 0x01, 0x02, 0x01, 0x01],
    ),
  });

  // ---- 9. Empty signature field ----
  //
  // PushDrop pushes an empty sig as an OP_0 (opcode 0). The decoder re-expands
  // OP_0 to an empty number[], so fields.length stays at 6, and the
  // signature byte slice is empty. TS validator then fails sig verification.
  cases.push({
    label: 'empty_signature_rejects',
    expected_admit: false,
    reason: 'signature slot is empty; verify rejects',
    locking_script_hex: rawSixFieldPushdrop(
      [
        adminIdentityBytes,
        Array.from(new Uint8Array(32).fill(0x99)),
        Utils.toArray('https://pub-abc.r2.dev/cdn/emptysig', 'utf8'),
        varint(1_900_000_000),
        varint(500),
      ],
      adminIdentityBytes,
      [], // empty
    ),
  });

  // ---- 10. Valid-shape signature but wrong key (properly shaped DER, random)
  cases.push({
    label: 'bad_signature_wrong_key_rejects',
    expected_admit: false,
    reason: 'valid DER shape but not signed by the author — verify fails',
    locking_script_hex: rawSixFieldPushdrop(
      [
        adminIdentityBytes,
        Array.from(new Uint8Array(32).fill(0xAA)),
        Utils.toArray('https://pub-abc.r2.dev/cdn/badsig', 'utf8'),
        varint(1_900_000_000),
        varint(500),
      ],
      adminIdentityBytes,
      // Real-looking DER sig shape, but signed over unrelated data.
      [
        0x30, 0x44, 0x02, 0x20,
        0x77, 0x77, 0x77, 0x77, 0x77, 0x77, 0x77, 0x77,
        0x77, 0x77, 0x77, 0x77, 0x77, 0x77, 0x77, 0x77,
        0x77, 0x77, 0x77, 0x77, 0x77, 0x77, 0x77, 0x77,
        0x77, 0x77, 0x77, 0x77, 0x77, 0x77, 0x77, 0x77,
        0x02, 0x20,
        0x88, 0x88, 0x88, 0x88, 0x88, 0x88, 0x88, 0x88,
        0x88, 0x88, 0x88, 0x88, 0x88, 0x88, 0x88, 0x88,
        0x88, 0x88, 0x88, 0x88, 0x88, 0x88, 0x88, 0x88,
        0x88, 0x88, 0x88, 0x88, 0x88, 0x88, 0x88, 0x88,
      ],
    ),
  });

  // ---- 11. Bad linkage: locking pubkey ≠ BRC-42 child of identity
  //   Use a deterministic distinct pubkey so the final linkage check fails.
  {
    const otherKey = PrivateKey.fromHex(
      '0000000000000000000000000000000000000000000000000000000000000007',
    );
    const randomLockingPub = Utils.toArray(otherKey.toPublicKey().toString(), 'hex');
    cases.push({
      label: 'bad_linkage_rejects',
      expected_admit: false,
      reason: 'locking pubkey is not the BRC-42 child of identity+protocol',
      locking_script_hex: rawSixFieldPushdrop(
        [
          adminIdentityBytes,
          Array.from(new Uint8Array(32).fill(0xBB)),
          Utils.toArray('https://pub-abc.r2.dev/cdn/badlink', 'utf8'),
          varint(1_900_000_000),
          varint(500),
        ],
        randomLockingPub,
        [0x30, 0x06, 0x02, 0x01, 0x01, 0x02, 0x01, 0x01],
      ),
    });
  }

  // ---- 12. Too-few fields (4 data fields) ----
  cases.push({
    label: 'too_few_fields_rejects',
    expected_admit: false,
    reason: '4 fields total (3 data + junk sig) — fails `< 5` check',
    // Only 3 data fields + sig = 4 pushed fields total.
    locking_script_hex: rawSixFieldPushdrop(
      [
        adminIdentityBytes,
        Array.from(new Uint8Array(32).fill(0xCC)),
        Utils.toArray('https://pub-abc.r2.dev/cdn/toofew', 'utf8'),
      ],
      adminIdentityBytes,
      [0x30, 0x06, 0x02, 0x01, 0x01, 0x02, 0x01, 0x01],
    ),
  });

  // ---- 13. Too-many fields (6 data fields before sig = 7 total) ----
  cases.push({
    label: 'too_many_fields_rejects',
    expected_admit: false,
    reason: '6 data fields + sig = 7 pushed fields; Rust validator requires exactly 6',
    locking_script_hex: rawSixFieldPushdrop(
      [
        adminIdentityBytes,
        Array.from(new Uint8Array(32).fill(0xDD)),
        Utils.toArray('https://pub-abc.r2.dev/cdn/toomany', 'utf8'),
        varint(1_900_000_000),
        varint(500),
        [0x01, 0x02, 0x03], // extra field
      ],
      adminIdentityBytes,
      [0x30, 0x06, 0x02, 0x01, 0x01, 0x02, 0x01, 0x01],
    ),
  });

  // ---- 14. Non-PushDrop script (random OP_RETURN bytes) ----
  cases.push({
    label: 'non_pushdrop_rejects',
    expected_admit: false,
    reason: 'script is not a PushDrop shape at all (OP_RETURN + data)',
    locking_script_hex: '6a04deadbeef',
  });

  // ---- 15. Zero content-length ----
  cases.push({
    label: 'zero_content_length_rejects',
    expected_admit: false,
    reason: 'content_length=0 fails TS `file_size < 1` check',
    locking_script_hex: await validPushdrop([
      adminIdentityBytes,
      Array.from(new Uint8Array(32).fill(0xEE)),
      Utils.toArray('https://pub-abc.r2.dev/cdn/zerosize', 'utf8'),
      varint(1_900_000_000),
      varint(0),
    ]),
  });

  // ---- 16. Max content-length (u64 boundary — we use 2^53-1, the largest
  //   exact integer JS can varint-serialize through `writeVarIntNum`).
  cases.push({
    label: 'max_content_length_admits',
    expected_admit: true,
    reason: 'max JS-representable u53 content length still admits (TS only checks file_size<1)',
    locking_script_hex: await validPushdrop([
      adminIdentityBytes,
      Array.from(new Uint8Array(32).fill(0xFA)),
      Utils.toArray('https://pub-abc.r2.dev/cdn/maxsize', 'utf8'),
      varint(1_900_000_000),
      varint(Number.MAX_SAFE_INTEGER),
    ]),
  });

  // Persist each case to its own file under transcripts/ and also bundle into
  // a combined transcripts.json array for convenient Rust iteration.
  for (const c of cases) {
    const filename = `transcripts/${c.label}.json`;
    const fullPath = join(FIXTURES, `${filename}`);
    writeFileSync(fullPath, JSON.stringify({
      ...meta(c.label, `tm_uhrp admission case: ${c.reason}`),
      admin_pub_hex: adminPubCompressedHex,
      ...c,
    }, null, 2) + '\n');
    console.log(`  wrote ${filename}`);
  }

  writeFixture('transcripts_index', {
    ...meta('transcripts_index', 'Index of per-case tm_uhrp admission fixtures'),
    admin_pub_hex: adminPubCompressedHex,
    cases: cases.map((c) => ({
      label: c.label,
      expected_admit: c.expected_admit,
      reason: c.reason,
      locking_script_hex: c.locking_script_hex,
    })),
  });
}

// =============================================================================
// Run all
// =============================================================================

async function main() {
  console.log(`generating parity fixtures with @bsv/sdk ${SDK_VERSION}`);
  await genUhrpPushDrops();
  await genShipPushDrops();
  await genSlapPushDrops();
  genBrc42Derivations();
  await genAdmissionTranscripts();
  await genAtomicBeefFixtures();
  genBrc29PaymentFixtures();
  genSighashPreimageFixtures();
  await genAdmissionTranscriptCases();
  console.log('done.');
}

main().catch(e => {
  console.error(e);
  process.exit(1);
});
