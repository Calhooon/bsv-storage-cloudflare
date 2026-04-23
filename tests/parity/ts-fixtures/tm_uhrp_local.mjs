// tm_uhrp_local.mjs — verbatim copy of
// ~/bsv/uhrp-services/backend/src/topic-managers/UHRPTopicManager.ts
// (+ isTokenSignatureCorrectlyLinked.ts), translated to JS but
// NOT semantically altered. Pinned to the `@bsv/sdk 1.10.1` and
// `@bsv/overlay 0.6.0` versions in package.json, which mirror
// nanostore.babbage.systems + overlay-us-1.bsvb.tech deployments.
//
// This is the ground-truth admission rule for tm_uhrp. Do not
// "clean up" or "optimize" this file — any divergence from the
// upstream TS source defeats the cross-validator.
//
// If uhrp-services ever publishes a new UHRPTopicManager.ts,
// re-sync this file by hand and bump the `_meta.note` in any
// generated transcript so reviewers notice.

import { Transaction, PushDrop, ProtoWallet, Utils } from '@bsv/sdk';

const isTokenSignatureCorrectlyLinked = async (
  lockingPublicKey,
  fields,
) => {
  // The signature is the last field, which needs to be removed for verification
  const signature = fields.pop();

  // The protocol is in the first field (of the TS docstring — actually it's hard-coded)
  const protocolID = [2, 'uhrp advertisement'];

  // The identity key is in the first field
  const identityKey = Utils.toHex(fields[0]);

  const data = fields.reduce((a, e) => [...a, ...e], []);
  const anyoneWallet = new ProtoWallet('anyone');
  try {
    const { valid } = await anyoneWallet.verifySignature({
      data,
      signature,
      counterparty: identityKey,
      protocolID,
      keyID: '1',
    });
    if (!valid) return false;
  } catch (e) {
    return false;
  }

  const { publicKey: expectedLockingPublicKey } = await anyoneWallet.getPublicKey({
    counterparty: identityKey,
    protocolID,
    keyID: '1',
  });
  return expectedLockingPublicKey === lockingPublicKey.toString();
};

export default class UHRPTopicManager {
  identifyNeededInputs;

  async getDocumentation() {
    return 'UHRP topic manager (local copy for cross-validator).';
  }

  async getMetaData() {
    return {
      name: 'Universal Hash Resolution Protocol',
      shortDescription: 'Manages UHRP content availability advertisements.',
    };
  }

  async identifyAdmissibleOutputs(beef, previousCoins) {
    try {
      console.log('previous UTXOs', previousCoins.length);
      const outputs = [];
      const parsedTransaction = Transaction.fromBEEF(beef);

      for (const [i, output] of parsedTransaction.outputs.entries()) {
        try {
          const result = PushDrop.decode(output.lockingScript);
          if (result.fields.length < 5) {
            throw new Error('Invalid UHRP token');
          }
          const isLinked = await isTokenSignatureCorrectlyLinked(
            result.lockingPublicKey,
            result.fields,
          );
          if (!isLinked) {
            throw new Error('Signature is not properly linked');
          }
          if (result.fields[1].length !== 32) {
            throw new Error('Invalid hash length');
          }
          const fileLocationString = Utils.toUTF8(result.fields[2]);
          const fileLocationURL = new URL(fileLocationString);
          if (fileLocationURL.protocol !== 'https:') {
            throw new Error('Advertisement must be on HTTPS');
          }
          const expiryTime = new Utils.Reader(result.fields[3]).readVarIntNum();
          const fileSize = new Utils.Reader(result.fields[4]).readVarIntNum();
          if (expiryTime < 1 || fileSize < 1) {
            throw new Error('Invalid expiry time or file size');
          }
          outputs.push(i);
        } catch (error) {
          console.error('Error with output', i, error);
        }
      }
      if (outputs.length === 0) {
        throw new Error('This transaction does not publish a valid CWI account descriptor!');
      }

      return {
        coinsToRetain: previousCoins,
        outputsToAdmit: outputs,
      };
    } catch (error) {
      return {
        coinsToRetain: [],
        outputsToAdmit: [],
      };
    }
  }
}
