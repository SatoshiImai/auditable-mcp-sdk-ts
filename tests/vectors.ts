/**
 * Load the vendored golden conformance vectors. These are the single source of truth shared with the
 * Python SDK; both must reproduce every `canonical` / `sha256` / `record_hash` byte-for-byte.
 */

import { readFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

const VECTORS_DIR = join(dirname(fileURLToPath(import.meta.url)), '..', 'spec', 'vectors');

function load<T>(name: string): T {
  return JSON.parse(readFileSync(join(VECTORS_DIR, name), 'utf-8')) as T;
}

export interface CanonicalizationVector {
  name: string;
  value: unknown;
  canonical: string;
  sha256: string;
}

export interface EventVector {
  name: string;
  event: Record<string, unknown>;
  canonical: string;
  sha256: string;
}

export interface ChainRecord {
  event: Record<string, unknown>;
  seq: number;
  host_ts: string;
  previous_hash: string;
  record_hash: string;
}

export interface ChainVector {
  /** The public half of each key a record in the chain is signed with, as a JWK (§5.1). */
  keys?: Record<string, { alg: string; jwk: Record<string, string> }>;
  records: ChainRecord[];
  digest?: string;
}

/** A record of the countersigned chain: a chain record plus the §7.1 countersignature and its preimage. */
export interface CountersignedChainRecord extends ChainRecord {
  host_signature: string;
  host_key_id: string;
  log_id: string;
  countersignature_preimage: { canonical: string; sha256: string };
}

export interface CountersignedChainVector {
  keys: Record<string, { alg: string; jwk: Record<string, string> }>;
  records: CountersignedChainRecord[];
  digest: string;
}

export interface ErrorCase {
  name: string;
  channel: 'attempt' | 'outcome';
  event: Record<string, unknown>;
  expect: { status?: string; reason?: string; sealed?: boolean; anomaly_kind?: string };
}

export const canonicalizationVectors = load<CanonicalizationVector[]>('canonicalization.json');
export const eventVectors = load<EventVector[]>('events.json');
export const chainVector = load<ChainVector>('chain.json');
export const chainSignedVector = load<ChainVector>('chain-signed.json');
export const chainCountersignedVector = load<CountersignedChainVector>('chain-countersigned.json');
export const errorCases = load<ErrorCase[]>('error-cases.json');

export interface SignerSeqReplayStep {
  name: string;
  channel: 'attempt' | 'outcome';
  host_available: boolean;
  event: Record<string, unknown>;
  expect: { status?: string; reason?: string; seq?: number; sealed?: boolean; anomalies: string[] };
}

export interface SignerSeqReplayVector {
  keys: Record<string, { alg: string; jwk: Record<string, string> }>;
  steps: SignerSeqReplayStep[];
}

export interface SignerSeqAccountingCase {
  name: string;
  records: Record<string, unknown>[];
  unaccounted: { key_id: string; session_id: string; signer_seq: number }[];
}

export const signerSeqReplayVector = load<SignerSeqReplayVector>('signer-seq-replay.json');
export const signerSeqAccountingCases = load<SignerSeqAccountingCase[]>('signer-seq-accounting.json');

export interface VerifierCase {
  name: string;
  records: Record<string, unknown>[];
  options: {
    countersignature_required?: boolean;
    expected_identity?: { log_id: string; host_key_ids: string[] };
  };
  expect_kinds: string[];
}

export interface VerifierCasesVector {
  keys: Record<string, { alg: string; jwk: Record<string, string> }>;
  cases: VerifierCase[];
}

export const verifierCasesVector = load<VerifierCasesVector>('verifier-cases.json');
