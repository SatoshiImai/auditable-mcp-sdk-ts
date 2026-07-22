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
  records: ChainRecord[];
  digest?: string;
}

export const canonicalizationVectors = load<CanonicalizationVector[]>('canonicalization.json');
export const eventVectors = load<EventVector[]>('events.json');
export const chainVector = load<ChainVector>('chain.json');
