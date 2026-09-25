/**
 * Verify a sealed ledger for non-tampering and completeness (§8.3, §10.7).
 *
 * The chain is recomputed from the record bodies rather than read from the stored hashes, so any
 * mutation of an event propagates to the tail digest and is localized. An out-of-band anchored digest
 * (§8.3) catches a fully re-linked rewrite or truncation that an internally-consistent chain cannot.
 * This is a read-only auditor over records that may come straight from a `Ledger` or be reloaded from
 * untrusted storage. `verifyChain` checks chain integrity alone (§8.3); `verifyLedger` adds A-MCP
 * event-schema validation on top (§7.1).
 */

import { CanonicalizationError } from './canonical';
import * as fields from './fields';
import { computeRecordHash, countersignaturePayload, GENESIS_HASH } from './hashing';
import type { SealedRecord } from './ledger';
import { firstSealedValidationError, isEarlierSpecVersion, KNOWN_SPEC_VERSIONS, Outcome } from './models';
import * as reasons from './reasons';
import { AmcpUsageError } from './transport';

// A verifier reports only the §7.6 Tier-1 anomaly kinds. Re-exported here for convenience so callers
// can match against them without importing `reasons` directly; finer causes go in `detail` (Tier-2).
export const SCHEMA_INVALID = reasons.SCHEMA_INVALID;
export const SEQ_GAP = reasons.SEQ_GAP;
export const RECORD_HASH_MISMATCH = reasons.RECORD_HASH_MISMATCH;
export const DIGEST_MISMATCH = reasons.DIGEST_MISMATCH;
export const PRINCIPAL_MISMATCH = reasons.PRINCIPAL_MISMATCH;
export const ORPHANED_OUTCOME = reasons.ORPHANED_OUTCOME;
export const REPLAY_DETECTED = reasons.REPLAY_DETECTED;

/** A single verification failure. `seq` is null for whole-ledger issues (e.g. digest mismatch). */
export interface VerifyIssue {
  seq: number | null;
  kind: string;
  detail: string;
}

/** The result of verifying a ledger; `ok` is true only when `issues` is empty. */
export interface VerifyReport {
  /** True when the checks that ran found nothing. Not the same as having checked everything. */
  ok: boolean;
  count: number;
  computedDigest: string;
  issues: VerifyIssue[];
  /**
   * Checks that were applicable and did not run (§11.4).
   *
   * Countersignature determination and Level-2 signature re-verification both need an out-of-band registry,
   * and a verifier without one performs neither. §11.4 requires that to be reported rather than left
   * as an absence of anomalies - an unchecked signature and a valid one are not the same finding.
   */
  unchecked: readonly string[];
  /** True when nothing was found and nothing applicable was skipped (§11.4). */
  complete: boolean;
}

/**
 * Resolves a `host_key_id` and verifies a detached signature over canonical bytes (§7.1).
 *
 * Synchronous because offline ledger verification reads stored records and does no I/O;
 * `CountersignatureRegistryVerifier.check` is the registry-backed implementation.
 */
export type CountersignatureChecker = (hostKeyId: string, signature: string, payload: Uint8Array) => boolean;

/**
 * Verifies a sealed Level-2 event's own `signature` against the out-of-band key registry (§7.4).
 *
 * Synchronous for the same reason as `CountersignatureChecker`; `KeyRegistryVerifier.check` implements it.
 */
export type SignatureChecker = (event: Record<string, unknown>) => boolean;

/**
 * The identity a partition is expected to hold under §10.10's first construction, supplied out-of-band.
 *
 * `log_id` is distinct only among one host's chains (§7.1), so the identity is the `log_id` together
 * with the keys the partition's host countersigns under: another host may name a chain the same way.
 */
export interface ExpectedIdentity {
  logId: string;
  hostKeyIds: ReadonlySet<string>;
}

/** Out-of-band inputs to verification beyond the registries (§10.10, §11.4). */
export interface VerifyOptions {
  /**
   * The chain must be countersigned: an uncountersigned record is `host-signature-invalid` rather than a
   * state (§11.4). A storage-level attacker can strip a countersignature it cannot forge, so only an
   * input from outside the ledger tells a stripped record from one that never carried one.
   */
  countersignatureRequired?: boolean;
  /**
   * Every record must carry the full countersignature triple under this `log_id` and one of these
   * `host_key_id`s, else `principal-mismatch` (§10.10). Compared as strings, including for a record that
   * fails every other check.
   */
  expectedIdentity?: ExpectedIdentity;
}

/**
 * Every input to `verifyChain` / `verifyLedger` by name - the alternative to the positional form, with
 * the same names and meaning as the Python port's keyword arguments.
 */
export interface VerifyLedgerOptions extends VerifyOptions {
  anchoredDigest?: string | undefined;
  adapter?: RecordAdapter | undefined;
  expectedPrincipal?: unknown;
  /** A function, e.g. `CountersignatureRegistryVerifier#check` - not the verifier object itself. */
  countersignatureChecker?: CountersignatureChecker | undefined;
  /** A function, e.g. `KeyRegistryVerifier#check` - not the verifier object itself. */
  signatureChecker?: SignatureChecker | undefined;
}

/** The inputs of either calling form, resolved to one shape and checked. */
interface ResolvedInputs {
  anchoredDigest: string | undefined;
  adapter: RecordAdapter;
  expectedPrincipal: unknown;
  countersignatureChecker: CountersignatureChecker | undefined;
  signatureChecker: SignatureChecker | undefined;
  options: VerifyOptions;
}

/**
 * A checker is called per record, so an object passed where one belongs would surface as a
 * `TypeError` deep in the loop; it is refused up front, naming the method to pass instead.
 */
function requireChecker<T>(value: T | undefined, name: string, method: string): T | undefined {
  if (value !== undefined && typeof value !== 'function') {
    throw new AmcpUsageError(
      `${name} must be a function, not ${value === null ? 'null' : typeof value}; pass the verifier's bound ` +
        `check method (e.g. ${method}.check), not the verifier`,
    );
  }
  return value;
}

function resolveInputs(
  second: string | VerifyLedgerOptions | undefined,
  positional: {
    adapter: RecordAdapter;
    expectedPrincipal: unknown;
    countersignatureChecker: CountersignatureChecker | undefined;
    signatureChecker: SignatureChecker | undefined;
    options: VerifyOptions;
  },
): ResolvedInputs {
  if (second !== null && typeof second === 'object') {
    const {
      anchoredDigest,
      adapter,
      expectedPrincipal,
      countersignatureChecker,
      signatureChecker,
      countersignatureRequired,
      expectedIdentity,
    } = second;
    return {
      anchoredDigest,
      adapter: adapter ?? DEFAULT_ADAPTER,
      expectedPrincipal,
      countersignatureChecker: requireChecker(
        countersignatureChecker,
        'countersignatureChecker',
        'CountersignatureRegistryVerifier',
      ),
      signatureChecker: requireChecker(signatureChecker, 'signatureChecker', 'KeyRegistryVerifier'),
      options: {
        ...(countersignatureRequired === undefined ? {} : { countersignatureRequired }),
        ...(expectedIdentity === undefined ? {} : { expectedIdentity }),
      },
    };
  }
  return {
    anchoredDigest: second,
    ...positional,
    countersignatureChecker: requireChecker(
      positional.countersignatureChecker,
      'countersignatureChecker',
      'CountersignatureRegistryVerifier',
    ),
    signatureChecker: requireChecker(positional.signatureChecker, 'signatureChecker', 'KeyRegistryVerifier'),
  };
}

/**
 * How the verifier reads a-MCP correlation fields, the embedded event, and the governed identity.
 *
 * The defaults (`DEFAULT_ADAPTER`) read a bare, top-level a-MCP event. A caller that seals a-MCP
 * records inside another envelope (e.g. SEP-3004) provides accessors that reach into it, so the
 * verifier can correlate, schema-check, and principal-match the enveloped event without the SDK
 * importing any specific envelope shape.
 */
export interface RecordAdapter {
  /**
   * Extract the correlation key that pairs an attempt with its terminal outcome. `undefined`/`null`
   * means the record names no call and is exempt from correlation - an envelope that seals records
   * which are not tool calls says so here.
   */
  idOf: (event: Record<string, unknown>) => unknown;
  /** True when the record is an attempt, false for a terminal outcome. */
  isAttempt: (event: Record<string, unknown>) => boolean;
  /**
   * Extract the audit session an attempt and its outcome share (§7.2 correlates by `session_id` and
   * `id`). Optional: without it a record is correlated by `idOf` alone.
   */
  sessionOf?: (event: Record<string, unknown>) => unknown;
  /** Extract the embedded a-MCP event that `verifyLedger` schema-checks. */
  eventOf: (event: Record<string, unknown>) => unknown;
  /**
   * Extract the governed identity a record is attributed to, compared against `expectedPrincipal`.
   * Optional: a bare a-MCP event binds no identity (attributing a record to a principal is the
   * envelope's concern, not a-MCP's). A deployment that seals records inside an identity-binding
   * envelope (e.g. SEP-3004, whose protected core carries `principal_id`) reads that identity here.
   * Normalization (e.g. tenant hierarchy) belongs here, so the comparison stays a strict equality.
   */
  principalOf?: (event: Record<string, unknown>) => unknown;
}

/**
 * The sealed event is itself a bare, top-level a-MCP event, binding no governed identity. Frozen so
 * the process-wide default cannot be mutated; spread it to override only what you need:
 * `{ ...DEFAULT_ADAPTER, idOf: (e) => (e.sep3004 as { id: unknown }).id }`.
 */
export const DEFAULT_ADAPTER: RecordAdapter = Object.freeze({
  idOf: (event: Record<string, unknown>) => event[fields.ID],
  isAttempt: (event: Record<string, unknown>) => event[fields.OUTCOME] === Outcome.ATTEMPTED,
  sessionOf: (event: Record<string, unknown>) => event[fields.SESSION_ID],
  eventOf: (event: Record<string, unknown>) => event,
  principalOf: () => undefined,
});

/**
 * The refusals that account for an unsealed attempt's `signer_seq` (§7.2, §11.4): the tool declined to
 * act because the host did not accept, so the attempt it numbered is not in the chain.
 */
const REFUSAL_REASONS: readonly string[] = [reasons.HOST_REJECTED, reasons.HOST_UNAVAILABLE];

/** One operation's correlation key: its audit session and its `id`, compared by type and value (§7.2). */
function operationKey(sessionId: unknown, id: unknown): string {
  return JSON.stringify([typeof sessionId, String(sessionId), typeof id, String(id)]);
}

/**
 * True for an event the per-session procedures apply to (§7.2, §11.4): one of v0.3 or later. An event
 * sealed before v0.3 has no audit session; it is correlated by its `call_id` and left out of the
 * `signer_seq` accounting and replay checks, which its per-key numbering does not fit.
 */
function isSessionScoped(event: Record<string, unknown>): boolean {
  return !isEarlierSpecVersion(event[fields.SPEC_VERSION]);
}

/**
 * A maximal run of `signer_seq` values missing from one key's sequence in one audit session, no value of
 * which a sealed refusal accounts for (§11.4). `first` and `last` are inclusive.
 */
export interface UnaccountedSignerSeq {
  key_id: string;
  session_id: string;
  first: number;
  last: number;
}

/**
 * The values from 0 to the largest in `present` that are not in it, as `[first, last]` runs, computed
 * from the gaps between present values so a value near 2^53 costs one run (§11.4).
 */
function missingRuns(present: ReadonlySet<number>): Array<[number, number]> {
  const runs: Array<[number, number]> = [];
  let next = 0;
  for (const value of [...present].sort((a, b) => a - b)) {
    if (value > next) {
      runs.push([next, value - 1]);
    }
    next = value + 1;
  }
  return runs;
}

/**
 * Run §11.4's accounting over the sealed a-MCP events of one partition.
 *
 * A verifier does not see the events a host rejected, so a rejected attempt leaves its `signer_seq`
 * missing from the sealed sequence; the sealed refusal of that attempt accounts for it. The procedure is
 * pinned so that two verifiers report the same values for one ledger:
 *
 * 1. Per key and session, the missing values are those from 0 to the largest sealed value that are not
 *    sealed.
 * 2. The refusals are the sealed `aborted` outcomes with `host-rejected` or `host-unavailable` to which
 *    no sealed attempt correlates - none with the same `session_id` and `id` sealed before it - in
 *    ascending `signer_seq`.
 * 3. Each refusal accounts for the smallest missing value below its own not yet accounted for.
 * 4. What is left is unaccounted, one entry per maximal run.
 *
 * Events sealed before v0.3, when the sequence was per key, are not numbered this way and are left out.
 *
 * @param events The embedded a-MCP events of the partition's sealed records, in chain order.
 * @returns One entry per maximal run of unaccounted values, per key and session in order of first
 *   appearance, ascending.
 */
export function unaccountedSignerSeq(events: Iterable<unknown>): UnaccountedSignerSeq[] {
  const listed = [...events].filter(
    (event): event is Record<string, unknown> =>
      event !== null && typeof event === 'object' && isSessionScoped(event as Record<string, unknown>),
  );
  // Read in chain order: a refusal is correlated only by an attempt sealed before it (§7.2).
  const sealedAttempts = new Set<string>();
  const groups = new Map<string, { keyId: string; sessionId: string; values: number[]; refusals: number[] }>();
  for (const event of listed) {
    const operation = operationKey(event[fields.SESSION_ID], event[fields.ID]);
    const refusal =
      event[fields.OUTCOME] === Outcome.ABORTED &&
      REFUSAL_REASONS.includes(String(event[fields.REASON])) &&
      !sealedAttempts.has(operation);
    if (event[fields.OUTCOME] === Outcome.ATTEMPTED) {
      sealedAttempts.add(operation);
    }
    const keyId = event[fields.KEY_ID];
    const sessionId = event[fields.SESSION_ID];
    const signerSeq = event[fields.SIGNER_SEQ];
    if (
      typeof keyId === 'string' &&
      typeof sessionId === 'string' &&
      typeof signerSeq === 'number' &&
      Number.isSafeInteger(signerSeq) &&
      signerSeq >= 0
    ) {
      const group = JSON.stringify([keyId, sessionId]);
      const entry = groups.get(group) ?? { keyId, sessionId, values: [], refusals: [] };
      entry.values.push(signerSeq);
      if (refusal) {
        entry.refusals.push(signerSeq);
      }
      groups.set(group, entry);
    }
  }
  const unaccounted: UnaccountedSignerSeq[] = [];
  for (const { keyId, sessionId, values, refusals } of groups.values()) {
    const missing = missingRuns(new Set(values));
    // The smallest value still missing below a refusal is always the first of the first run.
    for (const refusal of refusals.sort((a, b) => a - b)) {
      const run = missing[0];
      if (run === undefined || run[0] >= refusal) {
        continue;
      }
      run[0] += 1;
      if (run[0] > run[1]) {
        missing.shift();
      }
    }
    for (const [first, last] of missing) {
      unaccounted.push({ key_id: keyId, session_id: sessionId, first, last });
    }
  }
  return unaccounted;
}

/**
 * Verify chain integrity alone, independent of the event vocabulary (§8.3).
 *
 * Checks sequence order, previous-hash linkage, record-hash recomputation, attempt/outcome
 * correlation, the principal binding (when `expectedPrincipal` is set), and (with `anchoredDigest`)
 * the anchored-digest compare. This is the tamper-evidence guarantee for any events sealed through
 * `Ledger`; it never inspects the event schema.
 *
 * @param records The sealed records in append order (from a `Ledger` or reloaded storage).
 * @param anchoredDigest An out-of-band anchored tail digest to compare against, if available (§8.3).
 * @param adapter How to read the correlation key and attempt flag from each sealed record. Defaults to
 *   a bare top-level a-MCP event; inject accessors to correlate records sealed inside an envelope. A
 *   record whose `idOf` is `undefined`/`null` names no call and is exempt from attempt/outcome correlation.
 * @param expectedPrincipal When set, every record's `adapter.principalOf` is compared against it as a
 *   value (§11.4); a mismatch or an absent identity is flagged `principal-mismatch`. This is an SDK
 *   check, not an a-MCP anomaly: it detects a transplant only for records sealed in an identity-binding
 *   envelope. Omit to skip.
 * @param countersignatureChecker Resolves a `host_key_id` and verifies a countersignature over the
 *   canonical host-assigned fields and `log_id` (§7.1). A record carrying none of the triple is
 *   uncountersigned, which is a state and not an anomaly (§5.2); one whose signature fails, or that
 *   carries part of the triple, is `host-signature-invalid`. Without a checker, records that do carry one
 *   are counted in `unchecked` (§11.4).
 * @param signatureChecker Verifies a sealed Level-2 event's own `signature` against the key registry.
 *   Without one, records that carry Level-2 fields are counted in `unchecked` rather than verified.
 * @param options The out-of-band requirements: whether the chain must be countersigned, and the identity
 *   the partition is expected to hold where the deployment binds it by the countersignature (§10.10).
 * @returns A report; `ok` is true only when no issues were found.
 */
export function verifyChain(records: SealedRecord[], options?: VerifyLedgerOptions): VerifyReport;
export function verifyChain(
  records: SealedRecord[],
  anchoredDigest?: string,
  adapter?: RecordAdapter,
  expectedPrincipal?: unknown,
  countersignatureChecker?: CountersignatureChecker,
  signatureChecker?: SignatureChecker,
  options?: VerifyOptions,
): VerifyReport;
export function verifyChain(
  records: SealedRecord[],
  second?: string | VerifyLedgerOptions,
  positionalAdapter: RecordAdapter = DEFAULT_ADAPTER,
  positionalPrincipal?: unknown,
  positionalCountersignatureChecker?: CountersignatureChecker,
  positionalSignatureChecker?: SignatureChecker,
  positionalOptions: VerifyOptions = {},
): VerifyReport {
  const { anchoredDigest, adapter, expectedPrincipal, countersignatureChecker, signatureChecker, options } =
    resolveInputs(second, {
      adapter: positionalAdapter,
      expectedPrincipal: positionalPrincipal,
      countersignatureChecker: positionalCountersignatureChecker,
      signatureChecker: positionalSignatureChecker,
      options: positionalOptions,
    });
  // §11.4 compares the expectation and the bound identity as values. A structured expectation would
  // be compared by identity here and by value in the Python port, so two conforming verifiers would
  // return opposite verdicts on one ledger; §10.10 binds a single primitive, so it is refused.
  if (
    expectedPrincipal !== undefined &&
    (typeof expectedPrincipal === 'object' || typeof expectedPrincipal === 'function')
  ) {
    throw new Error(
      'the expected principal is compared as a value; reduce a structured identity to a primitive (§10.10, §11.4)',
    );
  }
  const issues: VerifyIssue[] = [];
  const attempted = new Set<string>();
  const numbered = new Map<string, number>();
  let prevRecomputed = GENESIS_HASH;
  let countersignatureUnchecked = false;
  let l2Unchecked = false;

  // Per-record, fail-closed (an absent identity !== the expected one): a valid chain transplanted under
  // the wrong principal passes hash + chain but fails this.
  const checkPrincipal = (record: SealedRecord): void => {
    if (expectedPrincipal !== undefined && adapter.principalOf?.(record.event) !== expectedPrincipal) {
      issues.push({
        seq: record.seq,
        kind: PRINCIPAL_MISMATCH,
        detail: `record principal does not match expected ${String(expectedPrincipal)}`,
      });
    }
  };

  // Countersignature determination and identity matching (§11.4). The signature is verified only over a
  // record whose hash was recomputed: over a stored hash the event does not produce, it confirms nothing.
  const checkCountersignature = (record: SealedRecord, hashable: boolean): void => {
    const present = [record.host_signature, record.host_key_id, record.log_id].filter(
      (value) => value !== undefined,
    ).length;
    if (present === 0 && options.countersignatureRequired === true) {
      issues.push({
        seq: record.seq,
        kind: reasons.HOST_SIGNATURE_INVALID,
        detail: 'the record is not countersigned, and the chain must be',
      });
    } else if (present !== 0 && present !== 3) {
      // §7.1 keeps the three together, and the response schema enforces it on the wire - but a stored
      // record is not schema-checked, so a partial triple reaches a verifier and establishes nothing.
      issues.push({
        seq: record.seq,
        kind: reasons.HOST_SIGNATURE_INVALID,
        detail: 'host_signature, host_key_id, and log_id must appear together or not at all',
      });
    } else if (
      hashable &&
      record.host_signature !== undefined &&
      record.host_key_id !== undefined &&
      record.log_id !== undefined
    ) {
      if (countersignatureChecker === undefined) {
        countersignatureUnchecked = true;
      } else {
        const payload = countersignaturePayload(
          record.seq,
          record.host_ts,
          record.log_id,
          record.previous_hash,
          record.record_hash,
        );
        if (!countersignatureChecker(record.host_key_id, record.host_signature, payload)) {
          issues.push({
            seq: record.seq,
            kind: reasons.HOST_SIGNATURE_INVALID,
            detail: `countersignature does not verify for host_key_id ${record.host_key_id}`,
          });
        }
      }
    }

    // §10.10's first construction: the countersignature's `log_id`, under the host's key, binds the
    // record to its partition. A record without the full triple carries no binding, so it cannot be
    // shown to belong where it was found.
    const expected = options.expectedIdentity;
    if (expected === undefined) {
      return;
    }
    let mismatch: string | null = null;
    if (present !== 3) {
      mismatch = 'the record is not countersigned, so it binds no identity';
    } else if (record.log_id !== expected.logId) {
      mismatch = `log_id ${String(record.log_id)} is not the expected ${expected.logId}`;
    } else if (!expected.hostKeyIds.has(String(record.host_key_id))) {
      mismatch = `host_key_id ${String(record.host_key_id)} is not one the partition's host countersigns under`;
    }
    if (mismatch !== null) {
      issues.push({ seq: record.seq, kind: PRINCIPAL_MISMATCH, detail: mismatch });
    }
  };

  for (let index = 0; index < records.length; index += 1) {
    const record = records[index];
    if (record === undefined) {
      continue;
    }
    const event = record.event;

    if (record.seq !== index) {
      // Out-of-order is rolled up to seq-gap (Tier-1); the direction is a Tier-2 detail.
      issues.push({ seq: record.seq, kind: SEQ_GAP, detail: `expected seq ${index}, got ${record.seq}` });
    }

    // Recompute from the record body against the recomputed prior link, not the stored one, so a
    // mutation cannot hide behind its own stored hashes. A broken previous_hash link surfaces as a
    // record-hash-mismatch (Tier-1); the "link" detail distinguishes it locally.
    let recomputed: string;
    try {
      recomputed = computeRecordHash(event, record.seq, record.host_ts, prevRecomputed);
    } catch (error) {
      if (!(error instanceof CanonicalizationError)) {
        throw error;
      }
      // §11.4: a record that cannot be canonicalized is a finding, and the chain is checked on either
      // side of it - the next record links to the hash this one stored. Its identity is still compared:
      // a transplanted record must not escape the identity check by also being malformed.
      issues.push({ seq: record.seq, kind: reasons.SCHEMA_INVALID, detail: error.message });
      checkPrincipal(record);
      checkCountersignature(record, false);
      prevRecomputed = record.record_hash;
      continue;
    }
    if (record.previous_hash !== prevRecomputed) {
      issues.push({
        seq: record.seq,
        kind: RECORD_HASH_MISMATCH,
        detail: 'previous_hash does not link to prior record',
      });
    }
    if (record.record_hash !== recomputed) {
      issues.push({ seq: record.seq, kind: RECORD_HASH_MISMATCH, detail: 'stored record_hash != recomputed' });
    }

    // A record that names no call is not one half of a pair. An envelope may seal records that are not
    // tool calls at all - a prompt, a model's reasoning, a turn boundary - and their adapter returns
    // undefined/null here to say so. Correlating them would report every one as an outcome missing its
    // attempt, the check crying wolf on a chain that is intact.
    // An aborted outcome with no attempt before it is a sealed refusal, not an orphan (§7.2).
    const inner = adapter.eventOf(event) as Record<string, unknown> | null;
    const refusal = inner !== null && typeof inner === 'object' && inner[fields.OUTCOME] === Outcome.ABORTED;
    const eventId = adapter.idOf(event);
    if (eventId !== undefined && eventId !== null) {
      const earlier = inner !== null && typeof inner === 'object' && !isSessionScoped(inner);
      const operation = earlier
        ? JSON.stringify(['call_id', String(inner[fields.CALL_ID]), String(eventId)])
        : operationKey(adapter.sessionOf?.(event), eventId);
      if (adapter.isAttempt(event)) {
        attempted.add(operation);
      } else if (!attempted.has(operation) && !refusal) {
        issues.push({
          seq: record.seq,
          kind: ORPHANED_OUTCOME,
          detail: `terminal outcome with no matching attempt in its session, id=${String(eventId)}`,
        });
      }
    }

    // §11.4: two sealed records sharing one `signer_seq` for one key and session.
    if (inner !== null && typeof inner === 'object' && isSessionScoped(inner)) {
      const keyId = inner[fields.KEY_ID];
      const sessionId = inner[fields.SESSION_ID];
      const signerSeq = inner[fields.SIGNER_SEQ];
      if (typeof keyId === 'string' && typeof sessionId === 'string' && typeof signerSeq === 'number') {
        const numberKey = JSON.stringify([keyId, sessionId, signerSeq]);
        const first = numbered.get(numberKey);
        if (first === undefined) {
          numbered.set(numberKey, record.seq);
        } else {
          issues.push({
            seq: record.seq,
            kind: REPLAY_DETECTED,
            detail: `signer_seq ${signerSeq} of key ${keyId} in session ${sessionId} is also sealed at seq ${first}`,
          });
        }
      }
    }

    checkPrincipal(record);

    // §11.4 names the Level-2 re-verification it did not perform as well: this verifier checks the
    // chain, not the event signatures (§10.6 makes that optional), and an unchecked signature must not
    // read as a verified one.
    // Read through the adapter: a record sealed inside an envelope (e.g. SEP-3004) keeps the a-MCP
    // event, and its signature, inside it, so a top-level lookup would miss exactly the deployment
    // §10.10 recommends and report a complete verification of signatures nobody checked.
    const signed = inner !== null && typeof inner === 'object' && inner[fields.SIGNATURE] !== undefined;
    if (signed && signatureChecker === undefined) {
      l2Unchecked = true;
    } else if (signed && signatureChecker !== undefined && inner !== null && !signatureChecker(inner)) {
      issues.push({ seq: record.seq, kind: reasons.SIGNATURE_INVALID, detail: 'event signature does not verify' });
    }

    checkCountersignature(record, true);

    prevRecomputed = recomputed;
  }

  // §11.4: a `signer_seq` missing within one key's sequence in one session, and not accounted for by a
  // sealed refusal, may mark a suppressed event. It is computable from the records alone - no registry -
  // so a verifier that omits it is silently dropping the one suppression signal the ledger carries.
  for (const gap of unaccountedSignerSeq(records.map((record) => adapter.eventOf(record.event)))) {
    issues.push({
      seq: null,
      kind: reasons.SIGNER_SEQ_GAP,
      detail: `signer_seq ${gap.first}..${gap.last} of key ${gap.key_id} in session ${gap.session_id} is missing`,
    });
  }

  const computedDigest = prevRecomputed;
  if (anchoredDigest !== undefined && anchoredDigest !== computedDigest) {
    issues.push({
      seq: null,
      kind: DIGEST_MISMATCH,
      detail: `anchored ${anchoredDigest} != computed ${computedDigest}`,
    });
  }

  const unchecked: string[] = [];
  if (countersignatureUnchecked) {
    unchecked.push('countersignature');
  }
  if (l2Unchecked) {
    unchecked.push('level-2-signature');
  }
  return {
    ok: issues.length === 0,
    count: records.length,
    computedDigest,
    issues,
    unchecked,
    complete: issues.length === 0 && unchecked.length === 0,
  };
}

/**
 * Verify chain integrity and A-MCP event-schema conformance (§8.3 + §7.1).
 *
 * `verifyChain` followed by a per-record schema check: a record whose embedded event is not a valid
 * A-MCP event is flagged `schema-invalid`, as a finding - it never throws on a malformed record. A record
 * sealed under an earlier published `spec_version` is validated against that version's schema and its
 * signature decoded as that version encoded it (§11.4). For valid A-MCP events the result is identical
 * to `verifyChain`.
 *
 * @param records The sealed records in append order (from a `Ledger` or reloaded storage).
 * @param anchoredDigest An out-of-band anchored tail digest to compare against, if available (§8.3).
 * @param adapter How to read the correlation fields and extract the embedded a-MCP event. Defaults to
 *   a bare top-level a-MCP event; inject `eventOf` to schema-check an event sealed inside an envelope.
 * @param expectedPrincipal When set, each record's `adapter.principalOf` is compared against it, else
 *   `principal-mismatch` (an SDK check); forwarded to `verifyChain`.
 * @param options The out-of-band requirements (§10.10, §11.4); forwarded to `verifyChain`.
 * @returns A report; `ok` is true only when no issues were found.
 */
export function verifyLedger(records: SealedRecord[], options?: VerifyLedgerOptions): VerifyReport;
export function verifyLedger(
  records: SealedRecord[],
  anchoredDigest?: string,
  adapter?: RecordAdapter,
  expectedPrincipal?: unknown,
  countersignatureChecker?: CountersignatureChecker,
  signatureChecker?: SignatureChecker,
  options?: VerifyOptions,
): VerifyReport;
export function verifyLedger(
  records: SealedRecord[],
  second?: string | VerifyLedgerOptions,
  positionalAdapter: RecordAdapter = DEFAULT_ADAPTER,
  positionalPrincipal?: unknown,
  positionalCountersignatureChecker?: CountersignatureChecker,
  positionalSignatureChecker?: SignatureChecker,
  positionalOptions: VerifyOptions = {},
): VerifyReport {
  const { anchoredDigest, adapter, expectedPrincipal, countersignatureChecker, signatureChecker, options } =
    resolveInputs(second, {
      adapter: positionalAdapter,
      expectedPrincipal: positionalPrincipal,
      countersignatureChecker: positionalCountersignatureChecker,
      signatureChecker: positionalSignatureChecker,
      options: positionalOptions,
    });
  const report = verifyChain(records, {
    anchoredDigest,
    adapter,
    expectedPrincipal,
    countersignatureChecker,
    signatureChecker,
    ...options,
  });
  const reported = new Set(report.issues.filter((issue) => issue.kind === SCHEMA_INVALID).map((issue) => issue.seq));
  const schemaIssues: VerifyIssue[] = [];
  // A chain's versions do not go backwards (§11.4): no conforming host seals a record of an earlier
  // version after one of a later version, so only a rewrite places it there.
  let latest = -1;
  for (const record of records) {
    const inner = adapter.eventOf(record.event);
    const version =
      inner !== null && typeof inner === 'object' ? (inner as Record<string, unknown>)[fields.SPEC_VERSION] : undefined;
    const rank = (KNOWN_SPEC_VERSIONS as readonly unknown[]).indexOf(version);
    const regressed = rank !== -1 && rank < latest;
    latest = Math.max(latest, rank);
    const structural =
      firstSealedValidationError(inner) ??
      (regressed ? `spec_version ${String(version)} is sealed after a record of a later version` : null);
    if (structural !== null && !reported.has(record.seq)) {
      schemaIssues.push({ seq: record.seq, kind: reasons.SCHEMA_INVALID, detail: structural });
    }
  }
  if (schemaIssues.length === 0) {
    return report;
  }
  return {
    ok: false,
    count: report.count,
    computedDigest: report.computedDigest,
    issues: [...report.issues, ...schemaIssues],
    unchecked: report.unchecked,
    complete: false,
  };
}
