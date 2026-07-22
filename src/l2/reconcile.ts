/**
 * Reconciliation: boundary-observed egress vs self-reported events (§7.5, §10.2).
 *
 * Cryptographic checks catch falsified or lost records, but not an egress a tool never reports at all
 * (suppression by omission). Comparing independent boundary observations (e.g. from a gateway)
 * against the tool's self-reported audit stream detects that omission — the one class of misbehaviour
 * signatures cannot reach.
 */

import * as fields from '../fields';
import type { SealedRecord } from '../ledger';

// Reconcile anomaly kind, local to this module.
export const UNREPORTED_EGRESS = 'unreported-egress';

/** An egress the host observed independently at the boundary. */
export interface EgressObservation {
  callId: string;
  destination: string;
}

/** A mismatch between self-reports and boundary observations. */
export interface ReconcileAnomaly {
  callId: string;
  kind: string;
  destination: string;
  detail: string;
}

/** Records egress facts the host sees independently (e.g. a network gateway). */
export class BoundaryObserver {
  #observations: EgressObservation[] = [];

  /** Record an observed egress for a call. */
  observeEgress(callId: string, destination: string): void {
    this.#observations.push({ callId, destination });
  }

  /** Return the observations recorded for a given call. */
  forCall(callId: string): EgressObservation[] {
    return this.#observations.filter((observation) => observation.callId === callId);
  }
}

function targetRef(record: SealedRecord): unknown {
  const target = record.event[fields.TARGET_RESOURCE];
  return target !== null && typeof target === 'object' ? (target as Record<string, unknown>)[fields.REF] : undefined;
}

/**
 * Compare self-reported egress against boundary observations for one call.
 *
 * Detects suppression by omission only (§7.5): an egress the boundary observed but the tool never
 * self-reported. The reverse (self-reported but boundary-unobserved) is not an anomaly — a boundary
 * is not omniscient, so its blind spots are not tool misbehaviour.
 *
 * @returns The unreported-egress anomalies, ordered by destination for determinism.
 */
export function reconcile(
  records: SealedRecord[],
  observations: EgressObservation[],
  callId: string,
): ReconcileAnomaly[] {
  const reported = new Set<unknown>();
  for (const record of records) {
    if (record.event[fields.CALL_ID] === callId && record.event[fields.EGRESS]) {
      reported.add(targetRef(record));
    }
  }

  const observed = new Set<string>();
  for (const observation of observations) {
    if (observation.callId === callId) {
      observed.add(observation.destination);
    }
  }

  return [...observed]
    .filter((destination) => !reported.has(destination))
    .sort()
    .map((destination) => ({
      callId,
      kind: UNREPORTED_EGRESS,
      destination,
      detail: 'observed egress with no self-report',
    }));
}
