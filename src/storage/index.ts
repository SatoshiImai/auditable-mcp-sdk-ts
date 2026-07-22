/**
 * Durable-ledger persistence: the repository contract and an in-memory implementation.
 *
 * The SDK defines `LedgerRepository`; integrators implement it over their own backend. No cloud SDK
 * enters this package.
 */

export { InMemoryLedgerRepository } from './memory';
export { type LedgerRepository, RepositoryError } from './repository';
