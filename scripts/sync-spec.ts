/**
 * Vendor the normative Auditable MCP spec artifacts into this repository.
 *
 * The JSON Schema (`schema/`) and golden conformance vectors (`vectors/`) have a single source of
 * truth in the separate `mcp-audit-extension` spec repository. This SDK is published standalone, so
 * those artifacts are vendored under `spec/` and this script keeps the copy honest — byte-for-byte
 * identical to the Python SDK's copy so both languages reproduce the same vectors.
 *
 * Usage:
 *   tsx scripts/sync-spec.ts            # copy source -> vendored spec/
 *   tsx scripts/sync-spec.ts --check    # verify vendored == source (CI drift gate); no writes
 *
 * The source resolves in this order: `--source` argument, `AMCP_SPEC_SRC` env var, then the default
 * sibling checkout `../mcp-audit-extension/spec`.
 */

import { existsSync, mkdirSync, readdirSync, readFileSync, rmSync, statSync, writeFileSync } from 'node:fs';
import { dirname, join, relative, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

// Subdirectories of the spec that are normative and must be reproduced byte-for-byte.
const VENDORED_SUBDIRS = ['schema', 'vectors'] as const;

const REPO_ROOT = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const VENDORED_SPEC_DIR = join(REPO_ROOT, 'spec');
const VENDORED_INTEROP_DIR = join(REPO_ROOT, 'interop');
/**
 * Vendored beside the spec, from the same source repository, but not part of it: the interop vectors
 * pin what the two SDK ports agree on where §5.1 deliberately says nothing, so an implementation
 * that ignores them is still conformant.
 */
const INTEROP_SUBDIR = 'interop';

/** The (source, vendored) directory pairs this script keeps in step. */
function roots(source: string): { src: string; dst: string }[] {
  return [
    ...VENDORED_SUBDIRS.map((subdir) => ({ src: join(source, subdir), dst: join(VENDORED_SPEC_DIR, subdir) })),
    { src: join(source, '..', INTEROP_SUBDIR), dst: VENDORED_INTEROP_DIR },
  ];
}

/** Every (source file, vendored file) pair the roots hold, in a stable order. */
function pairs(source: string): { src: string; dst: string }[] {
  const found: { src: string; dst: string }[] = [];
  for (const { src, dst } of roots(source)) {
    for (const srcPath of walkJson(src).sort()) {
      found.push({ src: srcPath, dst: join(dst, relative(src, srcPath)) });
    }
  }
  return found;
}
const DEFAULT_SOURCE = join(REPO_ROOT, '..', 'mcp-audit-extension', 'spec');

function resolveSource(cliSource: string | undefined): string {
  const raw = cliSource ?? process.env.AMCP_SPEC_SRC ?? DEFAULT_SOURCE;
  const source = resolve(raw);
  if (!existsSync(source) || !statSync(source).isDirectory()) {
    throw new Error(`spec source directory not found: ${source}`);
  }
  return source;
}

function walkJson(root: string): string[] {
  if (!existsSync(root) || !statSync(root).isDirectory()) {
    return [];
  }
  const out: string[] = [];
  for (const entry of readdirSync(root, { withFileTypes: true })) {
    const full = join(root, entry.name);
    if (entry.isDirectory()) {
      out.push(...walkJson(full));
    } else if (entry.isFile() && entry.name.endsWith('.json')) {
      out.push(full);
    }
  }
  return out;
}

function check(source: string): boolean {
  const expected = pairs(source);
  const known = new Set(expected.map(({ dst }) => dst));
  let ok = true;

  for (const { src, dst } of expected) {
    if (!existsSync(dst)) {
      console.error(`missing in vendored copy: ${relative(REPO_ROOT, dst)}`);
      ok = false;
    } else if (!readFileSync(src).equals(readFileSync(dst))) {
      console.error(`content drift: ${relative(REPO_ROOT, dst)}`);
      ok = false;
    }
  }
  for (const { dst } of roots(source)) {
    for (const stale of walkJson(dst)) {
      if (!known.has(stale)) {
        console.error(`stale file in vendored copy (not in source): ${relative(REPO_ROOT, stale)}`);
        ok = false;
      }
    }
  }

  if (ok) {
    console.log(`vendored copies are in sync (${expected.length} files)`);
  }
  return ok;
}

function sync(source: string): number {
  for (const { dst } of roots(source)) {
    if (existsSync(dst)) {
      rmSync(dst, { recursive: true, force: true });
    }
  }
  let copied = 0;
  for (const { src, dst } of pairs(source)) {
    mkdirSync(dirname(dst), { recursive: true });
    writeFileSync(dst, readFileSync(src));
    copied += 1;
  }
  console.log(`vendored ${copied} files from ${source}`);
  return copied;
}

function main(argv: string[]): number {
  const checkOnly = argv.includes('--check');
  const sourceIdx = argv.indexOf('--source');
  const cliSource = sourceIdx >= 0 ? argv[sourceIdx + 1] : undefined;

  const source = resolveSource(cliSource);
  if (checkOnly) {
    return check(source) ? 0 : 1;
  }
  sync(source);
  return 0;
}

process.exit(main(process.argv.slice(2)));
