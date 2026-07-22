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

function relativeJsonFiles(base: string): string[] {
  const files: string[] = [];
  for (const subdir of VENDORED_SUBDIRS) {
    for (const path of walkJson(join(base, subdir))) {
      files.push(relative(base, path));
    }
  }
  return files.sort();
}

function check(source: string): boolean {
  const sourceFiles = new Set(relativeJsonFiles(source));
  const vendoredFiles = new Set(relativeJsonFiles(VENDORED_SPEC_DIR));
  let ok = true;

  for (const rel of [...sourceFiles].filter((f) => !vendoredFiles.has(f)).sort()) {
    console.error(`missing in vendored spec: ${rel}`);
    ok = false;
  }
  for (const rel of [...vendoredFiles].filter((f) => !sourceFiles.has(f)).sort()) {
    console.error(`stale file in vendored spec (not in source): ${rel}`);
    ok = false;
  }
  for (const rel of [...sourceFiles].filter((f) => vendoredFiles.has(f)).sort()) {
    const a = readFileSync(join(source, rel));
    const b = readFileSync(join(VENDORED_SPEC_DIR, rel));
    if (!a.equals(b)) {
      console.error(`content drift: ${rel}`);
      ok = false;
    }
  }

  if (ok) {
    console.log(`vendored spec is in sync (${sourceFiles.size} files)`);
  }
  return ok;
}

function sync(source: string): number {
  let copied = 0;
  for (const subdir of VENDORED_SUBDIRS) {
    const srcDir = join(source, subdir);
    const dstDir = join(VENDORED_SPEC_DIR, subdir);
    if (existsSync(dstDir)) {
      rmSync(dstDir, { recursive: true, force: true });
    }
    for (const srcPath of walkJson(srcDir)) {
      const dstPath = join(dstDir, relative(srcDir, srcPath));
      mkdirSync(dirname(dstPath), { recursive: true });
      writeFileSync(dstPath, readFileSync(srcPath));
      copied += 1;
    }
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
