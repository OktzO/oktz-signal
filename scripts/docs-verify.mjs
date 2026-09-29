// docs:verify — execute the documentation instead of reading it.
//
// Prose about an API rots silently: the signature in the paragraph stops
// matching the function, the example keeps "working" because nobody ran it,
// and the README starts describing a package that no longer exists. This
// script removes that failure mode by making every code block in the
// documentation an input to a test.
//
// What it does, for README.md, CHANGELOG.md and every docs/**/*.md:
//
//   1. Extracts every fenced code block, with its info string.
//   2. Classifies it. A block is RUNNABLE when its info string names a
//      JavaScript dialect (`js`, `javascript`, `mjs`, `node`). A block is
//      SKIPPED only when its info string carries the literal token
//      `nonrunnable`. Anything else — an untagged fence, `bash`, `rust`,
//      `json`, a typo like `jss` — is a hard error: the default is "run it",
//      so a block that cannot run has to say so out loud.
//   3. Writes each runnable block to a temporary .mjs file next to the .md it
//      came from, so the relative specifiers a reader would type
//      (`../index.js`) resolve exactly as written, and runs it with node.
//   4. Also runs every examples/**/*.mjs the same way.
//   5. Prints each block's stdout indented under its source location, so a
//      reader sees what the example actually did.
//
// A runnable block is held to the same bar as a test: it must exit 0. There is
// no "warn and continue" path, because a failing example that does not fail the
// build is the exact problem this script exists to remove.
//
// Usage:
//   node scripts/docs-verify.mjs            run everything
//   node scripts/docs-verify.mjs --quiet    only report failures and the summary
//   node scripts/docs-verify.mjs <path>...  verify specific files or directories

import { spawnSync } from 'node:child_process';
import { mkdirSync, readFileSync, readdirSync, rmSync, statSync, writeFileSync } from 'node:fs';
import { basename, dirname, extname, join, relative, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const root = resolve(dirname(fileURLToPath(import.meta.url)), '..');

// Info strings that mean "this is JavaScript, run it".
const RUNNABLE = new Set(['js', 'javascript', 'mjs', 'node']);
// The only way to opt a block out of execution. Deliberately ugly: it shows up
// in the rendered source of the document, so a reader can see which snippets
// are pictures and which are real.
const SKIP_TOKEN = 'nonrunnable';

const args = process.argv.slice(2);
const quiet = args.includes('--quiet');
const targets = args.filter((a) => !a.startsWith('-'));
const DEFAULT_SOURCES = ['README.md', 'CHANGELOG.md', 'docs', 'examples'];

const walk = (path, out = []) => {
  let st;
  try {
    st = statSync(path);
  } catch {
    return out;
  }
  if (st.isDirectory()) {
    for (const entry of readdirSync(path).sort()) walk(join(path, entry), out);
  } else {
    out.push(path);
  }
  return out;
};

// Line-based fence scan. A regex over the whole file cannot tell an opening
// fence from a closing one that happens to carry an info string, and it cannot
// report a line number without a second pass; walking lines once does both and
// keeps the line numbers the error messages quote. ``` fences only — ~~~ is not
// used anywhere in this repo, and accepting it would double the ways a block
// can hide from the check.
const extract = (file) => {
  const lines = readFileSync(file, 'utf8').split('\n');
  const blocks = [];
  let open = null;
  lines.forEach((line, i) => {
    const fence = /^```(.*)$/.exec(line);
    if (!fence) {
      if (open) open.lines.push(line);
      return;
    }
    if (open) {
      open = null; // closing fence; info string on a closing fence is ignored
      return;
    }
    open = { info: fence[1].trim(), line: i + 1, lines: [] };
    blocks.push(open);
  });
  if (open) blocks.push({ ...open, unterminated: true });
  return blocks.map(({ info, line, lines: body, unterminated }) => ({
    info,
    line,
    unterminated,
    body: `${body.join('\n').replace(/^\n+|\n+$/g, '')}\n`,
  }));
};

const classify = (info) => {
  if (info.split(/\s+/).includes(SKIP_TOKEN)) return 'skip';
  return RUNNABLE.has(info) ? 'run' : 'error';
};

const indent = (text) => text.split('\n').map((l) => (l ? `      │ ${l}` : '      │')).join('\n');

const runNode = (file) =>
  spawnSync(process.execPath, [file], { cwd: root, encoding: 'utf8', timeout: 120_000 });

let ran = 0;
let skipped = 0;
let examples = 0;
const failures = [];
const notes = [];

const say = (line) => {
  if (!quiet) process.stdout.write(`${line}\n`);
};

const report = (ok, label, detail) => {
  if (ok) return true;
  failures.push({ label, detail });
  return false;
};

// --- markdown code blocks ----------------------------------------------------

const markdownFiles = (targets.length ? targets : DEFAULT_SOURCES)
  .flatMap((t) => walk(resolve(root, t)))
  .filter((f) => extname(f) === '.md');

if (markdownFiles.length === 0) {
  process.stderr.write('docs:verify found no markdown to check — pass a path\n');
  process.exit(1);
}

for (const file of markdownFiles) {
  const rel = relative(root, file);
  const blocks = extract(file);
  for (const block of blocks) {
    const kind = classify(block.info);
    const label = `${rel}:${block.line}`;
    if (kind === 'skip') {
      skipped += 1;
      notes.push(`${label}  skipped (marked nonrunnable)`);
      continue;
    }
    if (block.unterminated) {
      report(false, label, `the fence opened here is never closed with a bare \`\`\` line`);
      continue;
    }
    if (block.info === '') {
      report(
        false,
        label,
        'unmarked code block with an empty info string. ' +
          `Tag it \`${[...RUNNABLE][0]}\` if it is JavaScript, or \`\`\`js ${SKIP_TOKEN}\`\`\` ` +
          'if it is illustrative — an untagged fence is neither.',
      );
      continue;
    }
    if (kind === 'error') {
      report(
        false,
        label,
        `unmarked code block with info string ${JSON.stringify(block.info)}. ` +
          `Tag it \`${[...RUNNABLE][0]}\` if it is JavaScript, or \`\`\`js ${SKIP_TOKEN}\`\`\` ` +
          'if it is illustrative — a block that is neither is a rot vector.',
      );
      continue;
    }

    // Same directory as the .md, so `../index.js` resolves the way a reader
    // running the file would see it. Dot-prefixed so a stray run never looks
    // like a real example.
    const tmp = join(dirname(file), `.docs-verify.${basename(file, '.md')}.${block.line}.mjs`);
    writeFileSync(tmp, block.body, 'utf8');
    let result;
    try {
      result = runNode(tmp);
    } finally {
      rmSync(tmp, { force: true });
    }
    ran += 1;
    const ok = result.status === 0;
    say(`  ${ok ? 'run ' : 'FAIL'}  ${label}`);
    if (ok) {
      if (result.stdout && result.stdout.trim()) say(indent(result.stdout.trimEnd()));
    } else {
      report(false, label, `${result.stdout ?? ''}${result.stderr ?? ''}`.trim() || 'no output');
    }
  }
}

// --- examples/ ---------------------------------------------------------------

const exampleDir = resolve(root, 'examples');
if (!targets.length || targets.some((t) => resolve(root, t).startsWith(exampleDir))) {
  mkdirSync(exampleDir, { recursive: true });
  for (const file of walk(exampleDir)) {
    if (extname(file) !== '.mjs') continue;
    examples += 1;
    const result = runNode(file);
    const rel = relative(root, file);
    const ok = result.status === 0;
    say(`  ${ok ? 'run ' : 'FAIL'}  ${rel}`);
    if (ok) {
      if (result.stdout && result.stdout.trim()) say(indent(result.stdout.trimEnd()));
    } else {
      report(false, rel, `${result.stdout ?? ''}${result.stderr ?? ''}`.trim() || 'no output');
    }
  }
}

// --- summary -----------------------------------------------------------------

process.stdout.write('\n');
if (!quiet) {
  for (const note of notes) process.stdout.write(`  note  ${note}\n`);
  if (notes.length) process.stdout.write('\n');
}
process.stdout.write(
  `docs:verify  ${ran} code block(s) executed, ${examples} example(s) executed, ` +
    `${skipped} marked nonrunnable, ${failures.length} failure(s)\n`,
);

if (failures.length) {
  process.stderr.write('\n');
  for (const { label, detail } of failures) {
    process.stderr.write(`FAIL ${label}\n${indent(detail)}\n\n`);
  }
  process.exit(1);
}
