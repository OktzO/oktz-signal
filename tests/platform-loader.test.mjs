import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import { cpSync, mkdtempSync, readFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join } from 'node:path';
import test from 'node:test';
import { fileURLToPath } from 'node:url';
import { runInNewContext } from 'node:vm';
import { native } from '../index.js';

const packageRoot = dirname(fileURLToPath(import.meta.url));
const root = join(packageRoot, '..');

test('loads native module through platform loader', () => {
  assert.equal(typeof native.curveSign, 'function');
  assert.equal(typeof native.ratchetEncrypt, 'function');
  assert.equal(native.default, native);
});

test('packed package loads native module from optional platform package', () => {
  const workspace = mkdtempSync(join(tmpdir(), 'oktz-signal-'));
  const platformDir = join(root, 'npm', 'linux-x64-gnu');
  const platformBinary = join(platformDir, 'signal.linux-x64-gnu.node');
  let mainTarball;
  let platformTarball;

  try {
    const [{ filename: mainFilename }] = JSON.parse(execFileSync('npm', ['pack', '--json'], { cwd: root }));
    cpSync(join(root, 'native', 'signal', 'signal.linux-x64-gnu.node'), platformBinary);
    const [{ filename: platformFilename }] = JSON.parse(execFileSync('npm', ['pack', '--json'], { cwd: platformDir }));
    mainTarball = join(root, mainFilename);
    platformTarball = join(platformDir, platformFilename);
    execFileSync('npm', ['install', '--ignore-scripts', '--offline', '--no-audit', '--no-fund', mainTarball, platformTarball], { cwd: workspace });

    const output = execFileSync(process.execPath, ['--input-type=module', '--eval', "import { native } from 'oktz-signal'; console.log(typeof native.curveSign, native.default === native)"], { cwd: workspace, encoding: 'utf8' });
    assert.equal(output.trim(), 'function true');
  } finally {
    rmSync(workspace, { force: true, recursive: true });
    if (mainTarball) rmSync(mainTarball, { force: true });
    if (platformTarball) rmSync(platformTarball, { force: true });
    rmSync(platformBinary, { force: true });
  }
});

// The generated loader picks the glibc or musl artifact with isMusl(), which
// reads /usr/bin/ldd, then process.report, then `ldd --version`. Every one of
// those says "glibc" on a GitHub runner, so the musl half of the dispatch is
// unreachable from an ordinary test. Run the loader's real source in a
// context whose probes are stubbed, and record which artifact it reaches for.
const loaderSource = readFileSync(join(root, 'native', 'signal', 'index.cjs'), 'utf8');

function attemptLoad({ arch = 'x64', ldd = 'musl libc.so', lddThrows = false, report = null, lddVersion = 'musl libc' }) {
  const attempted = [];
  const notFound = (specifier) => {
    const error = new Error(`Cannot find module '${specifier}'`);
    error.code = 'MODULE_NOT_FOUND';
    return error;
  };
  const requireFrom = (specifier) => {
    attempted.push(specifier);
    if (specifier === 'fs') {
      return {
        readFileSync: (path) => {
          if (path !== '/usr/bin/ldd') throw new Error(`unexpected probe of ${path}`);
          if (lddThrows) throw new Error('ENOENT');
          return ldd;
        },
      };
    }
    if (specifier === 'child_process') return { execSync: () => lddVersion };
    throw notFound(specifier);
  };
  requireFrom.resolve = (specifier) => {
    throw notFound(specifier);
  };

  const sandbox = {
    module: { exports: {} },
    exports: {},
    require: requireFrom,
    process: { platform: 'linux', arch, env: {}, config: { variables: {} }, report },
  };
  try {
    runInNewContext(loaderSource, sandbox, { filename: 'index.cjs' });
  } catch (error) {
    // The loader always throws here: nothing is installed in the sandbox, so
    // only the specifiers it tried before giving up are interesting.
  }
  return attempted;
}

const LOADED = (attempted) => attempted.filter((s) => s.startsWith('./signal.') || s.startsWith('@oktz-signal/signal-'))
  .filter((s) => !s.includes('wasi'));

test('musl host loads the musl artifact, not the glibc one', () => {
  const attempted = attemptLoad({ ldd: 'musl libc.so' });
  assert.deepEqual(LOADED(attempted), ['./signal.linux-x64-musl.node', '@oktz-signal/signal-linux-x64-musl']);
});

test('glibc host loads the glibc artifact, not the musl one', () => {
  const attempted = attemptLoad({ ldd: 'ldd (Ubuntu GLIBC 2.39)' });
  assert.deepEqual(LOADED(attempted), ['./signal.linux-x64-gnu.node', '@oktz-signal/signal-linux-x64-gnu']);
});

test('musl arm64 dispatches to the arm64 musl artifact', () => {
  const attempted = attemptLoad({ arch: 'arm64', ldd: 'musl libc.so' });
  assert.deepEqual(LOADED(attempted), ['./signal.linux-arm64-musl.node', '@oktz-signal/signal-linux-arm64-musl']);
});

test('glibc arm64 dispatches to the arm64 glibc artifact', () => {
  const attempted = attemptLoad({ arch: 'arm64', ldd: 'ldd (GNU libc)' });
  assert.deepEqual(LOADED(attempted), ['./signal.linux-arm64-gnu.node', '@oktz-signal/signal-linux-arm64-gnu']);
});

test('without /usr/bin/ldd, a musl dynamic linker in the report decides', () => {
  const report = { getReport: () => ({ sharedObjects: ['/lib/ld-musl-aarch64.so.1'] }) };
  const attempted = attemptLoad({ arch: 'arm64', lddThrows: true, report });
  assert.deepEqual(LOADED(attempted), ['./signal.linux-arm64-musl.node', '@oktz-signal/signal-linux-arm64-musl']);
});

test('without /usr/bin/ldd, a glibc version in the report decides', () => {
  const report = { getReport: () => ({ header: { glibcVersionRuntime: '2.39' } }) };
  const attempted = attemptLoad({ arch: 'arm64', lddThrows: true, report });
  assert.deepEqual(LOADED(attempted), ['./signal.linux-arm64-gnu.node', '@oktz-signal/signal-linux-arm64-gnu']);
});

test('a glibc runtime in the report outranks a musl linker listed beside it', () => {
  // process.report can list ld-musl-* in sharedObjects on a glibc host that
  // has musl installed. glibcVersionRuntime is checked first, so it wins.
  const report = { getReport: () => ({ header: { glibcVersionRuntime: '2.39' }, sharedObjects: ['/lib/ld-musl-aarch64.so.1'] }) };
  const attempted = attemptLoad({ arch: 'arm64', lddThrows: true, report });
  assert.deepEqual(LOADED(attempted), ['./signal.linux-arm64-gnu.node', '@oktz-signal/signal-linux-arm64-gnu']);
});

test('with no ldd and no report, ldd --version is the last word', () => {
  const attempted = attemptLoad({ arch: 'arm64', lddThrows: true, lddVersion: 'musl libc (x86_64)' });
  assert.deepEqual(LOADED(attempted), ['./signal.linux-arm64-musl.node', '@oktz-signal/signal-linux-arm64-musl']);
});
