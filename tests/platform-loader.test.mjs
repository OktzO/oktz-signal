import assert from 'node:assert/strict';
import { execFileSync, spawnSync } from 'node:child_process';
import { cpSync, existsSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';

// Read from package.json so a release bump cannot leave these assertions stale.
const VERSION = JSON.parse(
  readFileSync(new URL('../package.json', import.meta.url), 'utf8')
).version;
const ESCAPED_VERSION = VERSION.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
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

function runLoader({
  arch = 'x64', ldd = 'musl libc.so', lddThrows = false, report = null,
  lddVersion = 'musl libc', lddVersionThrows = false, env = {}, provides = {},
  throwsFor = {},
} = {}) {
  const attempted = [];
  const execSyncCalls = [];
  const readFileSyncCalls = [];
  const notFound = (specifier) => {
    const error = new Error(`Cannot find module '${specifier}'`);
    error.code = 'MODULE_NOT_FOUND';
    return error;
  };
  const has = (specifier) => Object.prototype.hasOwnProperty.call(provides, specifier);
  const fails = (specifier) => Object.prototype.hasOwnProperty.call(throwsFor, specifier);
  const requireFrom = (specifier) => {
    attempted.push(specifier);
    if (specifier === 'fs') {
      return {
        readFileSync: (path) => {
          readFileSyncCalls.push(path);
          if (path !== '/usr/bin/ldd') throw new Error(`unexpected probe of ${path}`);
          if (lddThrows) throw new Error('ENOENT');
          return ldd;
        },
      };
    }
    if (specifier === 'child_process') {
      return {
        execSync: (command, options) => {
          execSyncCalls.push({ command, options });
          if (lddVersionThrows) throw new Error('probe failed');
          return lddVersion;
        },
      };
    }
    if (has(specifier)) return provides[specifier];
    if (fails(specifier)) throw throwsFor[specifier];
    throw notFound(specifier);
  };
  requireFrom.resolve = (specifier) => {
    if (has(specifier) || fails(specifier)) return specifier;
    throw notFound(specifier);
  };

  const sandbox = {
    module: { exports: {} },
    exports: {},
    require: requireFrom,
    process: { platform: 'linux', arch, env, config: { variables: {} }, report },
  };
  let thrown = null;
  try {
    runInNewContext(loaderSource, sandbox, { filename: 'index.cjs' });
  } catch (error) {
    // Nothing is installed in the sandbox by default, so the loader usually
    // throws; when `provides` satisfies a candidate it does not.
    thrown = error;
  }
  const chain = [];
  for (let error = thrown; error; error = error.cause) chain.push(error && error.message);
  return { attempted, chain, execSyncCalls, readFileSyncCalls, thrown };
}

const attemptLoad = (options) => runLoader(options).attempted;

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

const loaderPath = join(root, 'native', 'signal', 'index.cjs');

const runLoaderProcess = (source, env) =>
  execFileSync(process.execPath, ['--eval', source], { cwd: root, encoding: 'utf8', env: { ...process.env, ...env } });

const REQUIRE_LOCAL = `const binding = require(${JSON.stringify(loaderPath)}); console.log('loaded ' + typeof binding.curveSign)`;

test('a bad NAPI_RS_NATIVE_LIBRARY_PATH still falls back to the local platform artifact', () => {
  const output = runLoaderProcess(REQUIRE_LOCAL, { NAPI_RS_NATIVE_LIBRARY_PATH: '/nope/x.node' });
  assert.equal(output.trim(), 'loaded function');
});

test('a bad NAPI_RS_NATIVE_LIBRARY_PATH does not disable the platform candidates', () => {
  const { attempted } = runLoader({ env: { NAPI_RS_NATIVE_LIBRARY_PATH: '/nope/x.node' } });
  assert.ok(attempted.includes('/nope/x.node'));
  assert.deepEqual(LOADED(attempted), ['./signal.linux-x64-musl.node', '@oktz-signal/signal-linux-x64-musl']);
});

test('a failed NAPI_RS_NATIVE_LIBRARY_PATH override is reported by name in the cause chain', () => {
  const { chain } = runLoader({ env: { NAPI_RS_NATIVE_LIBRARY_PATH: '/nope/x.node' } });
  assert.ok(
    chain.some((message) => message.includes('NAPI_RS_NATIVE_LIBRARY_PATH')),
    `override failure not named in chain: ${JSON.stringify(chain)}`,
  );
});

const DLOPEN_FAILURE = new Error('dlopen: cannot open shared object file: No such file or directory');

// The shape of a real host failure: npm installed the optional platform
// package, but the addon itself will not load. The local artifact is simply
// absent, so its MODULE_NOT_FOUND is the innermost cause and the dlopen
// failure is the one worth reading.
const INSTALLED_BUT_UNLOADABLE = {
  throwsFor: { '@oktz-signal/signal-linux-x64-musl': DLOPEN_FAILURE },
  provides: { '@oktz-signal/signal-linux-x64-musl/package.json': { version: VERSION } },
};

test('the real native failure is the outermost cause, not an absent WASI package', () => {
  const { chain } = runLoader(INSTALLED_BUT_UNLOADABLE);
  assert.equal(chain[1], DLOPEN_FAILURE.message);
});

test('absent WASI candidates are not reported as load failures', () => {
  const { chain } = runLoader(INSTALLED_BUT_UNLOADABLE);
  assert.ok(
    !chain.some((message) => /signal\.wasi\.cjs|@oktz-signal\/signal-wasm32-wasi/.test(message)),
    `absent WASI candidate leaked into the load chain: ${JSON.stringify(chain)}`,
  );
});

test('the npm optional-dependency advice is not printed over a non-resolution failure', () => {
  const { thrown } = runLoader(INSTALLED_BUT_UNLOADABLE);
  assert.ok(!thrown.message.includes('npm has a bug related to optional dependencies'), thrown.message);
});

test('NAPI_RS_FORCE_WASI=error still reports the WASI candidates it looked for', () => {
  const { thrown, chain } = runLoader({ env: { NAPI_RS_FORCE_WASI: 'error' } });
  assert.equal(thrown.message, 'WASI binding not found and NAPI_RS_FORCE_WASI is set to error');
  assert.ok(chain.some((message) => /@oktz-signal\/signal-wasm32-wasi/.test(message)), JSON.stringify(chain));
});

test('NAPI_RS_FORCE_WASI=error and a resolvable WASI artifact loads the artifact', () => {
  const { attempted } = runLoader({
    env: { NAPI_RS_FORCE_WASI: 'error' },
    ldd: 'ldd (GNU libc) 2.39',
    provides: {
      './signal.wasi.cjs': { curveSign() {} },
      './signal.wasm32-wasi.wasm': '',
    },
  });
  assert.ok(attempted.includes('./signal.wasi.cjs'));
});

// isMuslFromReport() is unreachable from an ordinary test on a glibc host:
// /usr/bin/ldd answers first and says "glibc". fs.readFileSync is patched
// before the loader is required, because the loader destructures
// `readFileSync` off `require('fs')` at module scope, so patching the fs
// module object beforehand is what actually reaches it.
const REACH_REPORT_PROBE = `
  const fs = require('fs')
  const realReadFileSync = fs.readFileSync
  let reportRead = 0
  fs.readFileSync = function (path, ...rest) {
    if (path === '/usr/bin/ldd') { const e = new Error('ENOENT'); e.code = 'ENOENT'; throw e }
    return realReadFileSync.call(this, path, ...rest)
  }
  const getReport = process.report.getReport.bind(process.report)
  process.report.getReport = function (...rest) { reportRead++; return getReport(...rest) }
  const before = process.report.excludeNetwork
  require(${JSON.stringify(loaderPath)})
  console.log(JSON.stringify({ before, after: process.report.excludeNetwork, reportRead }))
`;

test('requiring the loader does not leave process.report.excludeNetwork mutated', () => {
  const output = runLoaderProcess(REACH_REPORT_PROBE, {});
  const { before, after, reportRead } = JSON.parse(output);
  assert.equal(reportRead, 1, `the report probe was never reached: ${output}`);
  assert.equal(after, before, `process.report.excludeNetwork leaked: ${output}`);
});

test('the report probe restores excludeNetwork to its prior value', () => {
  const report = { excludeNetwork: undefined, getReport: () => ({ header: { glibcVersionRuntime: '2.39' } }) };
  runLoader({ lddThrows: true, report });
  assert.equal(report.excludeNetwork, undefined);
});

test('a failing libc probe does not write to the parent process stderr', () => {
  // isMuslFromChildProcess() is the last of the three musl probes, reached
  // only when /usr/bin/ldd is unreadable and process.report is unavailable.
  // A fake ldd on an otherwise empty PATH both proves the probe ran and
  // produces stderr, which execSync's default stdio inherits from the parent.
  const bin = mkdtempSync(join(tmpdir(), 'oktz-signal-bin-'));
  const marker = join(bin, 'ran');
  writeFileSync(join(bin, 'ldd'), `#!/bin/sh\necho ran >> ${marker}\necho 'ldd (GNU libc) 2.39'\necho 'fake-ldd-stderr-noise' >&2\n`, { mode: 0o755 });
  const source = `
    const fs = require('fs')
    const realReadFileSync = fs.readFileSync
    fs.readFileSync = function (path, ...rest) {
      if (path === '/usr/bin/ldd') { const e = new Error('ENOENT'); e.code = 'ENOENT'; throw e }
      return realReadFileSync.call(this, path, ...rest)
    }
    Object.defineProperty(process, 'report', { value: null, configurable: true })
    require(${JSON.stringify(loaderPath)})
    console.log('parent-stdout-marker')
  `;
  try {
    const result = spawnSync(process.execPath, ['--eval', source], {
      cwd: root,
      encoding: 'utf8',
      env: { ...process.env, PATH: bin },
    });
    assert.equal(result.status, 0, result.stderr);
    assert.match(result.stdout, /parent-stdout-marker/);
    assert.ok(existsSync(marker), 'the ldd probe never ran, so this test proved nothing');
    assert.equal(result.stderr, '', 'the libc probe wrote to the parent process stderr');
  } finally {
    rmSync(bin, { force: true, recursive: true });
  }
});

const STALE_PLATFORM_PACKAGE = {
  ldd: 'ldd (GNU libc) 2.39',
  provides: {
    '@oktz-signal/signal-linux-x64-gnu': { curveSign() {} },
    '@oktz-signal/signal-linux-x64-gnu/package.json': { version: '0.1.0' },
  },
};

test('a version-mismatched platform package is rejected without opting in', () => {
  const { thrown } = runLoader({ ...STALE_PLATFORM_PACKAGE, env: {} });
  assert.match(thrown.message, new RegExp(`version mismatch, expected ${ESCAPED_VERSION} but got 0\\.1\\.0`));
});

test('a version-mismatched platform package reports the version error, not MODULE_NOT_FOUND', () => {
  const { thrown } = runLoader({ ...STALE_PLATFORM_PACKAGE, env: {} });
  assert.ok(
    !/Cannot find module/.test(thrown.message),
    `the version error was re-buried: ${thrown.message}`,
  );
  assert.ok(
    !(thrown.cause && /Cannot find module/.test(thrown.cause.message)),
    `the version error was re-buried under a resolution failure: ${thrown.cause && thrown.cause.message}`,
  );
});

test('a version-mismatched platform package is still rejected when enforcement is requested', () => {
  const { thrown } = runLoader({ ...STALE_PLATFORM_PACKAGE, env: { NAPI_RS_ENFORCE_VERSION_CHECK: '1' } });
  assert.match(thrown.message, new RegExp(`version mismatch, expected ${ESCAPED_VERSION} but got 0\\.1\\.0`));
});

test('a matching platform package loads', () => {
  const { thrown } = runLoader({
    ldd: 'ldd (GNU libc) 2.39',
    provides: {
      '@oktz-signal/signal-linux-x64-gnu': { curveSign() {} },
      '@oktz-signal/signal-linux-x64-gnu/package.json': { version: VERSION },
    },
    env: {},
  });
  assert.equal(thrown, null);
});
