// Guard for native/signal/index.cjs, the generated platform loader that ships
// in the npm tarball.
//
// `napi build --js index.cjs` emits that file, and this repo's copy is then
// hand-patched: the hardening fixes the loader carries (an unconditional
// binding version check, a scoped process.report mutation, a silent libc
// probe, platform fallbacks that survive a bad NAPI_RS_NATIVE_LIBRARY_PATH,
// absent-WASI-candidate suppression, gated npm advice) and the
// `module.exports.default` line are all *not* generator output. The generator
// knows none of them, so regenerating the file silently reverts every one of
// them and reports success.
//
// Two modes, both fail closed:
//
//   patch <generated> <published>
//     Turn a freshly generated loader into the published one. Every edit is
//     anchored on the exact text the generator emits and must match the
//     expected number of times, so an @napi-rs/cli upgrade that moves an
//     anchor stops the build instead of producing a loader with a fix
//     missing. The published file is written only after all edits and a
//     syntax check pass, and the generated file is removed afterwards.
//
//   verify <published>
//     Assert the loader that would be published still carries every
//     hand-maintained region, by requiring each region's patched form to be
//     present the expected number of times and its generated form to be
//     absent. A regenerated, hand-edited or half-patched loader exits
//     non-zero and names the regions that are wrong.
//
// Each region below is delimited in the loader itself with
// `/* oktz-signal:hand-maintained:begin <id> */` markers, so a maintainer can
// see in the file which lines are hand-written.

import { readFileSync, renameSync, rmSync, writeFileSync } from 'node:fs';
import { relative } from 'node:path';
import { Script } from 'node:vm';

const begin = (id) => `/* oktz-signal:hand-maintained:begin ${id} */`;
const end = (id) => `/* oktz-signal:hand-maintained:end ${id} */`;

const regions = [
  {
    id: 'version-check-helpers',
    edits: [
      {
        find: `const loadErrors = []

const isMusl = () => {`,
        replace: `const loadErrors = []

${begin('version-check-helpers')}
// hand-maintained patch, not emitted by \`napi build\`. Every binding version
// check below was gated on NAPI_RS_ENFORCE_VERSION_CHECK, which is unset by
// default: a platform package left behind by an earlier install loaded in
// silence, and a mismatched NAPI-RS ABI surfaced later as a crash inside the
// addon rather than as a version error. With enforcement switched on the
// version error was thrown inside the same \`try\` that guards the require, so
// the \`catch\` re-buried it as a MODULE_NOT_FOUND candidate miss. The checks
// are now unconditional, and a mismatch propagates out of requireNative()
// instead of joining the candidate list.
const __napiBindingVersionIsStale = (bindingPackageVersion) => bindingPackageVersion !== '0.3.0-rc.1'

const __napiBindingVersionMismatch = (bindingPackageVersion, flavor) => {
  const error = new Error(\`\${flavor || 'Native'} binding package version mismatch, expected 0.3.0-rc.1 but got \${bindingPackageVersion}. You can reinstall dependencies to fix this issue.\`)
  error.code = 'ERR_NAPI_BINDING_VERSION_MISMATCH'
  return error
}

const __napiPushLoadError = (e) => {
  if (e && e.code === 'ERR_NAPI_BINDING_VERSION_MISMATCH') throw e
  loadErrors.push(e)
}
${end('version-check-helpers')}

const isMusl = () => {`,
      },
    ],
  },
  {
    id: 'musl-report-scoping',
    edits: [
      {
        find: `  if (process.report && typeof process.report.getReport === 'function') {
    process.report.excludeNetwork = true
    report = process.report.getReport()
  }`,
        replace: `  if (process.report && typeof process.report.getReport === 'function') {
    ${begin('musl-report-scoping')}
    // hand-maintained patch, not emitted by \`napi build\`: the flag is scoped to
    // the getReport() call and restored in a finally. Setting it permanently
    // mutated process-global state on a library \`require\` -- the flag stuck and
    // the \`network\` section vanished from every report the host app emitted
    // afterwards. getReport() is the only consumer, so the value is restored
    // even when it throws.
    const excludeNetwork = process.report.excludeNetwork
    process.report.excludeNetwork = true
    try {
      report = process.report.getReport()
    } finally {
      process.report.excludeNetwork = excludeNetwork
    }
    ${end('musl-report-scoping')}
  }`,
      },
    ],
  },
  {
    id: 'musl-probe-stdio',
    edits: [
      {
        find: `    return require('child_process').execSync('ldd --version', { encoding: 'utf8' }).includes('musl')`,
        replace: `    ${begin('musl-probe-stdio')}
    // hand-maintained patch, not emitted by \`napi build\`: stdin and stderr are
    // discarded. execSync's default stdio inherits them from this process, so
    // a failed probe printed the shell's own diagnostics into the host
    // application's stderr -- noise attributed to the host, from a probe whose
    // only output of interest is the stdout captured below.
    return require('child_process').execSync('ldd --version', { encoding: 'utf8', stdio: ['ignore', 'pipe', 'ignore'] }).includes('musl')
    ${end('musl-probe-stdio')}`,
      },
    ],
  },
  {
    id: 'override-fallback',
    edits: [
      {
        find: `    } catch (err) {
      loadErrors.push(err)
    }
  } else if (process.platform === 'android') {`,
        replace: `    } catch (err) {
      ${begin('override-fallback')}
      // hand-maintained patch, not emitted by \`napi build\`: a failed override is
      // recorded by name, so the operator who set the variable can find it in
      // the cause chain instead of it surfacing as a bare resolution failure.
      loadErrors.push(new Error(\`NAPI_RS_NATIVE_LIBRARY_PATH could not be loaded: \${err && err.message ? err.message : String(err)}\`))
      ${end('override-fallback')}
    }
  }
  // hand-maintained patch, not emitted by \`napi build\`: an override is an
  // override, not a replacement. As the head of this if/else chain a bad
  // NAPI_RS_NATIVE_LIBRARY_PATH disabled every platform fallback below and
  // broke a working install; the override is now a standalone step, and its
  // failure is recorded above by name so it stays findable in the cause chain.
  if (process.platform === 'android') {`,
      },
    ],
  },
  {
    id: 'version-check-sites',
    edits: [
      {
        // 26 sites, one per platform package, at five indentation depths. The
        // 27th check is the WASI package, which is its own region.
        find: /^(\s*)if \(bindingPackageVersion !== '0\.3\.0-rc\.1' && process\.env\.NAPI_RS_ENFORCE_VERSION_CHECK && process\.env\.NAPI_RS_ENFORCE_VERSION_CHECK !== '0'\) \{\n\s*throw new Error\(`Native binding package version mismatch[^\n]*\)\n\1\}/gm,
        replace: '$1if (__napiBindingVersionIsStale(bindingPackageVersion)) {\n$1  throw __napiBindingVersionMismatch(bindingPackageVersion)\n$1}',
        expect: /^(\s*)if \(__napiBindingVersionIsStale\(bindingPackageVersion\)\) \{\n\s*throw __napiBindingVersionMismatch\(bindingPackageVersion\)\n\1\}/gm,
        count: 26,
      },
      {
        // 52 candidate catches: a version mismatch has to leave requireNative()
        // instead of joining loadErrors and being reported as a miss. Anchored
        // on the catch so it cannot also match the helper's own
        // `loadErrors.push(e)`, which the verify pass requires to be absent.
        find: /^(\s*)\} catch \(e\) \{\n\1  loadErrors\.push\(e\)$/gm,
        replace: '$1} catch (e) {\n$1  __napiPushLoadError(e)',
        expect: /^(\s*)__napiPushLoadError\(e\)$/gm,
        count: 52,
      },
      {
        find: 'function requireNative() {',
        keepsAnchor: true,
        replace: `${begin('version-check-sites')}
// hand-maintained patch, not emitted by \`napi build\`: the two edits above
// reach every candidate catch and every version check in this file. Those 78
// sites are scattered through the generated dispatch chain rather than sitting
// in one block, so they cannot be bracketed by these markers; \`verify\` pins
// their exact counts (26 version checks, 52 load-error records) instead.
${end('version-check-sites')}

function requireNative() {`,
      },
    ],
  },
  {
    id: 'wasi-candidate-errors',
    edits: [
      {
        find: `    return null
  }
  if (!wasiBindingLoaded && (!__napiWasiFlavorRequested || __napiWasiFlavor === 'wasm32-wasi')) {`,
        keepsAnchor: true,
        replace: `    return null
  }
  ${begin('wasi-candidate-errors')}
  // hand-maintained patch, not emitted by \`napi build\`: an absent WASI
  // candidate is a missing optional artifact, not a load failure, so both
  // candidates below record into \`wasiBindingErrors\` only. \`napi.config.json\`
  // ships no wasm target, so both are unresolved on every install; pushing them
  // into \`loadErrors\` put a MODULE_NOT_FOUND at the head of the cause chain and
  // made a real native failure surface as the misleading "npm has a bug related
  // to optional dependencies" advice. The explicit WASI error path below still
  // reports them, through \`wasiBindingErrors\`.
  ${end('wasi-candidate-errors')}
  if (!wasiBindingLoaded && (!__napiWasiFlavorRequested || __napiWasiFlavor === 'wasm32-wasi')) {`,
      },
      {
        find: `      wasiBindingErrors.push(candidateError)
      loadErrors.push(candidateError)
`,
        replace: `      wasiBindingErrors.push(candidateError)
`,
        count: 2,
      },
    ],
  },
  {
    id: 'wasi-version-check',
    edits: [
      {
        find: `        if (process.env.NAPI_RS_ENFORCE_VERSION_CHECK && process.env.NAPI_RS_ENFORCE_VERSION_CHECK !== '0') {
          const bindingPackageVersion = require('@oktz-signal/signal-wasm32-wasi/package.json').version
          if (bindingPackageVersion !== '0.3.0-rc.1') {
            throw new Error(\`WASI binding package version mismatch, expected 0.3.0-rc.1 but got \${bindingPackageVersion}. You can reinstall dependencies to fix this issue.\`)
          }
        }`,
        replace: `        ${begin('wasi-version-check')}
        // hand-maintained patch, not emitted by \`napi build\`: the WASI package
        // was gated on the same opt-in flag as every native platform package,
        // and is enforced identically. Leaving one opt-in site would have
        // meant a stale WASI package still loading silently.
        {
          const bindingPackageVersion = require('@oktz-signal/signal-wasm32-wasi/package.json').version
          if (__napiBindingVersionIsStale(bindingPackageVersion)) {
            throw __napiBindingVersionMismatch(bindingPackageVersion, 'WASI')
          }
        }
        ${end('wasi-version-check')}`,
      },
    ],
  },
  {
    id: 'npm-advice-gating',
    edits: [
      {
        find: `  if (loadErrors.length > 0) {
    const error = new Error(
      \`Cannot find native binding. \` +
        \`npm has a bug related to optional dependencies (https://github.com/npm/cli/issues/4828). \` +
        'Please try \`npm i\` again after removing both package-lock.json and node_modules directory.',
    )`,
        replace: `  if (loadErrors.length > 0) {
    ${begin('npm-advice-gating')}
    // hand-maintained patch, not emitted by \`napi build\`: "npm has a bug
    // related to optional dependencies" is only actionable advice when the
    // candidates genuinely failed to resolve. Printed over a dlopen or
    // corruption failure it sends the reader after a reinstall that cannot
    // help, so it is now gated on the errors it actually applies to.
    const unresolvedOnly = loadErrors.every((e) => e && e.code === 'MODULE_NOT_FOUND')
    ${end('npm-advice-gating')}
    const error = new Error(
      \`Cannot find native binding. \` +
        (unresolvedOnly
          ? \`npm has a bug related to optional dependencies (https://github.com/npm/cli/issues/4828). \` +
            'Please try \`npm i\` again after removing both package-lock.json and node_modules directory.'
          : 'The binding candidates below exist but failed to load. See the cause chain for the real error.'),
    )`,
      },
    ],
  },
  {
    id: 'default-export',
    edits: [
      {
        find: 'module.exports.x3DhBuildRecipientSession = nativeBinding.x3DhBuildRecipientSession\n',
        keepsAnchor: true,
        replace: `module.exports.x3DhBuildRecipientSession = nativeBinding.x3DhBuildRecipientSession
${begin('default-export')}
// hand-maintained patch, not emitted by \`napi build\`: the CommonJS entry is
// also consumed as an ES module, so \`default\` has to resolve to the binding
// itself. tests/platform-loader.test.mjs asserts \`native.default === native\`.
module.exports.default = nativeBinding
${end('default-export')}
`,
      },
    ],
  },
];

// A fresh global copy, so a pattern's `lastIndex` never leaks between edits.
const asGlobal = (pattern) =>
  new RegExp(pattern.source, pattern.flags.includes('g') ? pattern.flags : `${pattern.flags}g`);

// Count whole matches of a literal or a pattern. A pattern is always treated
// as global so an edit's count is a real total, not the first hit.
const countMatches = (source, needle) =>
  typeof needle === 'string' ? source.split(needle).length - 1 : [...source.matchAll(asGlobal(needle))].length;

const replaceAll = (source, edit) =>
  typeof edit.find === 'string'
    ? source.split(edit.find).join(edit.replace)
    : source.replace(asGlobal(edit.find), edit.replace);

const expectFor = (edit) => (edit.expect === undefined ? edit.replace : edit.expect);

const parse = (source, file) => {
  try {
    new Script(source, { filename: file });
  } catch (error) {
    throw new Error(`${file} is not valid CommonJS: ${error.message}`);
  }
};

const applyLoaderPatches = (generated, file) => {
  let patched = generated;
  for (const region of regions) {
    for (const edit of region.edits) {
      const found = countMatches(patched, edit.find);
      const want = edit.count === undefined ? 1 : edit.count;
      if (found !== want) {
        throw new Error(
          `hand-maintained region '${region.id}' does not match the generated loader: expected ${want} occurrence(s) of its anchor, found ${found}. ` +
            'The @napi-rs/cli output changed -- re-derive this patch against the new generated file. The published loader was not written.',
        );
      }
      patched = replaceAll(patched, edit);
    }
  }
  parse(patched, file);
  return patched;
};

// One report line per region, so the ids stay unique even when several edits of
// the same region are wrong. An edit that only inserts around its anchor
// (`keepsAnchor`) is exempt from the "generated form is gone" check; every
// other edit is assumed to consume it, so a new edit is checked by default.
const findLostRegions = (published) => {
  const lost = [];
  for (const region of regions) {
    const problems = [];
    for (const edit of region.edits) {
      const want = edit.count === undefined ? 1 : edit.count;
      const present = countMatches(published, expectFor(edit));
      const generated = countMatches(published, edit.find);
      if (present !== want) {
        problems.push(`expected ${want} occurrence(s) of the patched form, found ${present}`);
      } else if (!edit.keepsAnchor && generated !== 0) {
        problems.push(`the generated form is still present (${generated} occurrence(s))`);
      }
    }
    if (problems.length > 0) lost.push({ id: region.id, detail: problems.join('; ') });
  }
  return lost;
};

const fail = (file, lost) => {
  process.exitCode = 1;
  process.stderr.write(
    `${file} is not the loader this package publishes: ${lost.length} hand-maintained region(s) that \`napi build\` does not emit are missing or altered\n` +
      lost.map(({ id, detail }) => `  - ${id}: ${detail}\n`).join('') +
      'A regeneration reverts every one of them. Re-apply with `npm run build:loader`; from a fresh clone run `npm run build`.\n',
  );
};

const [mode, ...args] = process.argv.slice(2);
const show = (file) => relative(process.cwd(), file) || file;

const patch = (generatedPath, publishedPath) => {
  const generated = readFileSync(generatedPath, 'utf8');
  const published = applyLoaderPatches(generated, show(publishedPath));
  // Write beside the target and rename, so a crash mid-write cannot leave a
  // truncated loader where the published one used to be.
  const stagingPath = `${publishedPath}.tmp`;
  writeFileSync(stagingPath, published);
  renameSync(stagingPath, publishedPath);
  // The generated file is an intermediate: leaving it behind would make a later
  // `napi build` look like it had nothing to do.
  rmSync(generatedPath, { force: true });
};

const verify = (publishedPath) => {
  const published = readFileSync(publishedPath, 'utf8');
  const lost = findLostRegions(published);
  if (lost.length > 0) fail(show(publishedPath), lost);
  else parse(published, show(publishedPath));
};

const USAGE = 'usage: loader-guard.mjs <patch <generated> <published> | verify <published>>\n';

try {
  if (mode === 'patch' && args.length === 2) patch(args[0], args[1]);
  else if (mode === 'verify' && args.length === 1) verify(args[0]);
  else {
    process.exitCode = 1;
    process.stderr.write(USAGE);
  }
} catch (error) {
  // A guard that dies with a stack trace is a guard nobody reads.
  process.exitCode = 1;
  process.stderr.write(`${error.message}\n`);
}
