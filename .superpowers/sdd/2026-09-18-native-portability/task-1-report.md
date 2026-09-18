# Task 1 Report: napi-rs Packaging

## Files Changed

- `.gitignore`
- `package.json`
- `package-lock.json`
- `napi.config.json`
- `native/signal/index.cjs`
- `npm/android-arm64/package.json`
- `npm/linux-arm64-gnu/package.json`
- `npm/linux-arm64-musl/package.json`
- `npm/linux-x64-gnu/package.json`
- `npm/linux-x64-musl/package.json`
- `tests/platform-loader.test.mjs`

## Decisions

- Kept public `native` export unchanged in `index.js`; generated CommonJS loader remains at `native/signal/index.cjs`.
- Pinned `@napi-rs/cli` to `3.10.4`.
- Configured five requested prebuild targets and five exact-version optional platform dependencies under `@oktz-signal/signal-*`.
- Generated loader via `napi build`; no hand-written libc detection.
- Kept source build separate as `build:source`; no install lifecycle script builds native code.
- Passed `--config-path napi.config.json` to `build:native`; NAPI-RS otherwise derives `index.*` artifact names, which do not match `signal.*` platform manifests.
- Main tarball ships public JS, generated loader, and `napi.config.json`; local `.node` outputs and Cargo target are ignored.

## Commands And Results

- `node --test tests/platform-loader.test.mjs`: initial failure. Existing fixed loader could not find `./signal.linux-x64-gnu.node` in this worktree.
- `npm run build:native`: blocked. Cargo reported `error: linker cc not found`.
- `npm exec -- napi build --release --platform --js-package-name @oktz-signal/signal --config-path napi.config.json --manifest-path native/signal/Cargo.toml --output-dir native/signal --js index.cjs --use-napi-cross`: passed. Generated loader and Linux x64 GNU artifact using napi-rs cross toolchain.
- `npm exec -- napi artifacts --config-path napi.config.json --output-dir native/signal --npm-dir npm`: passed. No tracked binary output.
- `npm test && node --test tests/platform-loader.test.mjs`: passed. 18 suite tests plus standalone loader test.
- `npm pack --dry-run`: passed. Tarball contained public JS, generated loader, config; excluded `.node` files and `native/signal/target/`.
- `npm install --package-lock-only --ignore-scripts`: passed. Npm emitted pre-existing transitive `content-type@3.1.1` Node >=22 engine warning; audit found zero vulnerabilities.

## Commits

- `db2f118 feat: package signal prebuilds by platform`

## Concerns

- Host has no `cc`; plain `npm run build:native` and `npm run build:source` cannot link. Use an installed C compiler, or invoke NAPI-RS with `--use-napi-cross` in supported Linux CI.
- Generated loader supports additional NAPI-RS platform branches, but only five requested optional packages are declared and packaged.
