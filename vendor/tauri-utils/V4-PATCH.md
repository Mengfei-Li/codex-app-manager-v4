# V4 tauri-utils maintenance patch

Source package: `tauri-utils 2.9.3`, published from Tauri commit
`6f6ab1207bb3923c2721fbc67d2fdb1c8deb0c7a` under Apache-2.0 OR MIT.

V4 changes exactly one dependency declaration:

- `urlpattern = "0.3"` becomes `urlpattern = "0.6"` in `Cargo.toml` and
  `Cargo.toml.orig`.

Reason: `urlpattern 0.3.0` depends on the unmaintained `unic-*` family and
causes RUSTSEC-2025-0075, RUSTSEC-2025-0080, RUSTSEC-2025-0081,
RUSTSEC-2025-0098 and RUSTSEC-2025-0100 to remain reachable on the supported
Windows and macOS dependency graphs. `urlpattern 0.6.0` replaces that family
with maintained ICU dependencies.

Upstream alignment: Tauri's official `dev` branch at commit
`020919a1b5d2c1faa9deb972a31a1a11d0ae8ce6` already declares
`urlpattern = "0.6"` for `tauri-utils`; the local vendor patch avoids a mutable
Git dependency while the crates.io release is still 2.9.3.

Acceptance: the patch is retained only while all Manager Rust tests and
Clippy pass and cargo-deny reports zero denied advisories for Windows x64,
Windows ARM64, macOS Intel and macOS Apple Silicon. No advisory is ignored.
