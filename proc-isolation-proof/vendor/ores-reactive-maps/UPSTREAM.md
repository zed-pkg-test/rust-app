# Upstream provenance

This crate is a minimal vendored subset of the Rust API from `ORESoftware/ores-reactive-maps`, pinned from commit:

`39fa222499e1a041117fc3e6b136189b16669e6b`

Only the `ReactiveMap` functionality used by `ores-proc-isolation-cli` is retained here so CI and release builds do not require cross-repository credentials for the private upstream repository. Keep behavior and public names aligned with that pinned upstream source when refreshing this vendor snapshot.
