rust-mmap-fixed-fixed
=========

A Rust library for dealing with memory mapped files, originally extracted from
the Rust standard library source code before it was removed.

## NOTE

This is a fork of a fork of the original *rust-mmap* with updated dependencies and a
fix for the Windows version. This exists only because there are no other
alternative crates for `MAP_FIXED` allocations.

See: [memmap-rs#21](https://github.com/danburkert/memmap-rs/issues/21).

This second-degree fork exists because the first fork hasn't been updated to support winapi v0.3.

See: [detour-rs#32](https://github.com/darfink/detour-rs/issues/32).