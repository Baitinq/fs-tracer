# fs-tracer

This repository contains the eBPF agent for monitoring POSIX filesystem modifications. It works in conjunction with the backend services found in [fs-tracer-backend](https://github.com/baitinq/fs-tracer-backend) and [frotend part](https://github.com/baitinq/fs-tracer-frontend) of the application.


## Prerequisites

1. Install bpf-linker: `cargo install bpf-linker`

## Build eBPF

```bash
cargo xtask build-ebpf
```

To perform a release build you can use the `--release` flag.
You may also change the target architecture with the `--target` flag.

## Build Userspace

```bash
cargo build
```

## Run

```bash
RUST_LOG=info cargo xtask run
```

Related:
- https://github.com/baitinq/fs-tracer-backend
- https://github.com/baitinq/fs-tracer-frontend
