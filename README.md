# extrL

[![CI](https://github.com/NusaSec/extrL/actions/workflows/ci.yml/badge.svg)](https://github.com/NusaSec/extrL/actions/workflows/ci.yml)
[![crates.io](https://img.shields.io/crates/v/extrL.svg)](https://crates.io/crates/extrL)
[![Rust](https://img.shields.io/badge/rust-stable-orange.svg)](https://www.rust-lang.org)

Download a Solana program's on-chain Anchor IDL straight from the chain - no `anchor` toolchain, no RPC SDK, single static binary.

Anchor programs (pre-1.0) publish their IDL to a deterministic account derived from the program id and the seed `anchor:idl`. `extrL` derives that address, fetches the account over plain JSON-RPC, strips the header, zlib-inflates the payload, and writes the IDL JSON.

## Install

```sh
cargo install extrL
# or
cargo build --release   # -> target/release/extrL
```

Requires a current Rust toolchain (some transitive deps use edition 2024).

## Usage

```sh
extrL <PROGRAM_ID>                          # writes <idl name>.json
extrL <PROGRAM_ID> -o jup.json              # custom output path
extrL <PROGRAM_ID> -s                       # print to stdout
extrL <PROGRAM_ID> -u https://api.devnet.solana.com
extrL --completions bash > extrL.bash       # shell completions
```

| flag | meaning | default |
| --- | --- | --- |
| `-u, --url` | RPC endpoint | `https://api.mainnet-beta.solana.com` |
| `-o, --out` | output file (conflicts with `-s`) | `<idl name>.json`, else `<PROGRAM_ID>.json` |
| `-s, --stdout` | print instead of writing a file | off |
| `--completions <SHELL>` | print shell completions and exit | — |

The output file defaults to the IDL's own `name` (e.g. `jupiter.json`), falling back to the program id when the IDL has no name.

Programs without a published on-chain IDL produce a clear error rather than an empty file. Requests use a 10s connect / 30s read timeout and retry transient `429`/`5xx` responses with backoff — a rate-limited public RPC reports a clear hint to pass your own `-u` endpoint.

## How it works

```
base    = find_program_address([], program_id).0
idl_acc = create_with_seed(base, "anchor:idl", program_id)

account layout:
  [0..8]            8-byte account discriminator
  [8..40]           authority (Pubkey)
  [40..44]          data_len  (u32 LE)
  [44..44+data_len] zlib-compressed IDL JSON
```

Derivation is implemented directly with `sha2` + `curve25519-dalek` (the ed25519 on-curve check) and cross-checked byte-for-byte against `solders`. No `solana-sdk` dependency.

## Notes

- Targets the legacy `anchor:idl` account, which virtually every deployed Anchor program uses.
- Anchor 1.0 began migrating IDL storage to a separate Program Metadata standard. Programs that only publish via Program Metadata are not covered yet - a future `--source metadata` path can be added.

## License

MIT
