use anyhow::{anyhow, bail, Context, Result};
use base64::{engine::general_purpose::STANDARD, Engine};
use clap::{CommandFactory, Parser};
use clap_complete::Shell;
use curve25519_dalek::edwards::CompressedEdwardsY;
use flate2::read::ZlibDecoder;
use sha2::{Digest, Sha256};
use std::io::Read;
use std::time::Duration;

const PDA_MARKER: &[u8] = b"ProgramDerivedAddress";
const IDL_SEED: &str = "anchor:idl";
const HEADER: usize = 44;
const MAX_ATTEMPTS: u32 = 4;

const EXAMPLES: &str = "\
EXAMPLES:
  extrL <PROGRAM_ID>                          write <idl name>.json
  extrL <PROGRAM_ID> -o jup.json              custom output path
  extrL <PROGRAM_ID> -s                       print to stdout
  extrL <PROGRAM_ID> -u https://api.devnet.solana.com
  extrL --completions bash > extrL.bash       generate shell completions
";

#[derive(Parser)]
#[command(
    name = "extrL",
    version,
    about = "Download a Solana program's on-chain Anchor IDL",
    after_help = EXAMPLES
)]
struct Args {
    /// Program id (base58) whose IDL to download
    program: Option<String>,
    /// RPC endpoint
    #[arg(short, long, default_value = "https://api.mainnet-beta.solana.com")]
    url: String,
    /// Output file (defaults to <idl name>.json, or <program id>.json)
    #[arg(short, long, conflicts_with = "stdout")]
    out: Option<String>,
    /// Print the IDL to stdout instead of writing a file
    #[arg(short, long)]
    stdout: bool,
    /// Generate shell completions for the given shell and exit
    #[arg(long, value_name = "SHELL")]
    completions: Option<Shell>,
}

fn key(s: &str) -> Result<[u8; 32]> {
    let v = bs58::decode(s).into_vec().context("invalid base58")?;
    v.try_into().map_err(|_| anyhow!("pubkey must be 32 bytes"))
}

fn on_curve(b: &[u8; 32]) -> bool {
    CompressedEdwardsY(*b).decompress().is_some()
}

fn try_pda(seeds: &[&[u8]], program: &[u8; 32]) -> Option<[u8; 32]> {
    let mut h = Sha256::new();
    for s in seeds {
        h.update(s);
    }
    h.update(program);
    h.update(PDA_MARKER);
    let out: [u8; 32] = h.finalize().into();
    if on_curve(&out) {
        None
    } else {
        Some(out)
    }
}

fn find_pda(program: &[u8; 32]) -> Result<[u8; 32]> {
    for bump in (0..=255u8).rev() {
        if let Some(p) = try_pda(&[&[bump]], program) {
            return Ok(p);
        }
    }
    bail!("no off-curve pda")
}

fn with_seed(base: &[u8; 32], seed: &str, owner: &[u8; 32]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(base);
    h.update(seed.as_bytes());
    h.update(owner);
    h.finalize().into()
}

fn idl_addr(program: &[u8; 32]) -> Result<[u8; 32]> {
    let base = find_pda(program)?;
    Ok(with_seed(&base, IDL_SEED, program))
}

fn build_agent() -> ureq::Agent {
    ureq::AgentBuilder::new()
        .timeout_connect(Duration::from_secs(10))
        .timeout_read(Duration::from_secs(30))
        .user_agent(concat!("extrL/", env!("CARGO_PKG_VERSION")))
        .build()
}

/// POST a JSON-RPC body, retrying transient failures (429 / 5xx / transport)
/// with exponential backoff.
fn rpc_call(agent: &ureq::Agent, url: &str, body: &serde_json::Value) -> Result<serde_json::Value> {
    let mut attempt = 0;
    loop {
        attempt += 1;
        let reason = match agent.post(url).send_json(body.clone()) {
            Ok(resp) => return resp.into_json().context("rpc response was not json"),
            Err(ureq::Error::Status(code, resp)) => {
                let retryable = code == 429 || (500..=599).contains(&code);
                if !retryable || attempt >= MAX_ATTEMPTS {
                    let hint = if code == 429 {
                        " (public RPC rate-limited; pass -u with your own endpoint)"
                    } else {
                        ""
                    };
                    let detail = resp.into_string().unwrap_or_default();
                    bail!("rpc returned HTTP {code}{hint}: {}", detail.trim());
                }
                format!("HTTP {code}")
            }
            Err(e @ ureq::Error::Transport(_)) => {
                if attempt >= MAX_ATTEMPTS {
                    return Err(anyhow::Error::new(e)).context("rpc request failed");
                }
                "connection error".to_string()
            }
        };
        // transient failure with attempts remaining: report, back off, retry
        let backoff = Duration::from_millis(250 * (1 << (attempt - 1)));
        eprintln!(
            "rpc {reason}, retrying in {}ms ({}/{})",
            backoff.as_millis(),
            attempt + 1,
            MAX_ATTEMPTS
        );
        std::thread::sleep(backoff);
    }
}

fn fetch(agent: &ureq::Agent, url: &str, addr: &str) -> Result<Vec<u8>> {
    let body = serde_json::json!({
        "jsonrpc": "2.0",
        "id": 1,
        "method": "getAccountInfo",
        "params": [addr, { "encoding": "base64" }]
    });
    let resp = rpc_call(agent, url, &body)?;
    if let Some(e) = resp.get("error").filter(|e| !e.is_null()) {
        bail!("rpc error: {e}");
    }
    let value = &resp["result"]["value"];
    if value.is_null() {
        bail!("no idl account at {addr} (this program may not publish an on-chain anchor idl)");
    }
    let data = value["data"][0]
        .as_str()
        .context("unexpected rpc response shape")?;
    STANDARD.decode(data).context("base64 decode account data")
}

fn decode(account: &[u8]) -> Result<Vec<u8>> {
    if account.len() < HEADER {
        bail!("account too small ({} bytes) to be an idl account", account.len());
    }
    let len = u32::from_le_bytes(account[40..44].try_into().unwrap()) as usize;
    let end = HEADER + len;
    if account.len() < end {
        bail!("declared idl length {len} exceeds account size {}", account.len());
    }
    let mut z = ZlibDecoder::new(&account[HEADER..end]);
    let mut out = Vec::new();
    z.read_to_end(&mut out).context("zlib inflate failed")?;
    Ok(out)
}

/// Look up a string field, checking the top level then `metadata` — covers
/// both legacy and Anchor 0.30+ IDL layouts.
fn field<'a>(idl: &'a serde_json::Value, key: &str) -> Option<&'a str> {
    idl.get(key)
        .or_else(|| idl.get("metadata").and_then(|m| m.get(key)))
        .and_then(|v| v.as_str())
}

fn count(idl: &serde_json::Value, key: &str) -> usize {
    idl.get(key).and_then(|v| v.as_array()).map_or(0, |a| a.len())
}

/// `3, "instruction"` -> "3 instructions"; `1, "account"` -> "1 account".
fn plural(n: usize, noun: &str) -> String {
    if n == 1 {
        format!("{n} {noun}")
    } else {
        format!("{n} {noun}s")
    }
}

/// Filesystem-safe stem derived from the IDL's own name, if present.
fn idl_name(idl: &serde_json::Value) -> Option<String> {
    let raw = field(idl, "name")?;
    let cleaned: String = raw
        .chars()
        .map(|c| if c.is_ascii_alphanumeric() || c == '-' || c == '_' { c } else { '_' })
        .collect();
    let trimmed = cleaned.trim_matches('_').to_string();
    if trimmed.is_empty() {
        None
    } else {
        Some(trimmed)
    }
}

/// One-line human summary of what the IDL contains, for the success message.
fn idl_summary(idl: &serde_json::Value) -> String {
    let mut parts = Vec::new();
    let name = field(idl, "name").unwrap_or("<unnamed>");
    match field(idl, "version") {
        Some(v) => parts.push(format!("{name} v{v}")),
        None => parts.push(name.to_string()),
    }
    parts.push(plural(count(idl, "instructions"), "instruction"));
    let accts = count(idl, "accounts");
    if accts > 0 {
        parts.push(plural(accts, "account"));
    }
    parts.join(", ")
}

fn main() -> Result<()> {
    let args = Args::parse();

    if let Some(shell) = args.completions {
        let mut cmd = Args::command();
        let name = cmd.get_name().to_string();
        clap_complete::generate(shell, &mut cmd, name, &mut std::io::stdout());
        return Ok(());
    }

    let program_str = args
        .program
        .context("PROGRAM_ID is required (run with --help for usage)")?;
    let program = key(&program_str).context("invalid program id")?;
    let addr = bs58::encode(idl_addr(&program)?).into_string();
    let agent = build_agent();
    let account = fetch(&agent, &args.url, &addr)?;
    let raw = decode(&account)?;
    let idl: serde_json::Value =
        serde_json::from_slice(&raw).context("idl payload is not valid json")?;
    let pretty = serde_json::to_string_pretty(&idl)?;
    if args.stdout {
        println!("{pretty}");
    } else {
        let path = args
            .out
            .unwrap_or_else(|| format!("{}.json", idl_name(&idl).unwrap_or(program_str)));
        std::fs::write(&path, &pretty).with_context(|| format!("failed to write {path}"))?;
        eprintln!("wrote {path} ({} bytes) — {}", pretty.len(), idl_summary(&idl));
        eprintln!("  idl account {addr}");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use flate2::write::ZlibEncoder;
    use flate2::Compression;
    use std::io::Write;

    #[test]
    fn decode_roundtrip() {
        let idl = br#"{"version":"0.1.0","name":"demo"}"#;
        let mut e = ZlibEncoder::new(Vec::new(), Compression::default());
        e.write_all(idl).unwrap();
        let comp = e.finish().unwrap();
        let mut acc = vec![7u8; 8];
        acc.extend_from_slice(&[3u8; 32]);
        acc.extend_from_slice(&(comp.len() as u32).to_le_bytes());
        acc.extend_from_slice(&comp);
        assert_eq!(decode(&acc).unwrap(), idl);
    }

    #[test]
    fn decode_rejects_short() {
        assert!(decode(&[0u8; 20]).is_err());
    }

    #[test]
    fn addr_is_deterministic() {
        let p = key("TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA").unwrap();
        let a = bs58::encode(idl_addr(&p).unwrap()).into_string();
        let b = bs58::encode(idl_addr(&p).unwrap()).into_string();
        assert_eq!(a, b);
    }

    #[test]
    fn identity_is_on_curve() {
        let mut id = [0u8; 32];
        id[0] = 1;
        assert!(on_curve(&id));
    }

    #[test]
    fn idl_name_prefers_top_level() {
        let v = serde_json::json!({ "name": "jupiter", "metadata": { "name": "other" } });
        assert_eq!(idl_name(&v).as_deref(), Some("jupiter"));
    }

    #[test]
    fn idl_name_falls_back_to_metadata() {
        let v = serde_json::json!({ "metadata": { "name": "drift v2" } });
        assert_eq!(idl_name(&v).as_deref(), Some("drift_v2"));
    }

    #[test]
    fn idl_name_none_when_absent() {
        let v = serde_json::json!({ "version": "0.1.0" });
        assert_eq!(idl_name(&v), None);
    }

    #[test]
    fn summary_reports_name_version_and_counts() {
        let v = serde_json::json!({
            "name": "jupiter",
            "version": "0.1.0",
            "instructions": [{}, {}, {}],
            "accounts": [{}, {}]
        });
        assert_eq!(idl_summary(&v), "jupiter v0.1.0, 3 instructions, 2 accounts");
    }

    #[test]
    fn summary_omits_accounts_and_singularizes() {
        let v = serde_json::json!({ "name": "demo", "instructions": [{}] });
        assert_eq!(idl_summary(&v), "demo, 1 instruction");
    }
}
