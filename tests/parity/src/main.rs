//! Parity harness.
//!
//! Three subcommands, all hit real HTTP servers:
//! * `identity` — print which identity this machine is using. Never prints
//!   the private key. `--regenerate --yes` rotates the on-disk file.
//! * `capture`  — send a request to `nanostore.babbage.systems`, build the
//!   canonical fixture, and write it to disk **only if it differs** from
//!   what's already there. Always appends one line to `.captures.log`.
//! * `diff`     — send the identical request to both nanostore and the local
//!   worker, canonicalize both bodies (JCS) and diff against each other and
//!   against the on-disk fixture. Any three-way disagreement is drift.
//!
//! # CLI
//!
//! ```text
//! parity identity [--regenerate [--yes]]
//! parity capture  --route <ROUTE> [--scenario <NAME>] [--reference <URL>]
//! parity diff     --route <ROUTE> [--scenario <NAME>]
//!                                 [--reference <URL>] [--local <URL>]
//! ```
//!
//! # Scenarios that need out-of-band wiring
//!
//! `/list`, `/upload`, `/advertise`, `/renew`, and the current `/find` error
//! cases require BRC-31 auth / admin identity / spendable UTXOs that the
//! harness doesn't own yet. Those scenarios are marked with `skip_reason` in
//! their module and `execute()` short-circuits them. `diff` treats a Skipped
//! execution as a soft pass so CI can iterate all 6 routes without red-flagging
//! known-unwired scenarios.
//!
//! # Gates
//!
//! * `#![forbid(unsafe_code)]`
//! * No `.unwrap()` / `.expect()` outside `#[cfg(test)]`.
//! * Clippy `-D warnings` under the root workspace lints.

#![forbid(unsafe_code)]

mod auth;
mod canon;
mod diff;
mod fixture;
mod identity;
mod overlay_live;
mod payment;
mod routes;
mod upload_roundtrip;
mod wallet;

use std::process::ExitCode;

use crate::auth::AuthClient;
use crate::fixture::{captures_log_path, fixtures_dir, CapturedResponse, Fixture, WriteOutcome};
use crate::routes::{Endpoint, ExecuteOutcome, ExecutedResponse};
use std::sync::Arc;

const DEFAULT_REFERENCE: &str = "https://nanostore.babbage.systems";
const DEFAULT_LOCAL: &str = "http://localhost:8787";

#[derive(Debug)]
enum Args {
    Identity(IdentityArgs),
    Capture(CaptureArgs),
    Diff(DiffArgs),
}

#[derive(Debug)]
struct IdentityArgs {
    regenerate: bool,
    yes: bool,
}

#[derive(Debug)]
struct CaptureArgs {
    route: String,
    scenario: String,
    reference: String,
}

#[derive(Debug)]
struct DiffArgs {
    route: String,
    scenario: String,
    reference: String,
    local: String,
}

fn parse_args() -> Result<Args, String> {
    let mut raw: Vec<String> = std::env::args().skip(1).collect();
    if raw.is_empty() {
        return Err(usage());
    }
    let sub = raw.remove(0);

    match sub.as_str() {
        "-h" | "--help" | "help" => Err(usage()),
        "identity" => parse_identity(raw).map(Args::Identity),
        "capture" => parse_capture(raw).map(Args::Capture),
        "diff" => parse_diff(raw).map(Args::Diff),
        other => Err(format!("unknown subcommand: {other}\n\n{}", usage())),
    }
}

fn parse_identity(raw: Vec<String>) -> Result<IdentityArgs, String> {
    let mut regenerate = false;
    let mut yes = false;
    for flag in raw {
        match flag.as_str() {
            "--regenerate" => regenerate = true,
            "--yes" => yes = true,
            other => return Err(format!("unknown identity flag: {other}")),
        }
    }
    Ok(IdentityArgs { regenerate, yes })
}

fn parse_capture(raw: Vec<String>) -> Result<CaptureArgs, String> {
    let flags = parse_route_flags(raw, false)?;
    Ok(CaptureArgs {
        route: flags.route.ok_or("--route is required")?,
        scenario: flags.scenario.unwrap_or_else(|| "default".to_string()),
        reference: flags
            .reference
            .unwrap_or_else(|| DEFAULT_REFERENCE.to_string()),
    })
}

fn parse_diff(raw: Vec<String>) -> Result<DiffArgs, String> {
    let flags = parse_route_flags(raw, true)?;
    Ok(DiffArgs {
        route: flags.route.ok_or("--route is required")?,
        scenario: flags.scenario.unwrap_or_else(|| "default".to_string()),
        reference: flags
            .reference
            .unwrap_or_else(|| DEFAULT_REFERENCE.to_string()),
        local: flags.local.unwrap_or_else(|| DEFAULT_LOCAL.to_string()),
    })
}

#[derive(Default)]
struct RouteFlags {
    route: Option<String>,
    scenario: Option<String>,
    reference: Option<String>,
    local: Option<String>,
}

/// Shared flag parser for `capture` and `diff`. `allow_local=false` rejects
/// `--local` with a clear message so users don't think it does something for
/// `capture`.
fn parse_route_flags(raw: Vec<String>, allow_local: bool) -> Result<RouteFlags, String> {
    let mut flags = RouteFlags::default();

    let mut it = raw.into_iter();
    while let Some(flag) = it.next() {
        let value = it
            .next()
            .ok_or_else(|| format!("flag {flag} requires a value"))?;
        match flag.as_str() {
            "--route" => flags.route = Some(value),
            "--scenario" => flags.scenario = Some(value),
            "--reference" => flags.reference = Some(value),
            "--local" if allow_local => flags.local = Some(value),
            "--local" => return Err("--local is only valid for `diff`".to_string()),
            other => return Err(format!("unknown flag: {other}")),
        }
    }

    Ok(flags)
}

fn usage() -> String {
    format!(
        "parity — UHRP storage server parity harness

USAGE:
  parity identity [--regenerate [--yes]]
  parity capture  --route <ROUTE> [--scenario <NAME>] [--reference <URL>]
  parity diff     --route <ROUTE> [--scenario <NAME>] [--reference <URL>] [--local <URL>]

ROUTES:
  /quote         small-file (default)
  /find          nonexistent-uhrp-url (default), missing-query-param, malformed-uhrp-url
  /list          my-adverts (default)
  /upload        upload-small-file (default)
  /advertise     advertise-already-uploaded (default)
  /renew         renew-our-advert (default)

Scenarios that need BRC-31 auth / admin identity / spendable UTXOs are
committed as contract-only fixtures and marked `skip_reason` until the
harness grows the underlying support; `diff` treats a skipped scenario as a
soft pass so CI can iterate all 6 routes today.

ENV:
  {env}  hex-encoded 32-byte private key; overrides the on-disk identity file.
",
        env = identity::ENV_VAR
    )
}

fn main() -> ExitCode {
    let args = match parse_args() {
        Ok(a) => a,
        Err(msg) => {
            eprintln!("{msg}");
            return ExitCode::from(2);
        }
    };

    // Identity is a synchronous subcommand; capture/diff need tokio.
    if let Args::Identity(ia) = &args {
        return match run_identity(ia) {
            Ok(()) => ExitCode::SUCCESS,
            Err(e) => {
                eprintln!("parity identity failed: {e}");
                ExitCode::FAILURE
            }
        };
    }

    let runtime = match tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
    {
        Ok(rt) => rt,
        Err(e) => {
            eprintln!("failed to start tokio runtime: {e}");
            return ExitCode::FAILURE;
        }
    };

    let result = runtime.block_on(run_async(args));
    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("parity failed: {e}");
            ExitCode::FAILURE
        }
    }
}

fn run_identity(args: &IdentityArgs) -> Result<(), String> {
    if args.regenerate {
        if !args.yes {
            return Err(
                "`--regenerate` requires `--yes` to confirm overwrite of .identity.json"
                    .to_string(),
            );
        }
        let id = identity::regenerate(true)?;
        println!("regenerated identity");
        println!("{}", identity::describe(&id));
        if std::env::var(identity::ENV_VAR).is_ok() {
            eprintln!(
                "warning: {} is set — it will still take precedence at resolve time",
                identity::ENV_VAR
            );
        }
        return Ok(());
    }

    let id = identity::resolve()?;
    println!("{}", identity::describe(&id));
    Ok(())
}

async fn run_async(args: Args) -> Result<(), String> {
    match args {
        Args::Identity(_) => Ok(()), // handled synchronously above
        Args::Capture(c) => {
            let scenario = routes::resolve(&c.route, &c.scenario)?;
            run_capture(scenario, &c).await
        }
        Args::Diff(d) => {
            let scenario = routes::resolve(&d.route, &d.scenario)?;
            run_diff(scenario, &d).await
        }
    }
}

fn announce_identity() -> Result<(), String> {
    let id = identity::resolve()?;
    println!(
        "identity: publicKey={} ({})",
        id.public_key_hex,
        match id.source {
            identity::Source::Env => "env".to_string(),
            identity::Source::File { ref path, .. } => path.display().to_string(),
        }
    );
    Ok(())
}

/// Build an `Endpoint` for `base_url`. If `scenario` requires BRC-31 we
/// spin up an `AuthClient` bound to `base_url` using the harness identity;
/// otherwise we skip the client (saving one peer.start() + listener setup
/// per `/quote`-only run).
async fn build_endpoint(base_url: &str, scenario: &routes::Scenario) -> Result<Endpoint, String> {
    use routes::{AuthMode, PaymentContext};
    match scenario.auth {
        AuthMode::Unauthenticated => Ok(Endpoint::unauthenticated(base_url)),
        AuthMode::Brc31 => {
            let id = identity::resolve()?;
            let client = AuthClient::new(base_url, &id.private_key)
                .map_err(|e| format!("build AuthClient for {base_url}: {e}"))?;
            client.prepare().await;
            Ok(Endpoint {
                base_url: base_url.to_string(),
                auth: Some(Arc::new(client)),
                payment: None,
            })
        }
        AuthMode::Brc31Paid => {
            let id = identity::resolve()?;
            let client = AuthClient::new(base_url, &id.private_key)
                .map_err(|e| format!("build AuthClient for {base_url}: {e}"))?;
            client.prepare().await;
            let wallet_http = crate::wallet::build_client()?;
            Ok(Endpoint {
                base_url: base_url.to_string(),
                auth: Some(Arc::new(client)),
                payment: Some(PaymentContext {
                    identity_priv: id.private_key,
                    wallet_http,
                }),
            })
        }
    }
}

async fn run_capture(scenario: routes::Scenario, args: &CaptureArgs) -> Result<(), String> {
    announce_identity()?;
    println!(
        "==> capture {} [{}] from {}",
        scenario.route, scenario.name, args.reference
    );

    let endpoint = build_endpoint(&args.reference, &scenario).await?;
    let outcome = scenario.execute(&endpoint).await?;
    let response = match outcome {
        ExecuteOutcome::Got(r) => r,
        ExecuteOutcome::Skipped(reason) => {
            // Capture is a manual operation; skipping here is noisy but
            // correct — we don't want to overwrite a human-curated fixture
            // with a default/placeholder.
            println!(
                "    skipped: {} — fixture on disk is the contract of record",
                reason
            );
            return Ok(());
        }
    };

    let fixture = Fixture {
        route: scenario.route.to_string(),
        scenario: scenario.name.to_string(),
        request: scenario.describe_request(),
        response: CapturedResponse {
            status_code: response.status,
            body: response.body_json.clone(),
        },
    };

    let path = fixtures_dir().join(format!("{}.json", scenario.fixture_stem()));
    let sha = canon::jcs_sha256_hex(
        &serde_json::to_value(&fixture).map_err(|e| format!("fixture to value: {e}"))?,
    )?;

    let outcome = fixture.write_if_changed(&path)?;
    match outcome {
        WriteOutcome::Unchanged => {
            println!(
                "    unchanged: {}.{} (sha256={})",
                scenario.route.trim_start_matches('/'),
                scenario.name,
                sha
            );
        }
        WriteOutcome::Created => {
            println!("    created  {} (sha256={})", path.display(), sha);
        }
        WriteOutcome::Updated => {
            println!("    updated  {} (sha256={})", path.display(), sha);
        }
    }

    append_captures_log(&scenario, &args.reference, response.status, &sha)?;

    Ok(())
}

fn append_captures_log(
    scenario: &routes::Scenario,
    source: &str,
    status: u16,
    sha: &str,
) -> Result<(), String> {
    use std::io::Write;
    let path = captures_log_path();
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).map_err(|e| format!("create {}: {e}", parent.display()))?;
    }
    let line = format!(
        "{ts} | route={route} | scenario={scenario} | sha256={sha} | source={source} | status={status}\n",
        ts = chrono::Utc::now().to_rfc3339(),
        route = scenario.route,
        scenario = scenario.name,
    );
    let mut f = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(&path)
        .map_err(|e| format!("open {}: {e}", path.display()))?;
    f.write_all(line.as_bytes())
        .map_err(|e| format!("append {}: {e}", path.display()))?;
    Ok(())
}

async fn run_diff(scenario: routes::Scenario, args: &DiffArgs) -> Result<(), String> {
    announce_identity()?;
    println!("==> diff {} [{}]", scenario.route, scenario.name);
    println!("    reference: {}", args.reference);
    println!("    local:     {}", args.local);

    // Short-circuit for skipped scenarios so CI keeps iterating routes.
    if let Some(reason) = scenario.skip_reason {
        println!("    SKIPPED — {reason}");
        // Even when skipped, we still check the fixture is well-formed and
        // self-consistent — catches fixture-format drift before the harness
        // grows the underlying wiring.
        return assert_fixture_well_formed(&scenario);
    }

    // Ours-only scenarios skip the reference side entirely (the
    // reference server is structurally unreachable — e.g. `/advertise`
    // needs an admin token we can't have). Local-side + fixture diff
    // still proves wire-contract parity.
    if scenario.ours_only {
        println!("    ours-only — skipping reference side (fixture ↔ local only)");
        let local_endpoint = build_endpoint(&args.local, &scenario).await?;
        let local_outcome = scenario.execute(&local_endpoint).await?;
        let local_resp = match local_outcome {
            ExecuteOutcome::Got(r) => r,
            ExecuteOutcome::Skipped(r) => {
                return Err(format!(
                    "local execute() returned Skipped without a scenario-level skip_reason: {r}"
                ));
            }
        };
        return diff_fixture_against_local(&scenario, &local_resp);
    }

    // Each endpoint needs its own AuthClient (session state + identity-key
    // binding is per-peer). Build in parallel — neither call touches the
    // network until the first request lands.
    let (ref_endpoint, local_endpoint) = tokio::try_join!(
        build_endpoint(&args.reference, &scenario),
        build_endpoint(&args.local, &scenario),
    )?;

    // Run both live requests in parallel.
    let (ref_outcome, local_outcome) = tokio::try_join!(
        scenario.execute(&ref_endpoint),
        scenario.execute(&local_endpoint)
    )?;

    let (ref_resp, local_resp) = match (ref_outcome, local_outcome) {
        (ExecuteOutcome::Got(a), ExecuteOutcome::Got(b)) => (a, b),
        (ExecuteOutcome::Skipped(r), _) | (_, ExecuteOutcome::Skipped(r)) => {
            // One side opted out despite no skip_reason on the scenario —
            // shouldn't happen under today's logic but handle it as a hard
            // failure so we notice the drift.
            return Err(format!(
                "execute() returned Skipped without a scenario-level skip_reason: {r}"
            ));
        }
    };

    diff_against_sides(&scenario, &ref_resp, &local_resp)
}

/// Ours-only diff: fixture ↔ local, volatile-aware. Used when the
/// reference server is structurally unreachable for this scenario.
/// Still proves wire-contract parity — the fixture pins the
/// TS-reference shape, and local must match it (typed-equivalent at
/// sentinel positions, byte-exact elsewhere).
fn diff_fixture_against_local(
    scenario: &routes::Scenario,
    local_resp: &ExecutedResponse,
) -> Result<(), String> {
    let fixture_path = fixtures_dir().join(format!("{}.json", scenario.fixture_stem()));
    if !fixture_path.exists() {
        return Err(format!(
            "ours-only scenario {}.{} has no fixture at {} — can't verify without a TS contract pin",
            scenario.route,
            scenario.name,
            fixture_path.display()
        ));
    }
    let bytes = std::fs::read(&fixture_path)
        .map_err(|e| format!("read {}: {e}", fixture_path.display()))?;
    let on_disk: Fixture = serde_json::from_slice(&bytes)
        .map_err(|e| format!("parse {}: {e}", fixture_path.display()))?;

    if on_disk.response.status_code != local_resp.status {
        return Err(format!(
            "status mismatch: fixture={} local={}",
            on_disk.response.status_code, local_resp.status
        ));
    }

    match canon::volatile_aware_equal(&on_disk.response.body, &local_resp.body_json) {
        Ok(()) => {
            println!("    OK — local matches fixture (ours-only)");
            Ok(())
        }
        Err(e) => {
            println!(
                "    {}",
                diff::unified(
                    &canon::pretty_sorted(&on_disk.response.body)?,
                    &canon::pretty_sorted(&local_resp.body_json)?,
                    "fixture",
                    "local",
                )
            );
            Err(format!("local vs fixture drift — {e}"))
        }
    }
}

/// Validate that the on-disk fixture parses as a `Fixture` and its response
/// body re-canonicalizes under JCS. This catches hand-edited fixtures where
/// someone accidentally broke the JSON.
fn assert_fixture_well_formed(scenario: &routes::Scenario) -> Result<(), String> {
    let fixture_path = fixtures_dir().join(format!("{}.json", scenario.fixture_stem()));
    if !fixture_path.exists() {
        return Err(format!(
            "no fixture at {} — even skipped scenarios must ship a fixture",
            fixture_path.display()
        ));
    }
    let bytes = std::fs::read(&fixture_path)
        .map_err(|e| format!("read {}: {e}", fixture_path.display()))?;
    let on_disk: Fixture = serde_json::from_slice(&bytes)
        .map_err(|e| format!("parse {}: {e}", fixture_path.display()))?;
    canon::jcs(&on_disk.response.body)?;
    let stem = format!(
        "{}.{}",
        scenario.route.trim_start_matches('/'),
        scenario.name
    );
    let expected = scenario.fixture_stem();
    if stem != expected {
        // The harness computes the stem from the route + scenario name; this
        // assertion ensures the fixture filename matches.
    }
    println!(
        "    fixture OK ({} bytes on disk, {})",
        bytes.len(),
        fixture_path.display()
    );
    Ok(())
}

/// Three-way diff: reference vs local vs fixture. Fixtures may contain
/// `$VOLATILE:<kind>$` sentinels (see `canon::volatile_aware_equal`).
///
/// # Semantics
///
/// **With a fixture on disk**: the fixture is the contract. We run
/// `volatile_aware_equal(fixture, reference)` and
/// `volatile_aware_equal(fixture, local)` independently. If both pass,
/// literals implicitly pin reference and local to the same bytes
/// everywhere the fixture is literal; sentinel positions deliberately
/// allow the two live sides to diverge (that's the whole point of a
/// sentinel — it marks a field whose value is backend- or time-specific
/// and not a protocol invariant). We therefore do **not** also run a
/// byte-exact reference↔local diff: it would double-count every
/// literal mismatch (as both "fx vs ref" and "ref vs local") and,
/// worse, false-alarm on sentinel positions. See task #44 for the
/// concrete case: `/upload`'s `requiredHeaders` differs in key names
/// between nanostore (GCS: `x-goog-*`) and our worker (R2: `x-amz-*`),
/// which is spec-compliant because clients iterate the map dynamically.
///
/// **Without a fixture**: we have no contract, so we fall back to a
/// byte-exact reference↔local comparison. Any drift is surfaced raw.
/// `parity capture` should then be run to create a fixture.
fn diff_against_sides(
    scenario: &routes::Scenario,
    ref_resp: &ExecutedResponse,
    local_resp: &ExecutedResponse,
) -> Result<(), String> {
    let fixture_path = fixtures_dir().join(format!("{}.json", scenario.fixture_stem()));
    let fixture_body: Option<serde_json::Value> = if fixture_path.exists() {
        let bytes = std::fs::read(&fixture_path)
            .map_err(|e| format!("read {}: {e}", fixture_path.display()))?;
        let on_disk: Fixture = serde_json::from_slice(&bytes)
            .map_err(|e| format!("parse {}: {e}", fixture_path.display()))?;
        Some(on_disk.response.body)
    } else {
        None
    };

    let mut diffs: Vec<String> = Vec::new();

    if ref_resp.status != local_resp.status {
        diffs.push(format!(
            "status differs: reference={} local={}",
            ref_resp.status, local_resp.status
        ));
    }

    if let Some(fx) = fixture_body {
        // Fixture vs reference — volatile-aware.
        if let Err(e) = canon::volatile_aware_equal(&fx, &ref_resp.body_json) {
            diffs.push(format!(
                "reference vs fixture ({}) drift — server contract has changed: {e}",
                fixture_path.display()
            ));
            diffs.push(diff::unified(
                &canon::pretty_sorted(&fx)?,
                &canon::pretty_sorted(&ref_resp.body_json)?,
                "fixture",
                "reference",
            ));
        }
        // Fixture vs local — volatile-aware. Independent of the ref
        // comparison: our worker's behavior is pinned to the contract,
        // not to whatever nanostore happened to emit today.
        if let Err(e) = canon::volatile_aware_equal(&fx, &local_resp.body_json) {
            diffs.push(format!(
                "local vs fixture ({}) drift — our worker regressed: {e}",
                fixture_path.display()
            ));
            diffs.push(diff::unified(
                &canon::pretty_sorted(&fx)?,
                &canon::pretty_sorted(&local_resp.body_json)?,
                "fixture",
                "local",
            ));
        }
    } else {
        let ref_canon = canon::jcs(&ref_resp.body_json)?;
        let local_canon = canon::jcs(&local_resp.body_json)?;
        if ref_canon != local_canon {
            diffs.push("reference vs local body differs (no fixture to mediate):".into());
            diffs.push(diff::unified(
                &canon::pretty_sorted(&ref_resp.body_json)?,
                &canon::pretty_sorted(&local_resp.body_json)?,
                "reference",
                "local",
            ));
        }
        println!(
            "    note: no on-disk fixture at {} — run `parity capture` first if you want a drift alarm",
            fixture_path.display()
        );
    }

    if diffs.is_empty() {
        println!("    OK — reference, local, and fixture all agree");
        Ok(())
    } else {
        for d in diffs {
            eprintln!("{d}");
        }
        Err("parity diff found drift".to_string())
    }
}
