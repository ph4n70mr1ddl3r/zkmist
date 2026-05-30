//! On-chain monitoring for deployed ZKMist contracts.
//!
//! Polls the ZKMAirdrop contract on Base and reports:
//!   - Total claims, claims remaining
//!   - Total supply, burned tokens
//!   - Claim window status
//!   - Anomaly detection (surge, supply mismatch)
//!
//! Usage:
//!   cargo run -p zkmist-tools --bin monitor -- <airdrop_address> [OPTIONS]
//!
//! Options:
//!   --rpc <url>        RPC URL (default: https://mainnet.base.org)
//!   --interval <secs>  Polling interval in seconds (default: 60)
//!   --once             Run once and exit (default: continuous)

use std::str::FromStr;

use alloy::primitives::Address;
use alloy::providers::{Provider, ProviderBuilder};
use alloy::sol;

sol! {
    #[sol(rpc)]
    interface IZKMMonitor {
        function totalClaims() external view returns (uint256);
        function claimsRemaining() external view returns (uint256);
        function isClaimWindowOpen() external view returns (bool);
        function isClaimed(bytes32 nullifier) external view returns (bool);
        function token() external view returns (address);
        function CLAIM_AMOUNT() external view returns (uint256);
        function MAX_CLAIMS() external view returns (uint256);
        function merkleRoot() external view returns (bytes32);
    }
}

sol! {
    #[sol(rpc)]
    interface IZKMTokenMonitor {
        function totalSupply() external view returns (uint256);
        function minter() external view returns (address);
        function MAX_SUPPLY() external view returns (uint256);
    }
}

const DEFAULT_RPC: &str = "https://mainnet.base.org";
const CLAIM_AMOUNT_ZKM: u128 = 10_000;
const WEI_PER_ZKM: u128 = 1_000_000_000_000_000_000;

fn main() {
    let args: Vec<String> = std::env::args().collect();
    if args.len() < 2 || args[1] == "--help" || args[1] == "-h" {
        eprintln!("ZKMist On-Chain Monitor");
        eprintln!();
        eprintln!("Usage: monitor <airdrop_address> [OPTIONS]");
        eprintln!();
        eprintln!("Options:");
        eprintln!("  --rpc <url>        RPC URL (default: {})", DEFAULT_RPC);
        eprintln!("  --interval <secs>  Polling interval (default: 60)");
        eprintln!("  --once             Run once and exit");
        eprintln!();
        eprintln!("Example:");
        eprintln!("  monitor 0x1234...5678 --rpc https://mainnet.base.org --interval 30");
        std::process::exit(0);
    }

    let airdrop_addr: Address = args[1]
        .parse()
        .unwrap_or_else(|e| panic!("Invalid address '{}': {}", args[1], e));

    let mut rpc_url = DEFAULT_RPC.to_string();
    let mut interval_secs: u64 = 60;
    let mut once = false;

    let mut i = 2;
    while i < args.len() {
        match args[i].as_str() {
            "--rpc" => {
                rpc_url = args[i + 1].clone();
                i += 2;
            }
            "--interval" => {
                interval_secs = args[i + 1].parse().unwrap_or(60);
                i += 2;
            }
            "--once" => {
                once = true;
                i += 1;
            }
            _ => {
                eprintln!("Unknown option: {}", args[i]);
                std::process::exit(1);
            }
        }
    }

    let rt = tokio::runtime::Runtime::new().unwrap();

    rt.block_on(async move {
        let url: reqwest::Url = rpc_url.parse().expect("Invalid RPC URL");
        let provider = ProviderBuilder::new().connect_http(url);

        eprintln!("╔══════════════════════════════════════════════════╗");
        eprintln!("║  ZKMist On-Chain Monitor                         ║");
        eprintln!("╚══════════════════════════════════════════════════╝");
        eprintln!("  Airdrop:  {}", airdrop_addr);
        eprintln!("  RPC:      {}", rpc_url);
        eprintln!("  Interval: {}s", interval_secs);
        eprintln!();

        let mut prev_claims: u64 = 0;

        loop {
            match poll_state(&provider, airdrop_addr).await {
                Ok(state) => {
                    let claims_delta = if prev_claims > 0 {
                        state.total_claims.saturating_sub(prev_claims)
                    } else {
                        0
                    };
                    prev_claims = state.total_claims;

                    let timestamp = chrono_now();
                    eprintln!(
                        "[{}] claims={} remaining={} supply={:.1}M ZKM status={}",
                        timestamp,
                        state.total_claims,
                        state.claims_remaining,
                        state.on_chain_supply_zkm as f64 / 1e6,
                        if state.is_open {
                            "OPEN"
                        } else if state.total_claims >= 1_000_000 {
                            "CAP"
                        } else {
                            "CLOSED"
                        },
                    );

                    if claims_delta > 0 {
                        eprintln!("  ↳ {} new claims this interval", claims_delta);
                    }

                    // Anomaly detection
                    if claims_delta > 10_000 {
                        eprintln!("  ⚠️  ALERT: >10,000 claims in one interval (surge detected)");
                    }

                    let expected_supply = state.total_claims as u128 * CLAIM_AMOUNT_ZKM;
                    if state.on_chain_supply_zkm != expected_supply {
                        eprintln!(
                            "  ⚠️  ALERT: Supply mismatch! expected={} ZKM, on-chain={} ZKM",
                            expected_supply, state.on_chain_supply_zkm
                        );
                    }
                }
                Err(e) => {
                    eprintln!("[{}] ⚠️  Poll failed: {}", chrono_now(), e);
                }
            }

            if once {
                break;
            }
            tokio::time::sleep(std::time::Duration::from_secs(interval_secs)).await;
        }
    });
}

struct ChainState {
    total_claims: u64,
    claims_remaining: u64,
    is_open: bool,
    on_chain_supply_zkm: u128,
}

async fn poll_state(
    provider: &alloy::providers::RootProvider<alloy::transports::http::Http<reqwest::Client>>,
    airdrop_addr: Address,
) -> Result<ChainState, String> {
    let airdrop = IZKMMonitor::new(airdrop_addr, provider);

    let total_claims_u256 = airdrop
        .totalClaims()
        .call()
        .await
        .map_err(|e| format!("totalClaims: {}", e))?
        ._0;
    let total_claims: u64 = total_claims_u256
        .try_into()
        .map_err(|e: alloy::primitives::ruint::FromUintError<u64>| format!("overflow: {}", e))?;

    let claims_remaining_u256 = airdrop
        .claimsRemaining()
        .call()
        .await
        .map_err(|e| format!("claimsRemaining: {}", e))?
        ._0;
    let claims_remaining: u64 = claims_remaining_u256
        .try_into()
        .map_err(|e: alloy::primitives::ruint::FromUintError<u64>| format!("overflow: {}", e))?;

    let is_open = airdrop
        .isClaimWindowOpen()
        .call()
        .await
        .map_err(|e| format!("isClaimWindowOpen: {}", e))?
        ._0;

    let token_addr = airdrop
        .token()
        .call()
        .await
        .map_err(|e| format!("token: {}", e))?
        ._0;
    let token = IZKMTokenMonitor::new(token_addr, provider);

    let supply_wei = token
        .totalSupply()
        .call()
        .await
        .map_err(|e| format!("totalSupply: {}", e))?
        ._0;
    let supply_u128: u128 = supply_wei
        .try_into()
        .map_err(|e: alloy::primitives::ruint::FromUintError<u128>| format!("overflow: {}", e))?;
    let supply_zkm = supply_u128 / WEI_PER_ZKM;

    Ok(ChainState {
        total_claims,
        claims_remaining,
        is_open,
        on_chain_supply_zkm: supply_zkm,
    })
}

/// Simple timestamp without chrono dependency.
fn chrono_now() -> String {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default();
    let secs = now.as_secs();
    let days = (secs / 86400) as i64;
    let (y, m, d) = days_to_ymd(days);
    let s = (secs % 86400) as u32;
    format!(
        "{:04}-{:02}-{:02} {:02}:{:02}:{:02}",
        y,
        m,
        d,
        s / 3600,
        (s % 3600) / 60,
        s % 60
    )
}

fn days_to_ymd(mut days: i64) -> (i64, u32, u32) {
    days += 719468;
    let era = (if days >= 0 { days } else { days - 146096 }) / 146097;
    let doe = days - era * 146097;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = if m <= 2 { y + 1 } else { y };
    (y, m as u32, d as u32)
}
