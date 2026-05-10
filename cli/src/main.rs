//! ZKMist CLI — claim tool for the ZKMist airdrop
//!
//! Commands:
//!   zkmist fetch    — Download eligibility list from IPFS
//!   zkmist prove    — Generate ZK proof locally
//!   zkmist submit   — Submit proof to ZKMAirdrop contract
//!   zkmist verify   — Verify proof locally
//!   zkmist check    — Check if address is eligible
//!   zkmist status   — Show claim window status

use clap::{Parser, Subcommand};

#[derive(Parser)]
#[command(name = "zkmist", version, about = "ZKMist (ZKM) claim tool")]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Download eligibility list from IPFS (~1.3 GB). Builds and caches the Merkle tree.
    Fetch,

    /// Generate ZK proof (interactive). Uses cached Merkle tree from `fetch`.
    Prove,

    /// Submit proof to ZKMAirdrop contract on Base.
    Submit {
        /// Path to proof.json
        proof_file: String,
    },

    /// Verify proof locally: validates the STARK proof and checks journal contents.
    Verify {
        /// Path to proof.json
        proof_file: String,
    },

    /// Check if an address is eligible (requires downloaded eligibility list).
    Check {
        /// Ethereum address to check
        address: String,
    },

    /// Show claim window status, claims remaining, total supply.
    Status,
}

#[tokio::main]
async fn main() {
    let cli = Cli::parse();

    match cli.command {
        Commands::Fetch => {
            eprintln!("TODO: implement zkmist fetch");
            eprintln!("  1. Download eligibility list from IPFS (~1.3 GB)");
            eprintln!("  2. Build Merkle tree (~4 GB RAM required)");
            eprintln!("  3. Cache tree to ~/.zkmist/");
        }
        Commands::Prove => {
            eprintln!("TODO: implement zkmist prove");
            eprintln!("  1. Load cached Merkle tree");
            eprintln!("  2. Prompt for private key (hidden)");
            eprintln!("  3. Derive address, verify eligibility");
            eprintln!("  4. Prompt for recipient address (validate != 0x0)");
            eprintln!("  5. Build Merkle proof for address");
            eprintln!("  6. Run RISC Zero zkVM guest program");
            eprintln!("  7. Save proof.json");
        }
        Commands::Submit { proof_file } => {
            eprintln!("TODO: implement zkmist submit {}", proof_file);
        }
        Commands::Verify { proof_file } => {
            eprintln!("TODO: implement zkmist verify {}", proof_file);
        }
        Commands::Check { address } => {
            eprintln!("TODO: implement zkmist check {}", address);
        }
        Commands::Status => {
            eprintln!("TODO: implement zkmist status");
        }
    }
}
