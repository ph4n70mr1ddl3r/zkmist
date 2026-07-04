//! Benchmark the (now parallel) halo2-base production tree builder and confirm
//! the recomputed root matches the committed `KNOWN_MERKLE_ROOT`.
//!
//! Usage:
//!   parallel_halo2_root <addresses.csv> [limit]
//!
//! This exercises the REAL production path
//! (`zkmist_merkle_tree::halo2base::build_tree_streaming`) — no bespoke hasher.
//! Correctness of the parallel builder itself is locked by the crate's test
//! suite (`test_halo2base_streaming_matches_in_memory`,
//! `test_merkle_tree_halo2base_round_trip`); this example just times it at
//! production scale and re-checks the committed root.

use std::io::{BufRead, Write};
use zkmist_merkle_tree::halo2base::build_tree_streaming;
use zkmist_merkle_tree::TREE_DEPTH;

fn load(path: &str, limit: Option<usize>) -> Vec<[u8; 20]> {
    let r = std::io::BufReader::with_capacity(64 * 1024 * 1024, std::fs::File::open(path).unwrap());
    let mut out = Vec::new();
    for line in r.lines() {
        let l = line.unwrap().trim().to_string();
        if l.is_empty() || l.starts_with("address") || l.starts_with("qualified") {
            continue;
        }
        let h = l.strip_prefix("0x").unwrap_or(&l);
        let mut a = [0u8; 20];
        hex::decode_to_slice(h, &mut a).unwrap();
        out.push(a);
        if matches!(limit, Some(n) if n > 0 && out.len() >= n) {
            break;
        }
    }
    out
}

macro_rules! emit {
    ($($a:tt)*) => {{ println!($($a)*); let _ = std::io::stdout().flush(); }};
}

fn main() {
    let path = std::env::args().nth(1).expect("usage: parallel_halo2_root <file> [limit]");
    let limit: Option<usize> = std::env::args().nth(2).map(|s| s.parse().unwrap());

    let addrs = load(&path, limit);
    emit!("Loaded {} addresses; building depth-{} production tree on {} rayon threads...",
          addrs.len(), TREE_DEPTH, rayon::current_num_threads());

    let t = std::time::Instant::now();
    let (root, _) = build_tree_streaming(&addrs, None);
    let dt = t.elapsed();

    emit!("HALO2-BASE production root = 0x{}", hex::encode(root));
    emit!("build time = {:.1}s on {} cores", dt.as_secs_f64(), rayon::current_num_threads());
    emit!("committed KNOWN_MERKLE_ROOT = 0x00cf0fa589ba3f949eec2774dca17df0c00a99497b31d70b76767d4dba38c0ba");
    emit!("matches committed? {}",
          hex::encode(root) == "00cf0fa589ba3f949eec2774dca17df0c00a99497b31d70b76767d4dba38c0ba");
}
