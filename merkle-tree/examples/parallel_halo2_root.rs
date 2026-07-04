//! Parallel halo2-base Merkle root builder (prototype for the perf fix).
//!
//! The interior hash at every tree level is `poseidon(a, b)` per independent
//! pair, so a parallel build that hashes the SAME pairs in the SAME order
//! yields the IDENTICAL root as the serial `halo2base::build_tree_streaming`.
//! That invariant is asserted on a small random tree below before the full
//! 64M-leaf run is trusted.
//!
//! Usage:
//!   parallel_halo2_root <file> [limit]    # build + print root, timing
//!   parallel_halo2_root --validate        # assert parallel == serial (small tree)

use rayon::prelude::*;
use zkmist_merkle_tree::halo2base::{build_tree_streaming_with_depth, Hasher};
use zkmist_merkle_tree::{PADDING_SENTINEL, TREE_DEPTH};

fn parallel_root(addresses: &[[u8; 20]], depth: usize) -> [u8; 32] {
    let hasher = Hasher::new();
    let num_leaves = 1usize << depth;
    // leaf layer — parallelize (64M leaves dominate if left serial).
    let mut current: Vec<[u8; 32]> = addresses
        .par_iter()
        .map(|a| hasher.hash_leaf(a))
        .collect();
    current.resize(num_leaves, PADDING_SENTINEL);
    for _ in 0..depth {
        let n = current.len() / 2;
        let mut next: Vec<[u8; 32]> = vec![[0u8; 32]; n];
        // each pair is independent — parallelize. &Hasher is Sync (params are
        // plain field-element Vecs), so sharing it across rayon threads is safe.
        next.par_iter_mut().enumerate().for_each(|(i, slot)| {
            *slot = hasher.hash_interior(&current[2 * i], &current[2 * i + 1]);
        });
        current = next;
    }
    current[0]
}

fn load(path: &str, limit: Option<usize>) -> Vec<[u8; 20]> {
    use std::io::BufRead;
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

fn main() {
    let args: Vec<String> = std::env::args().collect();

    if args.get(1) == Some(&"--validate".to_string()) {
        // Assert parallel == serial production builder on a small random tree.
        let depth = 6;
        let addrs: Vec<[u8; 20]> = (0..(1u64 << depth))
            .map(|i| {
                let mut a = [0u8; 20];
                a[19] = (i % 251) as u8;
                a[18] = ((i / 251) % 251) as u8;
                a
            })
            .collect();
        let (serial_root, _) = build_tree_streaming_with_depth(&addrs, depth, None);
        let par_root = parallel_root(&addrs, depth);
        println!("serial  = 0x{}", hex::encode(serial_root));
        println!("parallel= 0x{}", hex::encode(par_root));
        assert_eq!(serial_root, par_root, "PARALLEL != SERIAL — do not trust it");
        println!("VALIDATED: parallel == serial at depth {depth}");
        return;
    }

    let path = args.get(1).expect("usage: parallel_halo2_root <file> [limit] | --validate");
    let limit: Option<usize> = args.get(2).map(|s| s.parse().unwrap());
    let addrs = load(path, limit);
    eprintln!("Loaded {} addresses; building depth-{} tree on {} cores...",
              addrs.len(), TREE_DEPTH, rayon::current_num_threads());
    let t = std::time::Instant::now();
    let root = parallel_root(&addrs, TREE_DEPTH);
    let dt = t.elapsed();
    println!("HALO2-BASE (parallel) root = 0x{}", hex::encode(root));
    println!("build time = {:.1}s on {} cores", dt.as_secs_f64(), rayon::current_num_threads());
    println!("committed KNOWN_MERKLE_ROOT = 0x00cf0fa589ba3f949eec2774dca17df0c00a99497b31d70b76767d4dba38c0ba");
    println!("matches committed? {}", hex::encode(root) == "00cf0fa589ba3f949eec2774dca17df0c00a99497b31d70b76767d4dba38c0ba");
}
