//! verify-srs-from-ptau — gold-standard KZG SRS provenance check.
//!
//! Confirms that the pinned halo2 KZG SRS is the genuine PSE perpetual-powers-
//! of-tau ceremony output, by comparing it **byte-for-byte** against the public
//! ceremony transcript (`.ptau`). If every τ-power and G2 point matches, the
//! deployer did NOT substitute a toxic-waste file — the pinned SRS IS the
//! ceremony output. This is the strongest provenance check short of re-running
//! phase2 extraction yourself (docs/kzg-srs.md §2).
//!
//! # Why byte-comparison suffices
//!
//! The halo2 `ParamsKZG` file is `[k][g[]][g_lagrange[]][g2][s_g2]` where
//! `g[]` = the secret τ-powers in G1, `g2 = [1]_2`, `s_g2 = [τ]_2`. These ARE
//! the SRS's secret (they encode the trapdoor τ). The ceremony transcript's
//! section 2/3 contain the SAME τ-powers/G2 in the SAME RawBytes (Montgomery)
//! encoding. So:
//!   - `g[]`, `g2`, `s_g2` byte-identical ⟹ the pinned SRS embeds the
//!     ceremony's exact trapdoor-powers. Soundness is then the ceremony's
//!     (1-of-N + beacon), not the deployer's file-swap.
//!   - `g_lagrange` is a deterministic IFFT of `g[]`; its correctness is implied
//!     by the file loading as a valid `ParamsKZG` (`verify-srs`) and by proofs
//!     verifying on-chain (the round-trip tests) — a wrong `g_lagrange` would
//!     make every proof fail to verify, which they do not.
//!
//! # Source
//!
//! Ceremony: https://github.com/privacy-ethereum/perpetualpowersoftau (87
//! participants). The k=23 transcript, beaconed with Ethereum beacon-chain slot
//! 7,325,000 randao (announced on-chain in advance), is published as
//! `ppot_0080_23.ptau` (S3 link in the repo README). The beacon (future,
//! unpredictable Ethereum data) destroys the trapdoor regardless of participant
//! honesty.
//!
//! Usage:
//!   cargo run --release -p zkmist-tools --bin verify-srs-from-ptau -- \
//!       <pinned.bin> <ppot_0080_23.ptau>
//! Exit 0 = all checks pass; non-zero on any mismatch.

use std::io::{Read, Seek, SeekFrom};

const CHUNK: usize = 64 * 1024 * 1024; // 64 MiB streaming compare

fn main() {
    let args: Vec<String> = std::env::args().collect();
    if args.len() != 3 {
        eprintln!("usage: verify-srs-from-ptau <pinned-halo2-params.bin> <ceremony.ptau>");
        std::process::exit(2);
    }
    let pin_path = &args[1];
    let ptau_path = &args[2];

    // ── read k from the pinned halo2 file ──
    let mut pin = std::fs::File::open(pin_path).expect("open pinned file");
    let mut u4 = [0u8; 4];
    pin.read_exact(&mut u4).unwrap();
    let k = u32::from_le_bytes(u4);
    assert!((8..=28).contains(&k), "pinned file k={k} implausible");
    let n = 1usize << k;
    let g_off = 4usize;
    let g_len = n * 64; // bytes of g[]
    let g2_off = 4 + 2 * g_len; // g[] + g_lagrange[]
    println!("pinned halo2 SRS: k={k}, n=2^{k}={n} ({})", path_size(pin_path));

    // ── parse the .ptau section table ──
    let mut ptau = std::fs::File::open(ptau_path).expect("open .ptau");
    let mut magic = [0u8; 4];
    ptau.read_exact(&mut magic).unwrap();
    assert_eq!(&magic, b"ptau", "not a snarkjs .ptau");
    ptau.read_exact(&mut u4).unwrap(); // version
    ptau.read_exact(&mut u4).unwrap();
    let nsec = u32::from_le_bytes(u4) as usize;
    let mut secs: std::collections::BTreeMap<u32, u64> = std::collections::BTreeMap::new();
    let mut s8 = [0u8; 8];
    for _ in 0..nsec {
        ptau.read_exact(&mut u4).unwrap();
        let id = u32::from_le_bytes(u4);
        ptau.read_exact(&mut s8).unwrap();
        let sz = i64::from_le_bytes(s8);
        let pos = ptau.stream_position().unwrap();
        secs.insert(id, pos);
        ptau.seek(SeekFrom::Current(sz)).unwrap();
    }
    // section 1: power
    ptau.seek(SeekFrom::Start(secs[&1])).unwrap();
    ptau.read_exact(&mut u4).unwrap();
    let n8 = u32::from_le_bytes(u4) as usize;
    let mut q = vec![0u8; n8];
    ptau.read_exact(&mut q).unwrap();
    ptau.read_exact(&mut u4).unwrap();
    let power = u32::from_le_bytes(u4);
    println!("ceremony .ptau: power={power}, sections={nsec} ({})", path_size(ptau_path));
    assert!(power >= k, "ceremony power {power} < pinned k {k}; cannot truncate");

    let sec2 = secs[&2];
    let sec3 = secs[&3];

    // ── compare g[], g2, s_g2 byte-for-byte (streaming) ──
    println!("\nVerifying pinned SRS == ceremony transcript:");
    let ok_g = cmp("g[]  (τ-G1 powers)", &mut pin, g_off as u64, &mut ptau, sec2, g_len);
    let ok_g2 = cmp("g2   ([1]_2)", &mut pin, g2_off as u64, &mut ptau, sec3, 128);
    let ok_sg2 = cmp("s_g2 ([τ]_2)", &mut pin, (g2_off + 128) as u64, &mut ptau, sec3 + 128, 128);

    println!();
    if ok_g && ok_g2 && ok_sg2 {
        println!("✅✅✅ PROVENANCE CONFIRMED: every τ-power + G2 in the pinned halo2 SRS is");
        println!("   byte-identical to the public beaconed ceremony transcript. The deployer");
        println!("   did NOT substitute a toxic-waste file. Remaining trust = the ceremony");
        println!("   itself (1-of-87 participants OR the beacon honest) — inherent to KZG.");
        std::process::exit(0);
    } else {
        println!("❌ MISMATCH — the pinned SRS is NOT the ceremony transcript. Do NOT use it.");
        std::process::exit(1);
    }
}

/// Streaming byte-comparison of `len` bytes starting at `pin_pos` in `pin`
/// vs `ptau_pos` in `ptau`. Returns true if identical.
fn cmp(
    label: &str,
    pin: &mut std::fs::File,
    pin_pos: u64,
    ptau: &mut std::fs::File,
    ptau_pos: u64,
    len: usize,
) -> bool {
    pin.seek(SeekFrom::Start(pin_pos)).unwrap();
    ptau.seek(SeekFrom::Start(ptau_pos)).unwrap();
    let mut buf_a = vec![0u8; CHUNK.min(len)];
    let mut buf_b = vec![0u8; buf_a.len()];
    let mut done = 0usize;
    while done < len {
        let want = buf_a.len().min(len - done);
        pin.read_exact(&mut buf_a[..want]).unwrap();
        ptau.read_exact(&mut buf_b[..want]).unwrap();
        if buf_a[..want] != buf_b[..want] {
            for i in 0..want {
                if buf_a[i] != buf_b[i] {
                    eprintln!("  {label}: ❌ DIFFERS at byte {} (pin={:02x} ptau={:02x})",
                        done + i, buf_a[i], buf_b[i]);
                    return false;
                }
            }
        }
        done += want;
    }
    println!("  {label}: {len} bytes -> ✅ byte-identical");
    true
}

fn path_size(p: &str) -> String {
    let sz = std::fs::metadata(p).map(|m| m.len()).unwrap_or(0);
    if sz >= 1_000_000_000 {
        format!("{:.2} GB", sz as f64 / 1e9)
    } else if sz >= 1_000_000 {
        format!("{:.1} MB", sz as f64 / 1e6)
    } else {
        format!("{sz} B")
    }
}
