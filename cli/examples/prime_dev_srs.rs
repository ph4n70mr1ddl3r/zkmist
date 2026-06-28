//! One-shot dev SRS primer for local proving tests.
//!
//! Generates `Params::<G1Affine>::new(k)` and writes it to the CLI cache path
//! (`~/.zkmist/cache/v2_params_k{}.bin`) so `test_real_kzg_proof_round_trip`
//! and any `ZKMIST_DEV_SRS=1` prove run loads it instantly instead of
//! regenerating the ~2 GB file each time.
//!
//! ⚠️  DEV/TEST ONLY — this generates a RANDOM, FORGEABLE SRS. Never use proofs
//! from it on mainnet. Production loads the pinned PSE perpetual-powers-of-tau
//! SRS instead (see `docs/kzg-srs.md`). The only reason this exists is that
//! `Params::new(k)` is pathologically slow at k=23 in this halo2 version
//! (sequential 2^k point mults — tens of minutes), so priming the cache once
//! keeps the proving test runnable.
//!
//! Usage: `cargo run --release -p zkmist-cli --example prime_dev_srs -- [k]`
//! (k defaults to 23).

use halo2_proofs::poly::commitment::Params;
use halo2curves::bn256::G1Affine;

fn main() {
    let k: u32 = std::env::args()
        .nth(1)
        .and_then(|s| s.parse().ok())
        .unwrap_or(23);

    let dir = dirs::home_dir()
        .expect("home dir")
        .join(".zkmist")
        .join("cache");
    std::fs::create_dir_all(&dir).expect("create cache dir");
    let path = dir.join(format!("v2_params_k{}.bin", k));

    if path.exists() {
        eprintln!(
            "✅ cache already exists (k={}): {} ({} bytes)",
            k,
            path.display(),
            std::fs::metadata(&path).map(|m| m.len()).unwrap_or(0)
        );
        return;
    }

    eprintln!(
        "Generating dev SRS at k={} (slow: sequential 2^{} = {} point mults)...",
        k,
        k,
        1u64 << k
    );
    let t = std::time::Instant::now();
    // Periodic heartbeat so a long run isn't silent.
    let built = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
    let done = built.clone();
    let hb = std::thread::spawn(move || {
        let mut secs = 0u64;
        while !done.load(std::sync::atomic::Ordering::Relaxed) {
            std::thread::sleep(std::time::Duration::from_secs(15));
            secs += 15;
            eprintln!("   ...still generating ({}s elapsed)", secs);
        }
    });

    let params = Params::<G1Affine>::new(k);
    built.store(true, std::sync::atomic::Ordering::Relaxed);
    let _ = hb.join();
    let gen_secs = t.elapsed().as_secs_f64();
    eprintln!(
        "   generated in {:.1}s; writing cache to {}",
        gen_secs,
        path.display()
    );

    let f = std::fs::File::create(&path).expect("create cache file");
    let mut w = std::io::BufWriter::new(f);
    params.write(&mut w).expect("write params");
    eprintln!("✅ done (k={}, {:.1}s, {:.0} MiB)", k, gen_secs, std::fs::metadata(&path).unwrap().len() as f64 / (1024.0 * 1024.0));
}
