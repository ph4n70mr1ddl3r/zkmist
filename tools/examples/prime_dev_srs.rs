//! One-shot dev SRS primer for the PSE-format SRS tooling self-test.
//!
//! Generates a PSE `ParamsKZG::setup(k)` (a RANDOM, FORGEABLE SRS) and writes
//! it to `~/.zkmist/cache/v2_params_k{k}.bin`. `scripts/fetch-pse-srs.sh` uses
//! this in SELF-TEST mode to exercise the `verify-srs` / `truncate-srs`
//! plumbing against a small synthetic file without needing the real ceremony
//! transcript.
//!
//! ⚠️  DEV/TEST ONLY — this generates a RANDOM, FORGEABLE SRS. Never use proofs
//! from it on mainnet. Production loads the pinned PSE perpetual-powers-of-tau
//! SRS instead (see `docs/kzg-srs.md`). Lives in `zkmist-tools` (not the CLI)
//! because the CLI now builds against the axiom halo2-base backend and no
//! longer links the PSE `halo2_proofs` directly; the SRS verify/truncate tools
//! here do, so this primer shares their exact (PSE) serialization format.
//!
//! Usage: `cargo run --release -p zkmist-tools --example prime_dev_srs -- [k]`
//! (k defaults to 23).

use halo2_proofs::poly::{commitment::Params as _, kzg::commitment::ParamsKZG};

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

    let params = ParamsKZG::<halo2curves::bn256::Bn256>::setup(k, &mut rand::rngs::OsRng);
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
    eprintln!(
        "✅ done (k={}, {:.1}s, {:.0} MiB)",
        k,
        gen_secs,
        std::fs::metadata(&path).unwrap().len() as f64 / (1024.0 * 1024.0)
    );
}
