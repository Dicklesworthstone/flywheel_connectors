//! Redaction-safe `StatPack` artifact generator for hybrid signing verification.

#![allow(
    clippy::cast_possible_truncation,
    clippy::cast_precision_loss,
    clippy::cast_sign_loss,
    clippy::missing_errors_doc,
    clippy::print_stdout
)]

use std::{
    env,
    error::Error,
    fs,
    hint::black_box,
    path::{Path, PathBuf},
    time::Instant,
};

use fcp_bench::stats::StatPack;
use fcp_crypto::{
    Ed25519SigningKey, HybridSignedObjectKind, MlDsa65SigningKey, PqSigningPolicy, SignedEnvelope,
    signing_bytes_for_payload,
};
use serde::Serialize;
use serde_json::{Value, json};

const DEFAULT_SAMPLE_COUNT: usize = 10_000;
const DEFAULT_RESAMPLES: usize = 400;
const EVIDENCE_SCHEMA: &str = "fcp.pq-signing-overhead.v1";
const PQ_SIGNING_BUDGET_MS: f64 = 2.0;

#[derive(Debug)]
struct Config {
    samples: usize,
    statpack_out: PathBuf,
    machine_class: String,
    git_sha: String,
}

#[derive(Debug, Clone, Serialize)]
struct BenchPayload {
    id: String,
    body: Vec<u8>,
    seq: u64,
}

fn main() -> Result<(), Box<dyn Error>> {
    let config = Config::from_args(env::args().skip(1))?;
    let evidence = run_benchmark(&config)?;

    if let Some(parent) = config.statpack_out.parent() {
        fs::create_dir_all(parent)?;
    }

    let artifact = serde_json::to_string_pretty(&evidence)?;
    fs::write(&config.statpack_out, format!("{artifact}\n"))?;
    println!("{artifact}");
    Ok(())
}

impl Config {
    fn from_args(args: impl IntoIterator<Item = String>) -> Result<Self, String> {
        let mut samples = DEFAULT_SAMPLE_COUNT;
        let mut statpack_out = None;
        let mut machine_class = None;
        let mut git_sha = env::var("FCP_GIT_SHA").ok();
        let mut iter = args.into_iter();

        while let Some(arg) = iter.next() {
            match arg.as_str() {
                "--samples" => {
                    let raw = next_value(&mut iter, "--samples")?;
                    samples = raw
                        .parse::<usize>()
                        .map_err(|err| format!("invalid --samples value {raw:?}: {err}"))?;
                }
                "--statpack-out" => {
                    statpack_out = Some(PathBuf::from(next_value(&mut iter, "--statpack-out")?));
                }
                "--machine-class" => {
                    machine_class = Some(next_value(&mut iter, "--machine-class")?);
                }
                "--git-sha" => {
                    git_sha = Some(next_value(&mut iter, "--git-sha")?);
                }
                "--bench" => {}
                "--help" | "-h" => {
                    print_usage();
                    std::process::exit(0);
                }
                unknown => return Err(format!("unknown argument {unknown:?}\n{}", usage())),
            }
        }

        let statpack_out =
            statpack_out.ok_or_else(|| format!("missing --statpack-out\n{}", usage()))?;
        let machine_class =
            machine_class.unwrap_or_else(|| infer_machine_class(&statpack_out).to_string());
        let git_sha = git_sha.unwrap_or_else(|| infer_git_sha(&statpack_out).to_string());

        if samples == 0 {
            return Err("--samples must be greater than zero".to_string());
        }

        Ok(Self {
            samples,
            statpack_out,
            machine_class,
            git_sha,
        })
    }
}

fn run_benchmark(config: &Config) -> Result<Value, Box<dyn Error>> {
    let classical_key = Ed25519SigningKey::from_bytes(&[0x31; 32])?;
    let pq_key = MlDsa65SigningKey::from_seed(&[0x53; 32])?;
    let classical_verifying_key = classical_key.verifying_key();
    let pq_verifying_key = pq_key.verifying_key();
    let payload = BenchPayload {
        id: "phase-n-pq-signing-overhead".to_string(),
        body: vec![0xA5; 512],
        seq: 42,
    };
    let signing_bytes =
        signing_bytes_for_payload(HybridSignedObjectKind::CapabilityToken, &payload)?;
    let hybrid_envelope = SignedEnvelope::sign(
        HybridSignedObjectKind::CapabilityToken.as_str(),
        payload.clone(),
        &signing_bytes,
        &classical_key,
        &pq_key,
    )?;
    let baseline_envelope = SignedEnvelope::sign_with_policy(
        HybridSignedObjectKind::CapabilityToken.as_str(),
        payload,
        &signing_bytes,
        PqSigningPolicy::ClassicalOnly,
        Some(&classical_key),
        None,
    )?;

    warm_up(
        &hybrid_envelope,
        &baseline_envelope,
        &signing_bytes,
        &classical_verifying_key,
        pq_verifying_key,
    )?;

    let hybrid_samples = collect_samples(config.samples, || {
        sample_hybrid_verify(
            &hybrid_envelope,
            &signing_bytes,
            &classical_verifying_key,
            pq_verifying_key,
        )
    })?;
    let baseline_samples = collect_samples(config.samples, || {
        sample_classical_verify(&baseline_envelope, &signing_bytes, &classical_verifying_key)
    })?;

    let mut baseline_pack = StatPack::with_resamples(&baseline_samples, DEFAULT_RESAMPLES);
    baseline_pack.welch_t = 0.0;
    let mut hybrid_pack = StatPack::with_resamples(&hybrid_samples, DEFAULT_RESAMPLES);
    let comparison = hybrid_pack.compare_welch(&baseline_pack);
    hybrid_pack.welch_t =
        finite_welch_t(comparison.t, &hybrid_pack, &baseline_pack, config.samples);
    let welch_p = finite_welch_p(comparison.p_value, hybrid_pack.welch_t);
    let p99_ci = bootstrap_p99_ci(&hybrid_samples, DEFAULT_RESAMPLES);
    let verdict = if hybrid_pack.p99 <= PQ_SIGNING_BUDGET_MS && p99_ci[1] <= PQ_SIGNING_BUDGET_MS {
        "pass"
    } else {
        "fail"
    };

    Ok(json!({
        "schema": EVIDENCE_SCHEMA,
        "machine_class": config.machine_class,
        "artifact_path": artifact_path(&config.statpack_out),
        "git_sha": config.git_sha,
        "sample_count": config.samples,
        "verify_hybrid": hybrid_pack.to_json_value(),
        "baseline_classical_verify": baseline_pack.to_json_value(),
        "welch_p": welch_p,
        "bootstrap_p99_ci_ms": p99_ci,
        "verdict": verdict,
    }))
}

fn finite_welch_t(
    value: f64,
    observed: &StatPack,
    baseline: &StatPack,
    sample_count: usize,
) -> f64 {
    if value.is_finite() {
        return value;
    }

    let sample_count = sample_count.max(1) as f64;
    let standard_error = ((observed.std * observed.std / sample_count)
        + (baseline.std * baseline.std / sample_count))
        .sqrt();
    if standard_error <= f64::EPSILON {
        0.0
    } else {
        (observed.mean - baseline.mean) / standard_error
    }
}

fn finite_welch_p(value: f64, welch_t: f64) -> f64 {
    if value.is_finite() {
        value.clamp(0.0, 1.0)
    } else if welch_t.abs() <= f64::EPSILON {
        1.0
    } else {
        0.0
    }
}

fn warm_up(
    hybrid_envelope: &SignedEnvelope<BenchPayload>,
    baseline_envelope: &SignedEnvelope<BenchPayload>,
    signing_bytes: &[u8],
    classical_verifying_key: &fcp_crypto::Ed25519VerifyingKey,
    pq_verifying_key: &fcp_crypto::MlDsa65VerifyingKey,
) -> Result<(), Box<dyn Error>> {
    for _ in 0..128 {
        black_box(hybrid_envelope.verify(
            signing_bytes,
            classical_verifying_key,
            pq_verifying_key,
        )?);
        black_box(baseline_envelope.verify_with_policy(
            signing_bytes,
            PqSigningPolicy::ClassicalOnly,
            Some(classical_verifying_key),
            None,
        )?);
    }
    Ok(())
}

fn collect_samples<E>(
    samples: usize,
    mut sample: impl FnMut() -> Result<f64, E>,
) -> Result<Vec<f64>, E> {
    let mut values = Vec::with_capacity(samples);
    for _ in 0..samples {
        values.push(sample()?);
    }
    Ok(values)
}

fn sample_hybrid_verify(
    envelope: &SignedEnvelope<BenchPayload>,
    signing_bytes: &[u8],
    classical_verifying_key: &fcp_crypto::Ed25519VerifyingKey,
    pq_verifying_key: &fcp_crypto::MlDsa65VerifyingKey,
) -> Result<f64, fcp_crypto::CryptoError> {
    let start = Instant::now();
    black_box(envelope.verify(
        black_box(signing_bytes),
        black_box(classical_verifying_key),
        black_box(pq_verifying_key),
    )?);
    Ok(elapsed_ms(start))
}

fn sample_classical_verify(
    envelope: &SignedEnvelope<BenchPayload>,
    signing_bytes: &[u8],
    classical_verifying_key: &fcp_crypto::Ed25519VerifyingKey,
) -> Result<f64, fcp_crypto::CryptoError> {
    let start = Instant::now();
    black_box(envelope.verify_with_policy(
        black_box(signing_bytes),
        black_box(PqSigningPolicy::ClassicalOnly),
        Some(black_box(classical_verifying_key)),
        None,
    )?);
    Ok(elapsed_ms(start))
}

fn elapsed_ms(start: Instant) -> f64 {
    start.elapsed().as_secs_f64() * 1_000.0
}

fn bootstrap_p99_ci(samples: &[f64], resamples: usize) -> [f64; 2] {
    let sorted = finite_sorted(samples);
    if sorted.is_empty() {
        return [f64::NAN, f64::NAN];
    }
    if resamples == 0 {
        let p99 = percentile(&sorted, 0.990);
        return [p99, p99];
    }

    let mut seed = bootstrap_seed(&sorted);
    let mut p99_values = Vec::with_capacity(resamples);
    for _ in 0..resamples {
        let mut resample = Vec::with_capacity(sorted.len());
        for _ in 0..sorted.len() {
            let index = next_index(&mut seed, sorted.len());
            resample.push(sorted[index]);
        }
        resample.sort_by(f64::total_cmp);
        p99_values.push(percentile(&resample, 0.990));
    }
    p99_values.sort_by(f64::total_cmp);
    [
        nearest_rank(&p99_values, 25),
        nearest_rank(&p99_values, 975),
    ]
}

fn finite_sorted(samples: &[f64]) -> Vec<f64> {
    let mut sorted = samples
        .iter()
        .copied()
        .filter(|sample| sample.is_finite())
        .collect::<Vec<_>>();
    sorted.sort_by(f64::total_cmp);
    sorted
}

fn percentile(sorted: &[f64], quantile: f64) -> f64 {
    if sorted.len() == 1 {
        return sorted[0];
    }

    let rank = quantile.clamp(0.0, 1.0) * (sorted.len() - 1) as f64;
    let lower = rank.floor() as usize;
    let upper = rank.ceil() as usize;

    if lower == upper {
        sorted[lower]
    } else {
        let weight = rank - lower as f64;
        sorted[lower].mul_add(1.0 - weight, sorted[upper] * weight)
    }
}

const fn nearest_rank(sorted: &[f64], per_mille: usize) -> f64 {
    let len = sorted.len();
    let mut index = (len * per_mille).div_ceil(1_000).saturating_sub(1);
    if index >= len {
        index = len - 1;
    }
    sorted[index]
}

fn bootstrap_seed(sorted: &[f64]) -> u64 {
    let mut seed = 0x5051_5349_474e_0001_u64 ^ sorted.len() as u64;
    for sample in sorted.iter().take(64) {
        seed ^= sample.to_bits();
        seed = splitmix64(&mut seed);
    }
    seed
}

const fn next_index(seed: &mut u64, len: usize) -> usize {
    let value = splitmix64(seed);
    value as usize % len
}

const fn splitmix64(seed: &mut u64) -> u64 {
    *seed = seed.wrapping_add(0x9e37_79b9_7f4a_7c15);
    let mut value = *seed;
    value = (value ^ (value >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
    value = (value ^ (value >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
    value ^ (value >> 31)
}

fn infer_machine_class(path: &Path) -> &str {
    path.file_stem()
        .and_then(std::ffi::OsStr::to_str)
        .and_then(|stem| stem.split('-').next())
        .filter(|part| !part.is_empty())
        .unwrap_or("unknown")
}

fn infer_git_sha(path: &Path) -> &str {
    path.file_stem()
        .and_then(std::ffi::OsStr::to_str)
        .and_then(|stem| stem.rsplit('-').next().filter(|part| *part != stem))
        .filter(|part| !part.is_empty())
        .unwrap_or("unknown")
}

fn artifact_path(path: &Path) -> String {
    path.to_string_lossy().replace('\\', "/")
}

fn next_value(
    iter: &mut impl Iterator<Item = String>,
    flag: &'static str,
) -> Result<String, String> {
    iter.next()
        .ok_or_else(|| format!("{flag} requires a value\n{}", usage()))
}

fn print_usage() {
    println!("{}", usage());
}

const fn usage() -> &'static str {
    "usage: cargo bench -p fcp-crypto --bench hybrid_verify -- \
     --samples 10000 \
     --statpack-out artifacts/perf/pq_signing/<machine-class>-<date>-<sha>.json \
     [--machine-class <class>] [--git-sha <sha>]"
}
