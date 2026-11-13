// ネイティブでの速さ: cargo run --release --example bench
use bls12381::bls::*;
use bls12381::curve::*;
use bls12381::fp::Fp;
use bls12381::fp12::final_exp;
use bls12381::hash::hash_to_g2;
use bls12381::pairing::miller_loop;
use std::time::Instant;

fn t<F: FnMut()>(label: &str, n: u32, mut f: F) {
    for _ in 0..3 {
        f();
    }
    let s = Instant::now();
    for _ in 0..n {
        f();
    }
    let us = s.elapsed().as_secs_f64() * 1e6 / n as f64;
    println!("{label:<26} {us:>10.1} µs");
}

fn main() {
    let a = Fp::from_u64(123456789);
    let b = Fp::from_u64(987654321);
    t("Fp mul", 1_000_000, || {
        std::hint::black_box(a.mul(&b));
    });
    let sk = keygen(&[7u8; 48]).unwrap();
    let pk = sk_to_pk(&sk).unwrap();
    let sig = sign(&sk, b"hello", DST_NUL).unwrap();
    let g1 = g1_gen().to_affine().unwrap();
    let g2 = g2_gen().to_affine().unwrap();
    t("miller_loop 1ペア", 200, || {
        std::hint::black_box(miller_loop(&[(g1, g2)]));
    });
    let f = miller_loop(&[(g1, g2)]);
    t("final_exp", 200, || {
        std::hint::black_box(final_exp(&f));
    });
    t("hash_to_g2", 200, || {
        std::hint::black_box(hash_to_g2(b"hello", DST_NUL));
    });
    t("keygen (sk→pk)", 1000, || {
        std::hint::black_box(sk_to_pk(&sk));
    });
    t("sign", 200, || {
        std::hint::black_box(sign(&sk, b"hello", DST_NUL));
    });
    t("verify", 200, || {
        assert!(verify(&pk, b"hello", &sig, DST_NUL));
    });
}
