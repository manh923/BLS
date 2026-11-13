// ネイティブで 自前 vs blst: cargo run --release --bin native
use blst::min_pk::SecretKey;
use blst::BLST_ERROR;
use bls12381::bls as mine;
use std::time::Instant;

fn t<F: FnMut()>(label: &str, n: u32, mut f: F) -> f64 {
    for _ in 0..3 {
        f();
    }
    let s = Instant::now();
    for _ in 0..n {
        f();
    }
    let us = s.elapsed().as_secs_f64() * 1e6 / n as f64;
    println!("  {label:<16} {us:>9.1} µs");
    us
}

fn main() {
    let dst = bls_bench::DST;
    let msg = b"hello BLS";
    let sk_b = mine::keygen(&[42u8; 48]).unwrap();
    let pk_b = mine::sk_to_pk(&sk_b).unwrap();
    let sig_b = mine::sign(&sk_b, msg, dst).unwrap();
    let sk = SecretKey::from_bytes(&sk_b).unwrap();
    let pk = sk.sk_to_pk();
    let sig = sk.sign(msg, dst, &[]);
    // 同じ秘密鍵なら公開鍵も署名もバイト単位で一致するはず
    assert_eq!(pk.compress(), pk_b, "公開鍵が blst と一致しない");
    assert_eq!(sig.compress(), sig_b, "署名が blst と一致しない");
    println!("公開鍵・署名とも blst とバイト単位で一致\n");
    println!("自前 (Rust, 64bit × 6):");
    let a1 = t("鍵生成 sk→pk", 2000, || drop(mine::sk_to_pk(&sk_b)));
    let a2 = t("署名", 500, || drop(mine::sign(&sk_b, msg, dst)));
    let a3 = t("検証", 300, || assert!(mine::verify(&pk_b, msg, &sig_b, dst)));
    println!("blst:");
    let b1 = t("鍵生成 sk→pk", 2000, || drop(sk.sk_to_pk()));
    let b2 = t("署名", 500, || drop(sk.sign(msg, dst, &[])));
    let b3 = t("検証", 300, || assert_eq!(sig.verify(true, msg, dst, &[], &pk, true), BLST_ERROR::BLST_SUCCESS));
    println!("\n自前 / blst: 鍵生成 {:.1} 倍、署名 {:.1} 倍、検証 {:.1} 倍 遅い", a1 / b1, a2 / b2, a3 / b3);
}
