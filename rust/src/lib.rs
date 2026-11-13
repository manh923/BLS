// BLS 署名 (BLS12-381) ── 外部クレートなし、全部自前
#![allow(long_running_const_eval)]
pub mod consts;
pub mod fp;
pub mod fp2;
pub mod fp12;
pub mod curve;
pub mod pairing;
pub mod hash;
pub mod bls;

// ═══ WASM から呼ぶための関数 (wasm-bindgen なし、生のポインタでやりとり) ═══
//   JS 側で bls_alloc したメモリに入力を書いて、ポインタと長さを渡す
//   戻り値: 1 = 成功 / 有効、0 = 失敗 / 無効
use core::slice;

#[no_mangle]
pub extern "C" fn bls_alloc(len: usize) -> *mut u8 {
    let mut v = Vec::<u8>::with_capacity(len.max(1));
    let p = v.as_mut_ptr();
    core::mem::forget(v);
    p
}
/// # Safety
/// bls_alloc で確保したポインタと同じ長さを渡すこと
#[no_mangle]
pub unsafe extern "C" fn bls_free(p: *mut u8, len: usize) {
    drop(Vec::from_raw_parts(p, 0, len.max(1)));
}

unsafe fn sl<'a>(p: *const u8, n: usize) -> &'a [u8] {
    if n == 0 {
        &[]
    } else {
        slice::from_raw_parts(p, n)
    }
}
unsafe fn put(out: *mut u8, data: &[u8]) {
    slice::from_raw_parts_mut(out, data.len()).copy_from_slice(data);
}
// 連結されたメッセージ (長さは u32 の配列) を切り分ける
unsafe fn split_msgs<'a>(msgs: *const u8, lens: *const u32, n: usize) -> Vec<&'a [u8]> {
    let lens = slice::from_raw_parts(lens, n);
    let total: usize = lens.iter().map(|&l| l as usize).sum();
    let all = sl(msgs, total);
    let mut out = Vec::with_capacity(n);
    let mut o = 0;
    for &l in lens {
        out.push(&all[o..o + l as usize]);
        o += l as usize;
    }
    out
}
unsafe fn chunks<'a>(p: *const u8, n: usize, size: usize) -> Vec<&'a [u8]> {
    sl(p, n * size).chunks(size).collect()
}

/// # Safety
/// rand: 48 バイト、out: 32 バイト
#[no_mangle]
pub unsafe extern "C" fn bls_keygen(rand: *const u8, out: *mut u8) -> i32 {
    match bls::keygen(sl(rand, 48).try_into().unwrap()) {
        Some(sk) => {
            put(out, &sk);
            1
        }
        None => 0,
    }
}
/// # Safety
/// sk: 32 バイト、out: 48 バイト
#[no_mangle]
pub unsafe extern "C" fn bls_sk_to_pk(sk: *const u8, out: *mut u8) -> i32 {
    match bls::sk_to_pk(sl(sk, 32)) {
        Some(pk) => {
            put(out, &pk);
            1
        }
        None => 0,
    }
}
/// # Safety
/// out: 96 バイト
#[no_mangle]
pub unsafe extern "C" fn bls_sign(sk: *const u8, msg: *const u8, msg_len: usize, dst: *const u8, dst_len: usize, out: *mut u8) -> i32 {
    match bls::sign(sl(sk, 32), sl(msg, msg_len), sl(dst, dst_len)) {
        Some(sig) => {
            put(out, &sig);
            1
        }
        None => 0,
    }
}
/// # Safety
/// pk: 48 バイト、sig: 96 バイト
#[no_mangle]
pub unsafe extern "C" fn bls_verify(pk: *const u8, msg: *const u8, msg_len: usize, sig: *const u8, dst: *const u8, dst_len: usize) -> i32 {
    bls::verify(sl(pk, 48), sl(msg, msg_len), sl(sig, 96), sl(dst, dst_len)) as i32
}
/// # Safety
/// sigs: n × 96 バイト、out: 96 バイト
#[no_mangle]
pub unsafe extern "C" fn bls_aggregate_sigs(sigs: *const u8, n: usize, out: *mut u8) -> i32 {
    match bls::aggregate_sigs(&chunks(sigs, n, 96)) {
        Some(s) => {
            put(out, &s);
            1
        }
        None => 0,
    }
}
/// # Safety
/// pks: n × 48 バイト、out: 48 バイト
#[no_mangle]
pub unsafe extern "C" fn bls_aggregate_pks(pks: *const u8, n: usize, out: *mut u8) -> i32 {
    match bls::aggregate_pks(&chunks(pks, n, 48)) {
        Some(p) => {
            put(out, &p);
            1
        }
        None => 0,
    }
}
/// # Safety
/// msgs: 連結、lens: n 個の u32、pks: n × 48、sig: 96
#[no_mangle]
pub unsafe extern "C" fn bls_aggregate_verify(msgs: *const u8, lens: *const u32, n: usize, pks: *const u8, sig: *const u8, dst: *const u8, dst_len: usize) -> i32 {
    bls::aggregate_verify(&split_msgs(msgs, lens, n), &chunks(pks, n, 48), sl(sig, 96), sl(dst, dst_len)) as i32
}
/// # Safety
/// msgs: 連結、lens: n 個の u32、pks: n × 48、sigs: n × 96、rs: n 個の u64 (リトルエンディアン)
#[no_mangle]
pub unsafe extern "C" fn bls_verify_batch(msgs: *const u8, lens: *const u32, n: usize, pks: *const u8, sigs: *const u8, rs: *const u8, dst: *const u8, dst_len: usize) -> i32 {
    let rs: Vec<u64> = sl(rs, n * 8).chunks(8).map(|c| u64::from_le_bytes(c.try_into().unwrap())).collect();
    bls::verify_batch(&split_msgs(msgs, lens, n), &chunks(pks, n, 48), &chunks(sigs, n, 96), &rs, sl(dst, dst_len)) as i32
}

// 計測用: Fp の演算だけを n 回回す (kind: 0=mul, 1=sqr, 2=add, 3=Fp2 mul, 4=miller 1ペア, 5=final_exp, 6=hash_to_g2, 7=g1 部分群, 8=g2 部分群)
#[no_mangle]
pub extern "C" fn bls_bench(kind: u32, n: u32) -> u32 {
    use crate::fp::Fp;
    use crate::fp2::Fp2;
    let mut a = Fp::from_u64(0x1234_5678_9abc_def0);
    let b = Fp::from_u64(0x0fed_cba9_8765_4321);
    let mut a2 = Fp2::new(a, b);
    let b2 = Fp2::new(b, a);
    let g1 = curve::g1_gen();
    let g2 = curve::g2_gen();
    let pair = (g1.to_affine().unwrap(), g2.to_affine().unwrap());
    let mut acc = 0u32;
    for _ in 0..n {
        match kind {
            0 => a = a.mul(&b),
            1 => a = a.sqr(),
            2 => a = a.add(&b),
            3 => a2 = a2.mul(&b2),
            4 => acc ^= pairing::miller_loop(&[pair]).c0.c0.c0.0[0] as u32,
            5 => acc ^= fp12::final_exp(&pairing::miller_loop(&[pair])).c0.c0.c0.0[0] as u32,
            6 => acc ^= hash::hash_to_g2(b"bench", bls::DST_NUL).x.c0.0[0] as u32,
            7 => acc ^= curve::g1_in_subgroup(&g1) as u32,
            _ => acc ^= curve::g2_in_subgroup(&g2) as u32,
        }
    }
    acc ^ a.0[0] as u32 ^ a2.c0.0[0] as u32
}
