// blst を WASM から呼ぶための関数 (速さ比べ用)
use blst::min_pk::{PublicKey, SecretKey, Signature};
use blst::BLST_ERROR;
use core::slice;

pub const DST: &[u8] = b"BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_NUL_";

#[no_mangle]
pub extern "C" fn blst_alloc(len: usize) -> *mut u8 {
    let mut v = Vec::<u8>::with_capacity(len.max(1));
    let p = v.as_mut_ptr();
    core::mem::forget(v);
    p
}
/// # Safety
/// sk: 32, msg: msg_len, out: 96
#[no_mangle]
pub unsafe extern "C" fn blst_bench_sign(sk: *const u8, msg: *const u8, msg_len: usize, out: *mut u8) -> i32 {
    let Ok(sk) = SecretKey::from_bytes(slice::from_raw_parts(sk, 32)) else { return 0 };
    let sig = sk.sign(slice::from_raw_parts(msg, msg_len), DST, &[]);
    slice::from_raw_parts_mut(out, 96).copy_from_slice(&sig.compress());
    1
}
/// # Safety
/// pk: 48, sig: 96
#[no_mangle]
pub unsafe extern "C" fn blst_bench_verify(pk: *const u8, msg: *const u8, msg_len: usize, sig: *const u8) -> i32 {
    let (Ok(pk), Ok(sig)) = (PublicKey::from_bytes(slice::from_raw_parts(pk, 48)), Signature::from_bytes(slice::from_raw_parts(sig, 96))) else {
        return 0;
    };
    (sig.verify(true, slice::from_raw_parts(msg, msg_len), DST, &[], &pk, true) == BLST_ERROR::BLST_SUCCESS) as i32
}
