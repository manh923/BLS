// BLS 署名 (min-pk: 公開鍵 G1 48byte / 署名 G2 96byte)、ZCash 圧縮形式
use crate::consts::R_ORDER;
use crate::curve::{
    g1_in_subgroup, g1_mul_base, g2_in_subgroup, g2_mul_gls, msm_u64, to_affine_batch, Jac, G1, G2,
};
use crate::fp::Fp;
use crate::fp12::{final_exp, Fp12};
use crate::fp2::Fp2;
use crate::hash::hash_to_g2;
use crate::pairing::{miller_loop, Pair};

pub const DST_NUL: &[u8] = b"BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_NUL_";

// ─── シリアライズ ─────────────────────────────────────────────────────
pub fn g1_to_bytes(p: &G1) -> [u8; 48] {
    let mut out = [0u8; 48];
    match p.to_affine() {
        None => out[0] = 0xc0,
        Some((x, y)) => {
            out = x.to_bytes();
            out[0] |= 0x80;
            if y.lex_larger() {
                out[0] |= 0x20;
            }
        }
    }
    out
}
pub fn g1_from_bytes(b: &[u8]) -> Option<G1> {
    if b.len() != 48 || b[0] & 0x80 == 0 {
        return None;
    }
    let flags = b[0];
    let mut body = [0u8; 48];
    body.copy_from_slice(b);
    body[0] &= 0x1f;
    if flags & 0x40 != 0 {
        return if body.iter().all(|&x| x == 0) && flags & 0x20 == 0 { Some(Jac::inf()) } else { None };
    }
    let x = Fp::from_bytes(&body)?;
    let mut y = x.sqr().mul(&x).add(&crate::curve::b1()).sqrt()?;
    if y.lex_larger() != (flags & 0x20 != 0) {
        y = y.neg();
    }
    let p = Jac::from_affine(x, y);
    if !g1_in_subgroup(&p) {
        return None;
    }
    Some(p)
}
pub fn g2_to_bytes(p: &G2) -> [u8; 96] {
    let mut out = [0u8; 96];
    match p.to_affine() {
        None => out[0] = 0xc0,
        Some((x, y)) => {
            out[..48].copy_from_slice(&x.c1.to_bytes());
            out[48..].copy_from_slice(&x.c0.to_bytes());
            out[0] |= 0x80;
            if y.lex_larger() {
                out[0] |= 0x20;
            }
        }
    }
    out
}
pub fn g2_from_bytes(b: &[u8]) -> Option<G2> {
    if b.len() != 96 || b[0] & 0x80 == 0 {
        return None;
    }
    let flags = b[0];
    let mut body = [0u8; 96];
    body.copy_from_slice(b);
    body[0] &= 0x1f;
    if flags & 0x40 != 0 {
        return if body.iter().all(|&x| x == 0) && flags & 0x20 == 0 { Some(Jac::inf()) } else { None };
    }
    let x = Fp2::new(Fp::from_bytes(&body[48..])?, Fp::from_bytes(&body[..48])?);
    let mut y = x.sqr().mul(&x).add(&crate::curve::b2()).sqrt()?;
    if y.lex_larger() != (flags & 0x20 != 0) {
        y = y.neg();
    }
    let p = Jac::from_affine(x, y);
    if !g2_in_subgroup(&p) {
        return None;
    }
    Some(p)
}

// ─── 鍵 ───────────────────────────────────────────────────────────────
// 32 バイトのビッグエンディアン → 32bit × 8 (1 ≤ sk < r を確認)
fn sk_limbs(sk: &[u8]) -> Option<[u32; 8]> {
    if sk.len() != 32 {
        return None;
    }
    let mut l = [0u32; 8];
    for i in 0..8 {
        let o = 32 - 4 * (i + 1);
        l[i] = u32::from_be_bytes([sk[o], sk[o + 1], sk[o + 2], sk[o + 3]]);
    }
    let zero = l.iter().all(|&x| x == 0);
    // r と比べる (r は 255bit なので上位 8 limb だけ)
    let mut lt = false;
    for i in (0..8).rev() {
        if l[i] != R_ORDER[i] {
            lt = l[i] < R_ORDER[i];
            break;
        }
    }
    if zero || !lt {
        return None;
    }
    Some(l)
}
// 48 バイトの乱数 → mod r の秘密鍵 (0 なら None)
pub fn keygen(rand48: &[u8; 48]) -> Option<[u8; 32]> {
    // 384bit の値を r で割った余りを、上の桁から 1bit ずつ (遅いけど 1 回だけなので素朴に)
    let mut r = [0u32; 9];
    let rr = R_ORDER;
    for byte in rand48 {
        for b in (0..8).rev() {
            // r = 2r + bit
            let mut carry = (byte >> b) as u32 & 1;
            for limb in r.iter_mut() {
                let v = ((*limb as u64) << 1) | carry as u64;
                *limb = v as u32;
                carry = (v >> 32) as u32;
            }
            // r >= R なら引く
            let mut ge = r[8] != 0;
            if !ge {
                ge = true;
                for i in (0..8).rev() {
                    if r[i] != rr[i] {
                        ge = r[i] > rr[i];
                        break;
                    }
                }
            }
            if ge {
                let mut borrow = 0i64;
                for i in 0..9 {
                    let sub = if i < 8 { rr[i] as i64 } else { 0 };
                    let d = r[i] as i64 - sub - borrow;
                    r[i] = d as u32;
                    borrow = if d < 0 { 1 } else { 0 };
                }
            }
        }
    }
    if r.iter().all(|&x| x == 0) {
        return None;
    }
    let mut out = [0u8; 32];
    for i in 0..8 {
        let o = 32 - 4 * (i + 1);
        out[o..o + 4].copy_from_slice(&r[i].to_be_bytes());
    }
    Some(out)
}
pub fn sk_to_pk(sk: &[u8]) -> Option<[u8; 48]> {
    Some(g1_to_bytes(&g1_mul_base(&sk_limbs(sk)?)))
}

// ─── 署名・検証 ───────────────────────────────────────────────────────
pub fn sign(sk: &[u8], msg: &[u8], dst: &[u8]) -> Option<[u8; 96]> {
    let k = sk_limbs(sk)?;
    Some(g2_to_bytes(&g2_mul_gls(&hash_to_g2(msg, dst), &k)))
}

fn neg_g1_aff() -> (Fp, Fp) {
    let g = crate::curve::g1_gen();
    (g.x, g.y.neg())
}

fn is_one(f: &Fp12) -> bool {
    *f == Fp12::ONE
}

// e(-G1, σ)·e(pk, H(m)) == 1
pub fn verify(pk: &[u8], msg: &[u8], sig: &[u8], dst: &[u8]) -> bool {
    let (Some(p), Some(s)) = (g1_from_bytes(pk), g2_from_bytes(sig)) else { return false };
    if p.is_inf() {
        return false;
    }
    let h = hash_to_g2(msg, dst);
    let mut pairs: Vec<Pair> = vec![(p.to_affine().unwrap(), h.to_affine().unwrap())];
    if let Some(sa) = s.to_affine() {
        pairs.push((neg_g1_aff(), sa));
    }
    is_one(&final_exp(&miller_loop(&pairs)))
}

pub fn aggregate_sigs(sigs: &[&[u8]]) -> Option<[u8; 96]> {
    let mut acc: G2 = Jac::inf();
    for s in sigs {
        acc = acc.add(&g2_from_bytes(s)?);
    }
    Some(g2_to_bytes(&acc))
}
pub fn aggregate_pks(pks: &[&[u8]]) -> Option<[u8; 48]> {
    let mut acc: G1 = Jac::inf();
    for p in pks {
        acc = acc.add(&g1_from_bytes(p)?);
    }
    Some(g1_to_bytes(&acc))
}

// 違うメッセージをまとめて: e(G1, σ) == Π e(pk_i, H(m_i))
pub fn aggregate_verify(msgs: &[&[u8]], pks: &[&[u8]], sig: &[u8], dst: &[u8]) -> bool {
    if msgs.is_empty() || msgs.len() != pks.len() {
        return false;
    }
    if dst == DST_NUL {
        let mut sorted: Vec<&[u8]> = msgs.to_vec();
        sorted.sort();
        if sorted.windows(2).any(|w| w[0] == w[1]) {
            return false;
        }
    }
    let Some(s) = g2_from_bytes(sig) else { return false };
    let mut ps = Vec::new();
    let mut hs = Vec::new();
    for (m, pk) in msgs.iter().zip(pks) {
        let Some(p) = g1_from_bytes(pk) else { return false };
        if p.is_inf() {
            return false;
        }
        ps.push(p);
        hs.push(hash_to_g2(m, dst));
    }
    let pa = to_affine_batch(&ps);
    let qa = to_affine_batch(&hs);
    let mut pairs: Vec<Pair> = pa.into_iter().zip(qa).collect();
    if let Some(sa) = s.to_affine() {
        pairs.push((neg_g1_aff(), sa));
    }
    is_one(&final_exp(&miller_loop(&pairs)))
}

// バッチ検証: ランダムな 64bit の係数 rs (呼び出し側が用意する) で
//   e(-G1, Σ r_i·σ_i)·Π e(r_i·pk_i, H(m_i)) == 1
pub fn verify_batch(msgs: &[&[u8]], pks: &[&[u8]], sigs: &[&[u8]], rs: &[u64], dst: &[u8]) -> bool {
    let n = msgs.len();
    if n == 0 || pks.len() != n || sigs.len() != n || rs.len() != n || rs.iter().any(|&r| r == 0) {
        return false;
    }
    let mut ps = Vec::with_capacity(n);
    let mut hs = Vec::with_capacity(n);
    let mut ss = Vec::with_capacity(n);
    for i in 0..n {
        let (Some(p), Some(s)) = (g1_from_bytes(pks[i]), g2_from_bytes(sigs[i])) else { return false };
        if p.is_inf() {
            return false;
        }
        ps.push(p.mul_u64(rs[i]));
        ss.push(s);
        hs.push(hash_to_g2(msgs[i], dst));
    }
    let s = msm_u64(&ss, rs);
    let pa = to_affine_batch(&ps);
    let qa = to_affine_batch(&hs);
    let mut pairs: Vec<Pair> = pa.into_iter().zip(qa).collect();
    if let Some(sa) = s.to_affine() {
        pairs.push((neg_g1_aff(), sa));
    }
    is_one(&final_exp(&miller_loop(&pairs)))
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn sign_verify() {
        let sk = keygen(&[7u8; 48]).unwrap();
        let pk = sk_to_pk(&sk).unwrap();
        let sig = sign(&sk, b"hello", DST_NUL).unwrap();
        assert!(verify(&pk, b"hello", &sig, DST_NUL));
        assert!(!verify(&pk, b"hellp", &sig, DST_NUL));
        // G1 生成元の圧縮形式 (noble / ZCash と同じ)
        let g = g1_to_bytes(&crate::curve::g1_gen());
        assert_eq!(g[0], 0x97);
        assert_eq!(g[1], 0xf1);
        // バッチ
        let sk2 = keygen(&[9u8; 48]).unwrap();
        let pk2 = sk_to_pk(&sk2).unwrap();
        let sig2 = sign(&sk2, b"world", DST_NUL).unwrap();
        let msgs: [&[u8]; 2] = [b"hello", b"world"];
        let pks: [&[u8]; 2] = [&pk, &pk2];
        let sigs: [&[u8]; 2] = [&sig, &sig2];
        assert!(verify_batch(&msgs, &pks, &sigs, &[3, 5], DST_NUL));
        let bad: [&[u8]; 2] = [&sig2, &sig];
        assert!(!verify_batch(&msgs, &pks, &bad, &[3, 5], DST_NUL));
        let agg = aggregate_sigs(&sigs).unwrap();
        assert!(aggregate_verify(&msgs, &pks, &agg, DST_NUL));
    }
}
