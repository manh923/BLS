// SHA-256 と RFC 9380 の hash-to-curve (BLS12381G2_XMD:SHA-256_SSWU_RO_)
use crate::consts::{ISO_XDEN, ISO_XNUM, ISO_YDEN, ISO_YNUM, SSWU_A, SSWU_B, SSWU_B_ZA, SSWU_MB_A, SSWU_Z};
use crate::curve::{clear_cofactor_g2, Jac, G2};
use crate::fp::Fp;
use crate::fp2::Fp2;

const K256: [u32; 64] = [
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5, 0xd807aa98,
    0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174, 0xe49b69c1, 0xefbe4786,
    0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da, 0x983e5152, 0xa831c66d, 0xb00327c8,
    0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967, 0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
    0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85, 0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819,
    0xd6990624, 0xf40e3585, 0x106aa070, 0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a,
    0x5b9cca4f, 0x682e6ff3, 0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7,
    0xc67178f2,
];

pub fn sha256(msg: &[u8]) -> [u8; 32] {
    let mut h: [u32; 8] =
        [0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19];
    let mut data = msg.to_vec();
    let bitlen = (msg.len() as u64) * 8;
    data.push(0x80);
    while data.len() % 64 != 56 {
        data.push(0);
    }
    data.extend_from_slice(&bitlen.to_be_bytes());
    let mut w = [0u32; 64];
    for chunk in data.chunks(64) {
        for i in 0..16 {
            w[i] = u32::from_be_bytes([chunk[4 * i], chunk[4 * i + 1], chunk[4 * i + 2], chunk[4 * i + 3]]);
        }
        for i in 16..64 {
            let s0 = w[i - 15].rotate_right(7) ^ w[i - 15].rotate_right(18) ^ (w[i - 15] >> 3);
            let s1 = w[i - 2].rotate_right(17) ^ w[i - 2].rotate_right(19) ^ (w[i - 2] >> 10);
            w[i] = w[i - 16].wrapping_add(s0).wrapping_add(w[i - 7]).wrapping_add(s1);
        }
        let [mut a, mut b, mut c, mut d, mut e, mut f, mut g, mut hh] = h;
        for i in 0..64 {
            let s1 = e.rotate_right(6) ^ e.rotate_right(11) ^ e.rotate_right(25);
            let ch = (e & f) ^ (!e & g);
            let t1 = hh.wrapping_add(s1).wrapping_add(ch).wrapping_add(K256[i]).wrapping_add(w[i]);
            let s0 = a.rotate_right(2) ^ a.rotate_right(13) ^ a.rotate_right(22);
            let maj = (a & b) ^ (a & c) ^ (b & c);
            let t2 = s0.wrapping_add(maj);
            hh = g;
            g = f;
            f = e;
            e = d.wrapping_add(t1);
            d = c;
            c = b;
            b = a;
            a = t1.wrapping_add(t2);
        }
        for (x, y) in h.iter_mut().zip([a, b, c, d, e, f, g, hh]) {
            *x = x.wrapping_add(y);
        }
    }
    let mut out = [0u8; 32];
    for i in 0..8 {
        out[4 * i..4 * i + 4].copy_from_slice(&h[i].to_be_bytes());
    }
    out
}

// 5.3.1 expand_message_xmd
pub fn expand_message_xmd(msg: &[u8], dst: &[u8], len: usize) -> Vec<u8> {
    let ell = len.div_ceil(32);
    assert!(ell <= 255 && dst.len() <= 255);
    let mut dst_prime = dst.to_vec();
    dst_prime.push(dst.len() as u8);
    let mut m0 = vec![0u8; 64];
    m0.extend_from_slice(msg);
    m0.extend_from_slice(&(len as u16).to_be_bytes());
    m0.push(0);
    m0.extend_from_slice(&dst_prime);
    let b0 = sha256(&m0);
    let mut m1 = b0.to_vec();
    m1.push(1);
    m1.extend_from_slice(&dst_prime);
    let mut bi = sha256(&m1);
    let mut out = bi.to_vec();
    for i in 2..=ell {
        let mut m = Vec::with_capacity(33 + dst_prime.len());
        for j in 0..32 {
            m.push(b0[j] ^ bi[j]);
        }
        m.push(i as u8);
        m.extend_from_slice(&dst_prime);
        bi = sha256(&m);
        out.extend_from_slice(&bi);
    }
    out.truncate(len);
    out
}

fn hash_to_field_fp2(msg: &[u8], dst: &[u8]) -> [Fp2; 2] {
    let b = expand_message_xmd(msg, dst, 256);
    let e = |k: usize| Fp::from_bytes_wide(b[k * 64..(k + 1) * 64].try_into().unwrap());
    [Fp2::new(e(0), e(1)), Fp2::new(e(2), e(3))]
}

// 6.6.2 Simplified SWU on E2'
fn map_to_curve_sswu(u: &Fp2) -> (Fp2, Fp2) {
    let zu2 = SSWU_Z.mul(&u.sqr());
    let den = zu2.sqr().add(&zu2);
    let x1 = if den.is_zero() { SSWU_B_ZA } else { SSWU_MB_A.mul(&Fp2::ONE.add(&den.inv())) };
    let g = |x: &Fp2| x.sqr().add(&SSWU_A).mul(x).add(&SSWU_B);
    let (x, mut y) = match g(&x1).sqrt() {
        Some(y) => (x1, y),
        None => {
            let x2 = zu2.mul(&x1);
            (x2, g(&x2).sqrt().expect("gx2 は必ず剰余"))
        }
    };
    if u.sgn0() != y.sgn0() {
        y = y.neg();
    }
    (x, y)
}

// 3-isogeny。分数のままヤコビアンに入れて逆元を消す
fn iso_map(x: &Fp2, y: &Fp2) -> G2 {
    let ev = |k: &[Fp2]| k.iter().rev().fold(Fp2::ZERO, |acc, c| acc.mul(x).add(c));
    let (xn, xd, yn, yd) = (ev(&ISO_XNUM), ev(&ISO_XDEN), ev(&ISO_YNUM), ev(&ISO_YDEN));
    if xd.is_zero() || yd.is_zero() {
        return Jac::inf();
    }
    let yd2 = yd.sqr();
    Jac { x: xn.mul(&xd).mul(&yd2), y: y.mul(&yn).mul(&xd.sqr().mul(&xd)).mul(&yd2), z: xd.mul(&yd) }
}

pub fn hash_to_g2(msg: &[u8], dst: &[u8]) -> G2 {
    let [u0, u1] = hash_to_field_fp2(msg, dst);
    let (x0, y0) = map_to_curve_sswu(&u0);
    let (x1, y1) = map_to_curve_sswu(&u1);
    clear_cofactor_g2(&iso_map(&x0, &y0).add(&iso_map(&x1, &y1)))
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn sha() {
        let h = sha256(b"abc");
        assert_eq!(h[0..4], [0xba, 0x78, 0x16, 0xbf]);
    }
    #[test]
    fn rfc9380_vector() {
        // RFC 9380 J.10.1 msg = "" の P.x.c0
        let p = hash_to_g2(b"", b"QUUX-V01-CS02-with-BLS12381G2_XMD:SHA-256_SSWU_RO_").to_affine().unwrap();
        assert_eq!(
            p.0.c0,
            crate::fp::fp("0141ebfbdca40eb85b87142e130ab689c673cf60f1a3e98d69335266f30d9b8d4ac44c1038e9dcdd5393faf5c41fb78a")
        );
    }
}
