// Fp: BLS12-381 の素体。モンゴメリ表現 (x を x·R mod p で持つ、R = 2^384)
//   WASM:      32bit × 12 (WASM には 64×64→128bit の掛け算がないので 32×32→64bit で組む)
//   ネイティブ: 64bit × 6  (u128 の掛け算が速い)
//   値は常に [0, p) に正規化。例外は add_nr (掛け算の入力専用、2p 未満)
use crate::consts::{EXP_INV_SQRT, EXP_LEGENDRE, EXP_P_MINUS_2, EXP_SQRT, HALF_P, P_LIMBS};

#[cfg(target_arch = "wasm32")]
mod lw {
    pub type Limb = u32;
    pub type Wide = u64;
    pub const NL: usize = 12;
    pub const BITS: u32 = 32;
}
#[cfg(not(target_arch = "wasm32"))]
mod lw {
    pub type Limb = u64;
    pub type Wide = u128;
    pub const NL: usize = 6;
    pub const BITS: u32 = 64;
}
use lw::*;
type L = [Limb; NL];

#[derive(Clone, Copy, PartialEq, Eq, Debug, Default)]
pub struct Fp(pub L);

// ─── コンパイル時に使う補助 ────────────────────────────────────────
const fn hexval(c: u8) -> u32 {
    match c {
        b'0'..=b'9' => (c - b'0') as u32,
        b'a'..=b'f' => (c - b'a' + 10) as u32,
        b'A'..=b'F' => (c - b'A' + 10) as u32,
        _ => panic!("hex じゃない文字"),
    }
}
// 16進文字列 → 32bit × 12 (リトルエンディアン)。指数などはこの形のまま使う
pub const fn limbs(s: &str) -> [u32; 12] {
    let b = s.as_bytes();
    let n = b.len();
    let mut out = [0u32; 12];
    let mut i = 0;
    while i < n {
        out[i / 8] |= hexval(b[n - 1 - i]) << ((i % 8) * 4);
        i += 1;
    }
    out
}
// 32bit × 12 ⇄ 内部の桁
const fn from_u32s(a: &[u32; 12]) -> L {
    let mut out = [0 as Limb; NL];
    let mut i = 0;
    while i < 12 {
        out[i * 32 / BITS as usize] |= (a[i] as Limb) << ((i as u32 * 32) % BITS);
        i += 1;
    }
    out
}
const fn to_u32s(a: &L) -> [u32; 12] {
    let mut out = [0u32; 12];
    let mut i = 0;
    while i < 12 {
        out[i] = (a[i * 32 / BITS as usize] >> ((i as u32 * 32) % BITS)) as u32;
        i += 1;
    }
    out
}

const P: L = from_u32s(&P_LIMBS);
// -p⁻¹ mod 2^BITS (ニュートン法で正しいビット数が倍々になる)
const INV: Limb = {
    let mut inv: Limb = 1;
    let mut i = 0;
    while i < 6 {
        inv = inv.wrapping_mul((2 as Limb).wrapping_sub(P[0].wrapping_mul(inv)));
        i += 1;
    }
    inv.wrapping_neg()
};

#[inline(always)]
const fn geq(a: &L, b: &L) -> bool {
    let mut i = NL;
    while i > 0 {
        i -= 1;
        if a[i] != b[i] {
            return a[i] > b[i];
        }
    }
    true
}
#[inline(always)]
const fn sub_raw(a: &L, b: &L) -> (L, bool) {
    let mut out = [0 as Limb; NL];
    let mut borrow = false;
    let mut i = 0;
    while i < NL {
        let (d1, b1) = a[i].overflowing_sub(b[i]);
        let (d2, b2) = d1.overflowing_sub(borrow as Limb);
        out[i] = d2;
        borrow = b1 | b2;
        i += 1;
    }
    (out, borrow)
}
#[inline(always)]
const fn add_raw(a: &L, b: &L) -> (L, bool) {
    let mut out = [0 as Limb; NL];
    let mut carry = false;
    let mut i = 0;
    while i < NL {
        let (s1, c1) = a[i].overflowing_add(b[i]);
        let (s2, c2) = s1.overflowing_add(carry as Limb);
        out[i] = s2;
        carry = c1 | c2;
        i += 1;
    }
    (out, carry)
}
#[inline(always)]
const fn add_mod(a: &L, b: &L) -> L {
    let (s, c) = add_raw(a, b);
    if c || geq(&s, &P) {
        sub_raw(&s, &P).0
    } else {
        s
    }
}
#[inline(always)]
const fn sub_mod(a: &L, b: &L) -> L {
    let (d, borrow) = sub_raw(a, b);
    if borrow {
        add_raw(&d, &P).0
    } else {
        d
    }
}
#[inline(always)]
const fn final_sub(t: &L, top: bool) -> L {
    if top || geq(t, &P) {
        sub_raw(t, &P).0
    } else {
        *t
    }
}

// モンゴメリ乗算 (CIOS): a·b·R⁻¹ mod p。a, b < 2p なら結果は [0, p)
#[inline(always)]
const fn mont_mul(a: &L, b: &L) -> L {
    let mut t = [0 as Limb; NL + 2];
    let mut i = 0;
    while i < NL {
        let bi = b[i] as Wide;
        let mut c: Wide = 0;
        let mut j = 0;
        while j < NL {
            let s = t[j] as Wide + (a[j] as Wide) * bi + c;
            t[j] = s as Limb;
            c = s >> BITS;
            j += 1;
        }
        let s = t[NL] as Wide + c;
        t[NL] = s as Limb;
        t[NL + 1] = (s >> BITS) as Limb;
        let m = t[0].wrapping_mul(INV) as Wide;
        let s = t[0] as Wide + m * (P[0] as Wide);
        let mut c = s >> BITS;
        let mut j = 1;
        while j < NL {
            let s = t[j] as Wide + m * (P[j] as Wide) + c;
            t[j - 1] = s as Limb;
            c = s >> BITS;
            j += 1;
        }
        let s = t[NL] as Wide + c;
        t[NL - 1] = s as Limb;
        t[NL] = t[NL + 1] + (s >> BITS) as Limb;
        i += 1;
    }
    let mut out = [0 as Limb; NL];
    let mut k = 0;
    while k < NL {
        out[k] = t[k];
        k += 1;
    }
    final_sub(&out, t[NL] != 0)
}

// モンゴメリ二乗: 対称な項 a_i·a_j (i<j) を 1 回だけ計算して 2 倍 → REDC
//   掛け算の回数が n² + n² から n(n+1)/2 + n² に減る
#[inline(always)]
const fn mont_sqr(a: &L) -> L {
    let mut t = [0 as Limb; 2 * NL + 1];
    let mut i = 0;
    while i < NL {
        let mut c: Wide = 0;
        let mut j = i + 1;
        while j < NL {
            let s = t[i + j] as Wide + (a[i] as Wide) * (a[j] as Wide) + c;
            t[i + j] = s as Limb;
            c = s >> BITS;
            j += 1;
        }
        t[i + NL] = c as Limb;
        i += 1;
    }
    // 2 倍
    let mut carry: Limb = 0;
    let mut k = 0;
    while k < 2 * NL {
        let v = t[k];
        t[k] = (v << 1) | carry;
        carry = v >> (BITS - 1);
        k += 1;
    }
    // 対角 a_i² を足す
    let mut c: Wide = 0;
    i = 0;
    while i < NL {
        let sq = (a[i] as Wide) * (a[i] as Wide);
        let s = t[2 * i] as Wide + (sq as Limb) as Wide + c;
        t[2 * i] = s as Limb;
        c = s >> BITS;
        let s = t[2 * i + 1] as Wide + (sq >> BITS) + c;
        t[2 * i + 1] = s as Limb;
        c = s >> BITS;
        i += 1;
    }
    // REDC: 下から 1 桁ずつ m·p を足して消す
    i = 0;
    while i < NL {
        let m = t[i].wrapping_mul(INV) as Wide;
        let mut c: Wide = 0;
        let mut j = 0;
        while j < NL {
            let s = t[i + j] as Wide + m * (P[j] as Wide) + c;
            t[i + j] = s as Limb;
            c = s >> BITS;
            j += 1;
        }
        let mut k = i + NL;
        while c != 0 {
            let s = t[k] as Wide + c;
            t[k] = s as Limb;
            c = s >> BITS;
            k += 1;
        }
        i += 1;
    }
    let mut out = [0 as Limb; NL];
    let mut k = 0;
    while k < NL {
        out[k] = t[NL + k];
        k += 1;
    }
    final_sub(&out, t[2 * NL] != 0)
}

// R mod p, R² mod p (2 倍を 384 回繰り返して作る)
const R1: L = {
    let mut x = [0 as Limb; NL];
    x[0] = 1;
    let mut i = 0;
    while i < 384 {
        x = add_mod(&x, &x);
        i += 1;
    }
    x
};
const R2: L = {
    let mut x = R1;
    let mut i = 0;
    while i < 384 {
        x = add_mod(&x, &x);
        i += 1;
    }
    x
};
const HALF_P_INT: L = from_u32s(&HALF_P);

// 16進の定数 → モンゴメリ表現の Fp (コンパイル時に計算される)
pub const fn fp(hex: &str) -> Fp {
    Fp(mont_mul(&from_u32s(&limbs(hex)), &R2))
}

impl Fp {
    pub const ZERO: Fp = Fp([0; NL]);
    pub const ONE: Fp = Fp(R1);

    #[inline(always)]
    pub fn add(&self, b: &Fp) -> Fp {
        Fp(add_mod(&self.0, &b.0))
    }
    // 還元しない足し算 (結果は 2p 未満)。掛け算の入力にだけ使う
    #[inline(always)]
    pub fn add_nr(&self, b: &Fp) -> Fp {
        Fp(add_raw(&self.0, &b.0).0)
    }
    // p - a (還元しない。a = 0 なら p)。add_nr と組み合わせて a0 - a1 + p を作る用
    #[inline(always)]
    pub fn p_minus(&self) -> Fp {
        Fp(sub_raw(&P, &self.0).0)
    }
    #[inline(always)]
    pub fn sub(&self, b: &Fp) -> Fp {
        Fp(sub_mod(&self.0, &b.0))
    }
    #[inline(always)]
    pub fn double(&self) -> Fp {
        Fp(add_mod(&self.0, &self.0))
    }
    #[inline(always)]
    pub fn neg(&self) -> Fp {
        if self.is_zero() {
            *self
        } else {
            Fp(sub_raw(&P, &self.0).0)
        }
    }
    #[inline(always)]
    pub fn mul(&self, b: &Fp) -> Fp {
        Fp(mont_mul(&self.0, &b.0))
    }
    #[inline(always)]
    pub fn sqr(&self) -> Fp {
        Fp(mont_sqr(&self.0))
    }
    #[inline(always)]
    pub fn is_zero(&self) -> bool {
        self.0.iter().all(|&x| x == 0)
    }
    pub fn from_u64(v: u64) -> Fp {
        let mut l = [0u32; 12];
        l[0] = v as u32;
        l[1] = (v >> 32) as u32;
        Fp(mont_mul(&from_u32s(&l), &R2))
    }
    // モンゴメリ表現 → 普通の値 (内部の桁)
    fn to_normal(&self) -> L {
        let mut one = [0 as Limb; NL];
        one[0] = 1;
        mont_mul(&self.0, &one)
    }
    pub fn to_limbs(&self) -> [u32; 12] {
        to_u32s(&self.to_normal())
    }
    // 冪乗 (指数はリトルエンディアンの 32bit 列。左から 4bit ずつ)
    pub fn pow(&self, e: &[u32]) -> Fp {
        let mut tbl = [Fp::ONE; 16];
        for i in 1..16 {
            tbl[i] = tbl[i - 1].mul(self);
        }
        let mut r = Fp::ONE;
        let mut started = false;
        for limb in e.iter().rev() {
            for k in (0..8).rev() {
                let d = ((limb >> (k * 4)) & 0xf) as usize;
                if started {
                    r = r.sqr().sqr().sqr().sqr();
                }
                if d != 0 {
                    r = if started { r.mul(&tbl[d]) } else { tbl[d] };
                    started = true;
                }
            }
        }
        r
    }
    pub fn inv(&self) -> Fp {
        self.pow(&EXP_P_MINUS_2)
    }
    // p ≡ 3 (mod 4) なので √a = a^((p+1)/4)
    pub fn sqrt(&self) -> Option<Fp> {
        let r = self.pow(&EXP_SQRT);
        if r.sqr() == *self {
            Some(r)
        } else {
            None
        }
    }
    // a^((p-3)/4) = 1/√a (a が剰余のとき)
    pub fn inv_sqrt_pow(&self) -> Fp {
        self.pow(&EXP_INV_SQRT)
    }
    // 1: 平方剰余 / -1: 非剰余 / 0: ゼロ
    pub fn legendre(&self) -> i32 {
        let r = self.pow(&EXP_LEGENDRE);
        if r == Fp::ONE {
            1
        } else if r.is_zero() {
            0
        } else {
            -1
        }
    }
    // 普通の値として (p-1)/2 より大きいか (圧縮形式の符号ビット)
    pub fn lex_larger(&self) -> bool {
        let v = self.to_normal();
        v != HALF_P_INT && geq(&v, &HALF_P_INT)
    }
    pub fn is_odd(&self) -> bool {
        self.to_normal()[0] & 1 == 1
    }
    // 48 バイトのビッグエンディアン → Fp (p 以上なら None)
    pub fn from_bytes(b: &[u8]) -> Option<Fp> {
        if b.len() != 48 {
            return None;
        }
        let mut l = [0u32; 12];
        for (i, x) in l.iter_mut().enumerate() {
            let o = 48 - 4 * (i + 1);
            *x = u32::from_be_bytes([b[o], b[o + 1], b[o + 2], b[o + 3]]);
        }
        let l = from_u32s(&l);
        if geq(&l, &P) {
            return None;
        }
        Some(Fp(mont_mul(&l, &R2)))
    }
    pub fn to_bytes(&self) -> [u8; 48] {
        let l = self.to_limbs();
        let mut out = [0u8; 48];
        for (i, x) in l.iter().enumerate() {
            let o = 48 - 4 * (i + 1);
            out[o..o + 4].copy_from_slice(&x.to_be_bytes());
        }
        out
    }
    // 64 バイトのビッグエンディアン整数 mod p (hash_to_field 用)
    //   値 = hi·2^384 + lo。モンゴメリでは mont(lo) + mont(hi)·R
    pub fn from_bytes_wide(b: &[u8; 64]) -> Fp {
        let mut lo = [0u32; 12];
        let mut hi = [0u32; 12];
        for (i, x) in lo.iter_mut().enumerate() {
            let o = 64 - 4 * (i + 1);
            *x = u32::from_be_bytes([b[o], b[o + 1], b[o + 2], b[o + 3]]);
        }
        for (i, x) in hi.iter_mut().take(4).enumerate() {
            let o = 16 - 4 * (i + 1);
            *x = u32::from_be_bytes([b[o], b[o + 1], b[o + 2], b[o + 3]]);
        }
        let lo_m = Fp(mont_mul(&from_u32s(&lo), &R2));
        let hi_m = Fp(mont_mul(&from_u32s(&hi), &R2));
        lo_m.add(&hi_m.mul(&Fp(R2)))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn basic() {
        let a = Fp::from_u64(123456789);
        let b = Fp::from_u64(987654321);
        assert_eq!(a.mul(&b), Fp::from_u64(123456789u64 * 987654321u64));
        assert_eq!(a.mul(&a.inv()), Fp::ONE);
        assert_eq!(a.sub(&a), Fp::ZERO);
        assert_eq!(a.add(&a.neg()), Fp::ZERO);
        let s = a.sqr().sqrt().unwrap();
        assert!(s == a || s == a.neg());
        assert_eq!(a.sqr().legendre(), 1);
        assert_eq!(Fp::ONE.neg().legendre(), -1);
        let bytes = a.to_bytes();
        assert_eq!(Fp::from_bytes(&bytes).unwrap(), a);
    }
    #[test]
    fn sqr_matches_mul() {
        let mut x = Fp::from_u64(0xdeadbeef);
        for _ in 0..200 {
            assert_eq!(x.sqr(), x.mul(&x));
            // 2p 未満の入力でも正しいか
            let y = x.add_nr(&x.neg().p_minus());
            assert_eq!(y.mul(&Fp::ONE), x.add(&x));
            x = x.sqr().add(&Fp::from_u64(7));
        }
    }
}
