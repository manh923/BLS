// Fp2 = Fp[u]/(u²+1)
use crate::consts::INV2;
use crate::fp::Fp;

#[derive(Clone, Copy, PartialEq, Eq, Debug, Default)]
pub struct Fp2 {
    pub c0: Fp,
    pub c1: Fp,
}

impl Fp2 {
    pub const ZERO: Fp2 = Fp2 { c0: Fp::ZERO, c1: Fp::ZERO };
    pub const ONE: Fp2 = Fp2 { c0: Fp::ONE, c1: Fp::ZERO };

    pub const fn new(c0: Fp, c1: Fp) -> Fp2 {
        Fp2 { c0, c1 }
    }
    #[inline(always)]
    pub fn add(&self, b: &Fp2) -> Fp2 {
        Fp2::new(self.c0.add(&b.c0), self.c1.add(&b.c1))
    }
    #[inline(always)]
    pub fn sub(&self, b: &Fp2) -> Fp2 {
        Fp2::new(self.c0.sub(&b.c0), self.c1.sub(&b.c1))
    }
    #[inline(always)]
    pub fn double(&self) -> Fp2 {
        Fp2::new(self.c0.double(), self.c1.double())
    }
    #[inline(always)]
    pub fn neg(&self) -> Fp2 {
        Fp2::new(self.c0.neg(), self.c1.neg())
    }
    #[inline(always)]
    pub fn conj(&self) -> Fp2 {
        Fp2::new(self.c0, self.c1.neg())
    }
    // Karatsuba: Fp の掛け算 3 回
    #[inline(always)]
    pub fn mul(&self, b: &Fp2) -> Fp2 {
        let t0 = self.c0.mul(&b.c0);
        let t1 = self.c1.mul(&b.c1);
        // 足し算は還元しない (2p 未満なら掛け算はそのまま正しい)
        let t2 = self.c0.add_nr(&self.c1).mul(&b.c0.add_nr(&b.c1));
        Fp2::new(t0.sub(&t1), t2.sub(&t0).sub(&t1))
    }
    // (a0+a1)(a0-a1), 2a0a1
    #[inline(always)]
    pub fn sqr(&self) -> Fp2 {
        // a0 - a1 は a0 + (p - a1) として還元せずに掛け算へ
        let a = self.c0.add_nr(&self.c1).mul(&self.c0.add_nr(&self.c1.p_minus()));
        let b = self.c0.mul(&self.c1).double();
        Fp2::new(a, b)
    }
    #[inline(always)]
    pub fn mul_fp(&self, k: &Fp) -> Fp2 {
        Fp2::new(self.c0.mul(k), self.c1.mul(k))
    }
    // ξ = u + 1 を掛ける
    #[inline(always)]
    pub fn mul_xi(&self) -> Fp2 {
        Fp2::new(self.c0.sub(&self.c1), self.c0.add(&self.c1))
    }
    #[inline(always)]
    pub fn is_zero(&self) -> bool {
        self.c0.is_zero() && self.c1.is_zero()
    }
    pub fn inv(&self) -> Fp2 {
        let t = self.c0.sqr().add(&self.c1.sqr()).inv();
        Fp2::new(self.c0.mul(&t), self.c1.mul(&t).neg())
    }
    pub fn pow(&self, e: &[u32]) -> Fp2 {
        let mut r = Fp2::ONE;
        for limb in e.iter().rev() {
            for k in (0..32).rev() {
                r = r.sqr();
                if (limb >> k) & 1 == 1 {
                    r = r.mul(self);
                }
            }
        }
        r
    }
    // √(a0 + a1u): ノルムの平方根 s を取って t = (a0 ± s)/2, x0 = √t, x1 = a1/(2x0)
    //   剰余かどうかは先にルジャンドル記号で判定。t^((p-3)/4) = 1/x0 で逆元もいらない
    pub fn sqrt(&self) -> Option<Fp2> {
        if self.c1.is_zero() {
            if let Some(s) = self.c0.sqrt() {
                return Some(Fp2::new(s, Fp::ZERO));
            }
            return self.c0.neg().sqrt().map(|t| Fp2::new(Fp::ZERO, t));
        }
        let n = self.c0.sqr().add(&self.c1.sqr());
        if n.legendre() != 1 {
            return None;
        }
        let s = n.sqrt()?;
        let mut t = self.c0.add(&s).mul(&INV2);
        if t.legendre() != 1 {
            t = self.c0.sub(&s).mul(&INV2);
        }
        let y = t.inv_sqrt_pow();
        let x0 = t.mul(&y);
        if x0.sqr() != t {
            return None;
        }
        Some(Fp2::new(x0, self.c1.mul(&y).mul(&INV2)))
    }
    // RFC 9380 sgn0 (m = 2)
    pub fn sgn0(&self) -> bool {
        let s0 = self.c0.is_odd();
        let z0 = self.c0.is_zero();
        let s1 = self.c1.is_odd();
        s0 || (z0 && s1)
    }
    // 辞書順で大きいか (圧縮形式の符号ビット): c1 で決まる。c1 = 0 なら c0
    pub fn lex_larger(&self) -> bool {
        if !self.c1.is_zero() {
            self.c1.lex_larger()
        } else {
            self.c0.lex_larger()
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn basic() {
        let a = Fp2::new(Fp::from_u64(12345), Fp::from_u64(67890));
        let b = Fp2::new(Fp::from_u64(1111), Fp::from_u64(2222));
        assert_eq!(a.mul(&b).mul(&b.inv()), a);
        assert_eq!(a.sqr(), a.mul(&a));
        let s = a.sqr().sqrt().unwrap();
        assert!(s == a || s == a.neg());
        // u² = -1
        let u = Fp2::new(Fp::ZERO, Fp::ONE);
        assert_eq!(u.sqr(), Fp2::ONE.neg());
    }
}
