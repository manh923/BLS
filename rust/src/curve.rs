// 楕円曲線 y² = x³ + b (a = 0) をフィールド汎用で。ヤコビアン座標 (X, Y, Z): x = X/Z², y = Y/Z³
use crate::consts::{BETA, G1_X, G1_Y, PSI_X, PSI_Y, R_ORDER, X_ABS};
use crate::fp::Fp;
use crate::fp2::Fp2;
use std::sync::OnceLock;

pub trait Field: Copy + PartialEq + core::fmt::Debug {
    const ZERO: Self;
    const ONE: Self;
    fn f_add(&self, b: &Self) -> Self;
    fn f_sub(&self, b: &Self) -> Self;
    fn f_dbl(&self) -> Self;
    fn f_neg(&self) -> Self;
    fn f_mul(&self, b: &Self) -> Self;
    fn f_sqr(&self) -> Self;
    fn f_inv(&self) -> Self;
    fn f_is_zero(&self) -> bool;
}
macro_rules! impl_field {
    ($t:ty) => {
        impl Field for $t {
            const ZERO: Self = <$t>::ZERO;
            const ONE: Self = <$t>::ONE;
            #[inline(always)]
            fn f_add(&self, b: &Self) -> Self { self.add(b) }
            #[inline(always)]
            fn f_sub(&self, b: &Self) -> Self { self.sub(b) }
            #[inline(always)]
            fn f_dbl(&self) -> Self { self.double() }
            #[inline(always)]
            fn f_neg(&self) -> Self { self.neg() }
            #[inline(always)]
            fn f_mul(&self, b: &Self) -> Self { self.mul(b) }
            #[inline(always)]
            fn f_sqr(&self) -> Self { self.sqr() }
            #[inline(always)]
            fn f_inv(&self) -> Self { self.inv() }
            #[inline(always)]
            fn f_is_zero(&self) -> bool { self.is_zero() }
        }
    };
}
impl_field!(Fp);
impl_field!(Fp2);

#[derive(Clone, Copy, Debug)]
pub struct Jac<F: Field> {
    pub x: F,
    pub y: F,
    pub z: F,
}
pub type G1 = Jac<Fp>;
pub type G2 = Jac<Fp2>;

impl<F: Field> Jac<F> {
    pub fn inf() -> Self {
        Jac { x: F::ONE, y: F::ONE, z: F::ZERO }
    }
    pub fn from_affine(x: F, y: F) -> Self {
        Jac { x, y, z: F::ONE }
    }
    #[inline(always)]
    pub fn is_inf(&self) -> bool {
        self.z.f_is_zero()
    }
    // dbl-2009-l
    pub fn dbl(&self) -> Self {
        if self.is_inf() {
            return *self;
        }
        let a = self.x.f_sqr();
        let b = self.y.f_sqr();
        let c = b.f_sqr();
        let d = self.x.f_add(&b).f_sqr().f_sub(&a).f_sub(&c).f_dbl();
        let e = a.f_dbl().f_add(&a);
        let x3 = e.f_sqr().f_sub(&d.f_dbl());
        let y3 = e.f_mul(&d.f_sub(&x3)).f_sub(&c.f_dbl().f_dbl().f_dbl());
        let z3 = self.y.f_mul(&self.z).f_dbl();
        Jac { x: x3, y: y3, z: z3 }
    }
    // madd-2007-bl (q はアフィン)
    pub fn madd(&self, x2: &F, y2: &F) -> Self {
        if self.is_inf() {
            return Jac::from_affine(*x2, *y2);
        }
        let z1z1 = self.z.f_sqr();
        let u2 = x2.f_mul(&z1z1);
        let s2 = y2.f_mul(&self.z).f_mul(&z1z1);
        let h = u2.f_sub(&self.x);
        let rr = s2.f_sub(&self.y);
        if h.f_is_zero() {
            return if rr.f_is_zero() { self.dbl() } else { Jac::inf() };
        }
        let hh = h.f_sqr();
        let i = hh.f_dbl().f_dbl();
        let j = h.f_mul(&i);
        let r2 = rr.f_dbl();
        let v = self.x.f_mul(&i);
        let x3 = r2.f_sqr().f_sub(&j).f_sub(&v.f_dbl());
        let y3 = r2.f_mul(&v.f_sub(&x3)).f_sub(&self.y.f_mul(&j).f_dbl());
        let z3 = self.z.f_add(&h).f_sqr().f_sub(&z1z1).f_sub(&hh);
        Jac { x: x3, y: y3, z: z3 }
    }
    // add-2007-bl
    pub fn add(&self, q: &Self) -> Self {
        if self.is_inf() {
            return *q;
        }
        if q.is_inf() {
            return *self;
        }
        if q.z == F::ONE {
            return self.madd(&q.x, &q.y);
        }
        if self.z == F::ONE {
            return q.madd(&self.x, &self.y);
        }
        let z1z1 = self.z.f_sqr();
        let z2z2 = q.z.f_sqr();
        let u1 = self.x.f_mul(&z2z2);
        let u2 = q.x.f_mul(&z1z1);
        let s1 = self.y.f_mul(&q.z).f_mul(&z2z2);
        let s2 = q.y.f_mul(&self.z).f_mul(&z1z1);
        let h = u2.f_sub(&u1);
        let rr = s2.f_sub(&s1);
        if h.f_is_zero() {
            return if rr.f_is_zero() { self.dbl() } else { Jac::inf() };
        }
        let i = h.f_dbl().f_sqr();
        let j = h.f_mul(&i);
        let r2 = rr.f_dbl();
        let v = u1.f_mul(&i);
        let x3 = r2.f_sqr().f_sub(&j).f_sub(&v.f_dbl());
        let y3 = r2.f_mul(&v.f_sub(&x3)).f_sub(&s1.f_mul(&j).f_dbl());
        let z3 = self.z.f_add(&q.z).f_sqr().f_sub(&z1z1).f_sub(&z2z2).f_mul(&h);
        Jac { x: x3, y: y3, z: z3 }
    }
    pub fn neg(&self) -> Self {
        Jac { x: self.x, y: self.y.f_neg(), z: self.z }
    }
    // スカラー倍 (k はリトルエンディアンの 32bit 列)
    pub fn mul_limbs(&self, k: &[u32]) -> Self {
        let mut r = Jac::inf();
        for limb in k.iter().rev() {
            for b in (0..32).rev() {
                r = r.dbl();
                if (limb >> b) & 1 == 1 {
                    r = r.add(self);
                }
            }
        }
        r
    }
    pub fn mul_u64(&self, k: u64) -> Self {
        self.mul_limbs(&[k as u32, (k >> 32) as u32])
    }
    // [|x|]P
    pub fn mul_abs_x(&self) -> Self {
        let mut r = *self;
        for b in (0..63).rev() {
            r = r.dbl();
            if (X_ABS >> b) & 1 == 1 {
                r = r.add(self);
            }
        }
        r
    }
    // [x]P (x < 0)
    pub fn mul_x(&self) -> Self {
        self.mul_abs_x().neg()
    }
    pub fn to_affine(&self) -> Option<(F, F)> {
        if self.is_inf() {
            return None;
        }
        let zi = self.z.f_inv();
        let zi2 = zi.f_sqr();
        Some((self.x.f_mul(&zi2), self.y.f_mul(&zi2).f_mul(&zi)))
    }
    // 逆元なしで比較
    pub fn equals(&self, q: &Self) -> bool {
        let (a, b) = (self.is_inf(), q.is_inf());
        if a || b {
            return a && b;
        }
        let z1z1 = self.z.f_sqr();
        let z2z2 = q.z.f_sqr();
        self.x.f_mul(&z2z2) == q.x.f_mul(&z1z1)
            && self.y.f_mul(&z2z2).f_mul(&q.z) == q.y.f_mul(&z1z1).f_mul(&self.z)
    }
    pub fn in_subgroup_slow(&self) -> bool {
        self.mul_limbs(&R_ORDER).is_inf()
    }
}

// まとめてアフィンに (逆元 1 回)。無限遠点は渡さないこと
pub fn to_affine_batch<F: Field>(ps: &[Jac<F>]) -> Vec<(F, F)> {
    let n = ps.len();
    if n == 0 {
        return vec![];
    }
    let mut acc = Vec::with_capacity(n);
    let mut prod = F::ONE;
    for p in ps {
        prod = prod.f_mul(&p.z);
        acc.push(prod);
    }
    let mut inv = prod.f_inv();
    let mut out = vec![(F::ZERO, F::ZERO); n];
    for i in (0..n).rev() {
        let zi = if i > 0 { inv.f_mul(&acc[i - 1]) } else { inv };
        inv = inv.f_mul(&ps[i].z);
        let zi2 = zi.f_sqr();
        out[i] = (ps[i].x.f_mul(&zi2), ps[i].y.f_mul(&zi2).f_mul(&zi));
    }
    out
}

// Σ k_i·P_i (2倍算を共有)
pub fn msm_u64<F: Field>(ps: &[Jac<F>], ks: &[u64]) -> Jac<F> {
    let mut r = Jac::inf();
    for b in (0..64).rev() {
        r = r.dbl();
        for (p, k) in ps.iter().zip(ks) {
            if (k >> b) & 1 == 1 {
                r = r.add(p);
            }
        }
    }
    r
}

pub fn b1() -> Fp {
    Fp::from_u64(4)
}
pub fn b2() -> Fp2 {
    Fp2::new(Fp::from_u64(4), Fp::from_u64(4))
}
pub fn g1_gen() -> G1 {
    Jac::from_affine(G1_X, G1_Y)
}
pub fn g2_gen() -> G2 {
    Jac::from_affine(crate::consts::G2_X, crate::consts::G2_Y)
}
pub fn is_on_curve_g1(x: &Fp, y: &Fp) -> bool {
    y.sqr() == x.sqr().mul(x).add(&b1())
}
pub fn is_on_curve_g2(x: &Fp2, y: &Fp2) -> bool {
    y.sqr() == x.sqr().mul(x).add(&b2())
}

// ─── 自己準同型と部分群チェック ───────────────────────────────────────
// ψ(x, y) = (conj(x)·ξ^(-(p-1)/3), conj(y)·ξ^(-(p-1)/2))  G2 上では [x] 倍
pub fn psi(p: &G2) -> G2 {
    Jac { x: p.x.conj().mul(&PSI_X), y: p.y.conj().mul(&PSI_Y), z: p.z.conj() }
}
// G1: σ(P) = (βx, y) が -[x²]P と一致するか
pub fn g1_in_subgroup(p: &G1) -> bool {
    let s = Jac { x: p.x.mul(&BETA), y: p.y, z: p.z };
    s.equals(&p.mul_abs_x().mul_abs_x().neg())
}
// G2: ψ(P) = [x]P か
pub fn g2_in_subgroup(p: &G2) -> bool {
    psi(p).equals(&p.mul_x())
}

// RFC 9380 G.3: h_eff 倍を ψ と [x] 倍 2 回で
pub fn clear_cofactor_g2(p: &G2) -> G2 {
    let t1 = p.mul_x();
    let t2 = psi(p);
    let mut t3 = psi(&psi(&p.dbl()));
    t3 = t3.add(&t2.neg());
    let t2b = t1.add(&t2).mul_x();
    t3 = t3.add(&t2b);
    t3 = t3.add(&t1.neg());
    t3.add(&p.neg())
}

// ─── G1 固定基点 (8bit ウィンドウの事前計算テーブル) ─────────────────
const W: usize = 8;
static G1_TABLE: OnceLock<Vec<Vec<(Fp, Fp)>>> = OnceLock::new();
fn g1_table() -> &'static Vec<Vec<(Fp, Fp)>> {
    G1_TABLE.get_or_init(|| {
        let rows = 255usize.div_ceil(W);
        let mut flat = Vec::with_capacity(rows * 255);
        let mut base = g1_gen();
        for _ in 0..rows {
            let (bx, by) = base.to_affine().unwrap();
            let mut acc = Jac::from_affine(bx, by);
            flat.push(acc);
            for _ in 2..256 {
                acc = acc.madd(&bx, &by);
                flat.push(acc);
            }
            for _ in 0..W {
                base = base.dbl();
            }
        }
        let aff = to_affine_batch(&flat);
        aff.chunks(255).map(|c| c.to_vec()).collect()
    })
}
// k·G1 (k はリトルエンディアンの 32bit × 8)
pub fn g1_mul_base(k: &[u32; 8]) -> G1 {
    let t = g1_table();
    let mut r = Jac::inf();
    for i in 0..32 {
        let d = ((k[i / 4] >> ((i % 4) * 8)) & 0xff) as usize;
        if d != 0 {
            let (x, y) = &t[i][d - 1];
            r = r.madd(x, y);
        }
    }
    r
}

// ─── G2 スカラー倍 (GLS: ψ で 4 分割して 64bit × 4 の同時倍算) ───────
//   φ = -ψ は G2 上で [|x|] 倍。k = k0 + k1|x| + k2|x|² + k3|x|³
pub fn g2_mul_gls(q: &G2, k: &[u32; 8]) -> G2 {
    // k を |x| 進数に (上の桁から割っていく)
    let mut digits = [0u64; 4];
    let mut cur = *k;
    for d in digits.iter_mut() {
        let mut rem: u128 = 0;
        let mut quo = [0u32; 8];
        for i in (0..8).rev() {
            rem = (rem << 32) | cur[i] as u128;
            quo[i] = (rem / X_ABS as u128) as u32;
            rem %= X_ABS as u128;
        }
        *d = rem as u64;
        cur = quo;
    }
    let phi = |p: &G2| psi(p).neg();
    let mut base = [*q; 4];
    for i in 1..4 {
        base[i] = phi(&base[i - 1]);
    }
    let mut sums = vec![Jac::inf(); 16];
    for m in 1..16usize {
        let low = m & m.wrapping_neg();
        sums[m] = sums[m ^ low].add(&base[low.trailing_zeros() as usize]);
    }
    let nz: Vec<usize> = (1..16).filter(|&m| !sums[m].is_inf()).collect();
    let aff = to_affine_batch(&nz.iter().map(|&m| sums[m]).collect::<Vec<_>>());
    let mut tbl: [Option<(Fp2, Fp2)>; 16] = [None; 16];
    for (i, &m) in nz.iter().enumerate() {
        tbl[m] = Some(aff[i]);
    }
    let mut r = Jac::inf();
    for bit in (0..64).rev() {
        r = r.dbl();
        let idx = (0..4).fold(0, |acc, j| acc | ((((digits[j] >> bit) & 1) as usize) << j));
        if let Some((x, y)) = &tbl[idx] {
            r = r.madd(x, y);
        }
    }
    r
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn curves() {
        let g1 = g1_gen();
        let g2 = g2_gen();
        assert!(is_on_curve_g1(&G1_X, &G1_Y));
        assert!(is_on_curve_g2(&crate::consts::G2_X, &crate::consts::G2_Y));
        assert!(g1.in_subgroup_slow());
        assert!(g2.in_subgroup_slow());
        assert!(g1_in_subgroup(&g1));
        assert!(g2_in_subgroup(&g2));
        let k = [0x12345678u32, 0x9abcdef0, 0x11111111, 0x22222222, 0x33333333, 0x44444444, 0x55555555, 0x06666666];
        assert!(g1_mul_base(&k).equals(&g1.mul_limbs(&k)));
        assert!(g2_mul_gls(&g2, &k).equals(&g2.mul_limbs(&k)));
        // G1 の外の点 (適当な x で曲線に乗る点) は部分群チェックに落ちる
        let mut x = Fp::from_u64(5);
        loop {
            if let Some(y) = x.sqr().mul(&x).add(&b1()).sqrt() {
                let p = Jac::from_affine(x, y);
                assert_eq!(g1_in_subgroup(&p), p.in_subgroup_slow());
                break;
            }
            x = x.add(&Fp::ONE);
        }
    }
}
