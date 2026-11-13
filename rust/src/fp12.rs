// Fp6 = Fp2[v]/(v³-ξ),  Fp12 = Fp6[w]/(w²-v)
// 最終冪 (Karabina の圧縮円分二乗つき) もここ
use crate::consts::{FROB, X_ABS};
use crate::fp2::Fp2;

#[derive(Clone, Copy, PartialEq, Eq, Debug, Default)]
pub struct Fp6 {
    pub c0: Fp2,
    pub c1: Fp2,
    pub c2: Fp2,
}

impl Fp6 {
    pub const ZERO: Fp6 = Fp6 { c0: Fp2::ZERO, c1: Fp2::ZERO, c2: Fp2::ZERO };
    pub const ONE: Fp6 = Fp6 { c0: Fp2::ONE, c1: Fp2::ZERO, c2: Fp2::ZERO };

    #[inline(always)]
    pub fn add(&self, b: &Fp6) -> Fp6 {
        Fp6 { c0: self.c0.add(&b.c0), c1: self.c1.add(&b.c1), c2: self.c2.add(&b.c2) }
    }
    #[inline(always)]
    pub fn sub(&self, b: &Fp6) -> Fp6 {
        Fp6 { c0: self.c0.sub(&b.c0), c1: self.c1.sub(&b.c1), c2: self.c2.sub(&b.c2) }
    }
    #[inline(always)]
    pub fn neg(&self) -> Fp6 {
        Fp6 { c0: self.c0.neg(), c1: self.c1.neg(), c2: self.c2.neg() }
    }
    // v を掛ける: (b0, b1, b2)·v = (ξ·b2, b0, b1)
    #[inline(always)]
    pub fn mul_v(&self) -> Fp6 {
        Fp6 { c0: self.c2.mul_xi(), c1: self.c0, c2: self.c1 }
    }
    // Karatsuba (Fp2 の掛け算 6 回)
    pub fn mul(&self, b: &Fp6) -> Fp6 {
        let t0 = self.c0.mul(&b.c0);
        let t1 = self.c1.mul(&b.c1);
        let t2 = self.c2.mul(&b.c2);
        let c0 = t0.add(&self.c1.add(&self.c2).mul(&b.c1.add(&b.c2)).sub(&t1).sub(&t2).mul_xi());
        let c1 = self.c0.add(&self.c1).mul(&b.c0.add(&b.c1)).sub(&t0).sub(&t1).add(&t2.mul_xi());
        let c2 = self.c0.add(&self.c2).mul(&b.c0.add(&b.c2)).sub(&t0).sub(&t2).add(&t1);
        Fp6 { c0, c1, c2 }
    }
    // CH-SQR2: Fp2 の二乗 3 回 + 掛け算 2 回
    pub fn sqr(&self) -> Fp6 {
        let s0 = self.c0.sqr();
        let s1 = self.c0.mul(&self.c1).double();
        let s2 = self.c0.sub(&self.c1).add(&self.c2).sqr();
        let s3 = self.c1.mul(&self.c2).double();
        let s4 = self.c2.sqr();
        Fp6 {
            c0: s0.add(&s3.mul_xi()),
            c1: s1.add(&s4.mul_xi()),
            c2: s1.add(&s2).add(&s3).sub(&s0).sub(&s4),
        }
    }
    // a·(b0 + b1·v)  Fp2 の掛け算 5 回
    #[inline(always)]
    pub fn mul_by_01(&self, b0: &Fp2, b1: &Fp2) -> Fp6 {
        let t0 = self.c0.mul(b0);
        let t1 = self.c1.mul(b1);
        Fp6 {
            c0: t0.add(&self.c2.mul(b1).mul_xi()),
            c1: self.c0.add(&self.c1).mul(&b0.add(b1)).sub(&t0).sub(&t1),
            c2: self.c2.mul(b0).add(&t1),
        }
    }
    // a·(b1·v)
    #[inline(always)]
    pub fn mul_by_1(&self, b1: &Fp2) -> Fp6 {
        Fp6 { c0: self.c2.mul(b1).mul_xi(), c1: self.c0.mul(b1), c2: self.c1.mul(b1) }
    }
    pub fn inv(&self) -> Fp6 {
        let c0 = self.c0.sqr().sub(&self.c1.mul(&self.c2).mul_xi());
        let c1 = self.c2.sqr().mul_xi().sub(&self.c0.mul(&self.c1));
        let c2 = self.c1.sqr().sub(&self.c0.mul(&self.c2));
        let t = self.c0.mul(&c0).add(&self.c2.mul(&c1).add(&self.c1.mul(&c2)).mul_xi()).inv();
        Fp6 { c0: c0.mul(&t), c1: c1.mul(&t), c2: c2.mul(&t) }
    }
}

#[derive(Clone, Copy, PartialEq, Eq, Debug, Default)]
pub struct Fp12 {
    pub c0: Fp6,
    pub c1: Fp6,
}

impl Fp12 {
    pub const ONE: Fp12 = Fp12 { c0: Fp6::ONE, c1: Fp6::ZERO };

    pub fn mul(&self, b: &Fp12) -> Fp12 {
        let t0 = self.c0.mul(&b.c0);
        let t1 = self.c1.mul(&b.c1);
        let t2 = self.c0.add(&self.c1).mul(&b.c0.add(&b.c1));
        Fp12 { c0: t0.add(&t1.mul_v()), c1: t2.sub(&t0).sub(&t1) }
    }
    // a0² + v·a1² = (a0 + a1)(a0 + v·a1) - a0a1 - v·a0a1,  2a0a1
    pub fn sqr(&self) -> Fp12 {
        let ab = self.c0.mul(&self.c1);
        let t = self.c0.add(&self.c1).mul(&self.c0.add(&self.c1.mul_v()));
        Fp12 { c0: t.sub(&ab).sub(&ab.mul_v()), c1: ab.add(&ab) }
    }
    // f · (c0 + c1·v + c4·v·w)  (直線の値は 3 か所しか埋まってない)
    pub fn mul_014(&self, c0: &Fp2, c1: &Fp2, c4: &Fp2) -> Fp12 {
        let t0 = self.c0.mul_by_01(c0, c1);
        let t1 = self.c1.mul_by_1(c4);
        let t2 = self.c0.add(&self.c1).mul_by_01(c0, &c1.add(c4));
        Fp12 { c0: t0.add(&t1.mul_v()), c1: t2.sub(&t0).sub(&t1) }
    }
    pub fn conj(&self) -> Fp12 {
        Fp12 { c0: self.c0, c1: self.c1.neg() }
    }
    pub fn inv(&self) -> Fp12 {
        let t = self.c0.sqr().sub(&self.c1.sqr().mul_v()).inv();
        Fp12 { c0: self.c0.mul(&t), c1: self.c1.mul(&t).neg() }
    }
    // フロベニウス a ↦ a^(p^k)。w^i の係数に conj^k と定数を掛ける
    //   w^i の位置: 0→c0.c0, 1→c1.c0, 2→c0.c1, 3→c1.c1, 4→c0.c2, 5→c1.c2
    pub fn frob(&self, k: usize) -> Fp12 {
        let g = &FROB[k - 1];
        let c = |x: &Fp2| if k % 2 == 1 { x.conj() } else { *x };
        Fp12 {
            c0: Fp6 { c0: c(&self.c0.c0), c1: c(&self.c0.c1).mul(&g[2]), c2: c(&self.c0.c2).mul(&g[4]) },
            c1: Fp6 { c0: c(&self.c1.c0).mul(&g[1]), c1: c(&self.c1.c1).mul(&g[3]), c2: c(&self.c1.c2).mul(&g[5]) },
        }
    }
    pub fn pow_u64s(&self, e: &[u32]) -> Fp12 {
        let mut r = Fp12::ONE;
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
}

// ─── 円分部分群 ───────────────────────────────────────────────────────
// Fp4 の二乗: (a² + ξb², 2ab)
#[inline(always)]
fn fp4_sqr(a: &Fp2, b: &Fp2) -> (Fp2, Fp2) {
    let a2 = a.sqr();
    let b2 = b.sqr();
    (a2.add(&b2.mul_xi()), a.add(b).sqr().sub(&a2).sub(&b2))
}
#[inline(always)]
fn m3m2(t: &Fp2, z: &Fp2) -> Fp2 {
    t.double().add(t).sub(&z.double()) // 3t - 2z
}
#[inline(always)]
fn m3p2(t: &Fp2, z: &Fp2) -> Fp2 {
    t.double().add(t).add(&z.double()) // 3t + 2z
}
// Granger–Scott
pub fn cyc_sqr(f: &Fp12) -> Fp12 {
    let (z0, z4, z3) = (f.c0.c0, f.c0.c1, f.c0.c2);
    let (z2, z1, z5) = (f.c1.c0, f.c1.c1, f.c1.c2);
    let (a0, a1) = fp4_sqr(&z0, &z1);
    let (b0, b1) = fp4_sqr(&z2, &z3);
    let (c0, c1) = fp4_sqr(&z4, &z5);
    Fp12 {
        c0: Fp6 { c0: m3m2(&a0, &z0), c1: m3m2(&b0, &z4), c2: m3m2(&c0, &z3) },
        c1: Fp6 { c0: m3p2(&c1.mul_xi(), &z2), c1: m3p2(&a1, &z1), c2: m3p2(&b1, &z5) },
    }
}

// Karabina: g1 = c0.c1, g2 = c0.c2, g3 = c1.c0, g5 = c1.c2 だけ持って二乗する
#[derive(Clone, Copy)]
struct Cyc4 {
    g1: Fp2,
    g2: Fp2,
    g3: Fp2,
    g5: Fp2,
}
#[inline(always)]
fn cyc_sqr_c(c: &Cyc4) -> Cyc4 {
    let (b0, b1) = fp4_sqr(&c.g3, &c.g2);
    let (c0, c1) = fp4_sqr(&c.g1, &c.g5);
    Cyc4 { g1: m3m2(&b0, &c.g1), g2: m3m2(&c0, &c.g2), g3: m3p2(&c1.mul_xi(), &c.g3), g5: m3p2(&b1, &c.g5) }
}
// 復元: g4 = (ξg5² + 3g1² - 2g2) / (4g3)  (g3 = 0 なら 2g1g5 / g2)
//       g0 = ξ(2g4² + g3g5 - 3g1g2) + 1   分母の逆元はまとめて 1 回
fn cyc_decompress_batch(cs: &[Cyc4]) -> Vec<Fp12> {
    let mut nums = Vec::with_capacity(cs.len());
    let mut dens = Vec::with_capacity(cs.len());
    for c in cs {
        if !c.g3.is_zero() {
            let g1s = c.g1.sqr();
            nums.push(c.g5.sqr().mul_xi().add(&g1s.double().add(&g1s)).sub(&c.g2.double()));
            dens.push(c.g3.double().double());
        } else {
            nums.push(c.g1.mul(&c.g5).double());
            dens.push(c.g2);
        }
    }
    let n = dens.len();
    let mut acc = vec![Fp2::ONE; n];
    let mut prod = Fp2::ONE;
    for i in 0..n {
        acc[i] = prod;
        if !dens[i].is_zero() {
            prod = prod.mul(&dens[i]);
        }
    }
    let mut inv = prod.inv();
    let mut invs = vec![Fp2::ZERO; n];
    for i in (0..n).rev() {
        if dens[i].is_zero() {
            continue;
        }
        invs[i] = inv.mul(&acc[i]);
        inv = inv.mul(&dens[i]);
    }
    cs.iter()
        .enumerate()
        .map(|(i, c)| {
            let g4 = nums[i].mul(&invs[i]);
            let g12 = c.g1.mul(&c.g2);
            let inner = g4.sqr().double().add(&c.g3.mul(&c.g5)).sub(&g12.double().add(&g12));
            let g0 = inner.mul_xi().add(&Fp2::ONE);
            Fp12 { c0: Fp6 { c0: g0, c1: c.g1, c2: c.g2 }, c1: Fp6 { c0: c.g3, c1: g4, c2: c.g5 } }
        })
        .collect()
}

// f^x (x < 0)。f^|x| = Π f^(2^k) (|x| の立っているビット k)
pub fn cyc_exp(f: &Fp12) -> Fp12 {
    let mut c = Cyc4 { g1: f.c0.c1, g2: f.c0.c2, g3: f.c1.c0, g5: f.c1.c2 };
    let mut picks = Vec::with_capacity(6);
    let mut k = 0;
    for pos in 0..64 {
        if (X_ABS >> pos) & 1 == 0 {
            continue;
        }
        while k < pos {
            c = cyc_sqr_c(&c);
            k += 1;
        }
        picks.push(c);
    }
    let fs = cyc_decompress_batch(&picks);
    let mut r = fs[0];
    for x in &fs[1..] {
        r = r.mul(x);
    }
    r.conj()
}

// 最終冪 f^(3(p¹²-1)/r)
//   easy: (p⁶-1)(p²+1)
//   hard: λ3 = (x-1)², λ2 = λ3·x, λ1 = λ2·x - λ3, λ0 = λ1·x + 3
pub fn final_exp(f: &Fp12) -> Fp12 {
    let mut t = f.conj().mul(&f.inv());
    t = t.frob(2).mul(&t);
    let a = cyc_exp(&t).mul(&t.conj());
    let a3 = cyc_exp(&a).mul(&a.conj());
    let a2 = cyc_exp(&a3);
    let a1 = cyc_exp(&a2).mul(&a3.conj());
    let a0 = cyc_exp(&a1).mul(&cyc_sqr(&t)).mul(&t);
    a0.mul(&a1.frob(1)).mul(&a2.frob(2).mul(&a3.frob(3)))
}
