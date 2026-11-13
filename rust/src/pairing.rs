// optimal ate ペアリング
//   直線を P で評価して w³ 倍すると 0, 1, 4 番目だけ埋まる (TS 版と同じ式)
//   倍算 (T はヤコビアン): c0 = 3X³ - 2Y², c1 = -3X²Z²·xP, c4 = 2YZ·Z²·yP
//   加算 (T + Q):          c0 = 2r·xQ - yQ·Z3, c1 = -2r·xP, c4 = Z3·yP
use crate::consts::X_ABS;
use crate::fp::Fp;
use crate::fp12::{final_exp, Fp12};
use crate::fp2::Fp2;

pub type Pair = ((Fp, Fp), (Fp2, Fp2));

pub fn miller_loop(pairs: &[Pair]) -> Fp12 {
    let mut ts: Vec<(Fp2, Fp2, Fp2)> = pairs.iter().map(|(_, q)| (q.0, q.1, Fp2::ONE)).collect();
    let mut f = Fp12::ONE;
    for b in (0..63).rev() {
        if b != 62 {
            f = f.sqr(); // 二乗は全ペアで共有 (最初は f = 1 なので飛ばす)
        }
        for (j, ((xp, yp), _)) in pairs.iter().enumerate() {
            let (x, y, z) = ts[j];
            let xx = x.sqr();
            let yy = y.sqr();
            let zz = z.sqr();
            let c = yy.sqr();
            let e = xx.double().add(&xx);
            let d = x.add(&yy).sqr().sub(&xx).sub(&c).double();
            let x3 = e.sqr().sub(&d.double());
            let y3 = e.mul(&d.sub(&x3)).sub(&c.double().double().double());
            let z3 = y.mul(&z).double();
            ts[j] = (x3, y3, z3);
            f = f.mul_014(&e.mul(&x).sub(&yy.double()), &e.mul(&zz).neg().mul_fp(xp), &z3.mul(&zz).mul_fp(yp));
        }
        if (X_ABS >> b) & 1 == 1 {
            for (j, ((xp, yp), (xq, yq))) in pairs.iter().enumerate() {
                let (x, y, z) = ts[j];
                let zz = z.sqr();
                let u2 = xq.mul(&zz);
                let s2 = yq.mul(&z).mul(&zz);
                let h = u2.sub(&x);
                let hh = h.sqr();
                let i = hh.double().double();
                let jj = h.mul(&i);
                let rr = s2.sub(&y).double();
                let v = x.mul(&i);
                let x3 = rr.sqr().sub(&jj).sub(&v.double());
                let y3 = rr.mul(&v.sub(&x3)).sub(&y.mul(&jj).double());
                let z3 = z.add(&h).sqr().sub(&zz).sub(&hh);
                ts[j] = (x3, y3, z3);
                f = f.mul_014(&rr.mul(xq).sub(&yq.mul(&z3)), &rr.neg().mul_fp(xp), &z3.mul_fp(yp));
            }
        }
    }
    f.conj() // x < 0
}

pub fn pairing(p: (Fp, Fp), q: (Fp2, Fp2)) -> Fp12 {
    final_exp(&miller_loop(&[(p, q)]))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::curve::{g1_gen, g2_gen};
    use crate::consts::R_ORDER;
    #[test]
    fn bilinear() {
        let g1 = g1_gen();
        let g2 = g2_gen();
        let e = pairing(g1.to_affine().unwrap(), g2.to_affine().unwrap());
        assert_ne!(e, Fp12::ONE);
        assert_eq!(e.pow_u64s(&R_ORDER), Fp12::ONE);
        let (a, b) = (123456789u64, 987654321u64);
        let eab = pairing(g1.mul_u64(a).to_affine().unwrap(), g2.mul_u64(b).to_affine().unwrap());
        let ab = (a as u128) * (b as u128);
        assert_eq!(eab, e.pow_u64s(&[ab as u32, (ab >> 32) as u32, (ab >> 64) as u32]));
    }
}
