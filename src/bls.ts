// BLS署名 (Boneh–Lynn–Shacham) on BLS12-381
//   - 外部ライブラリなし。bigint だけで全部書く
//   - 方式: min-pk (公開鍵 G1 48byte / 署名 G2 96byte)。Ethereum とかと同じ並び
//   - hash-to-curve: RFC 9380 BLS12381G2_XMD:SHA-256_SSWU_RO_
//   - 圧縮形式: ZCash 形式 (0x80 圧縮 / 0x40 無限遠 / 0x20 y の符号)

// ─── 型 ─────────────────────────────────────────────────────────────
export type Fp2 = [bigint, bigint]; // a0 + a1·u   (u² = -1)
export type Fp6 = [Fp2, Fp2, Fp2]; // b0 + b1·v + b2·v²   (v³ = ξ = u + 1)
export type Fp12 = [Fp6, Fp6]; // c0 + c1·w   (w² = v)
type Jac<T> = [T, T, T]; // ヤコビアン座標 (X, Y, Z)  x = X/Z², y = Y/Z³
type Aff<T> = [T, T] | null; // アフィン座標。null = 無限遠点

// ─── 定数 ───────────────────────────────────────────────────────────
const P =
  0x1a0111ea397fe69a4b1ba7b6434bacd764774b84f38512bf6730d2a0f6b0f6241eabfffeb153ffffb9feffffffffaaabn;
const R = 0x73eda753299d7d483339d80809a1d80553bda402fffe5bfeffffffff00000001n;
// BLS パラメータ x = -0xd201000000010000 (負)
const X_ABS = 0xd201000000010000n;
// G2 の実効コファクター (RFC 9380 8.8.2)
const H_EFF_G2 =
  0xbc69f08f2ee75b3584c6a0ea91b352888e2a8e9145ad7689986ff031508ffe1329c2f178731db956d82bf015d1212b02ec0ec69d7477c1ae954cbc06689f6a359894c0adebbf6b4e8020005aaa95551n;

export const DST_NUL = "BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_NUL_";
export const DST_POP = "BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_POP_";

// ═══ Fp ═════════════════════════════════════════════════════════════
const m = (a: bigint): bigint => {
  const r = a % P;
  return r < 0n ? r + P : r;
};
const fpInv = (a: bigint): bigint => {
  let r0 = P,
    r1 = m(a);
  if (r1 === 0n) throw new Error("0 の逆元はない");
  let x0 = 0n,
    x1 = 1n;
  while (r1 !== 0n) {
    const q = r0 / r1;
    [r0, r1] = [r1, r0 - q * r1];
    [x0, x1] = [x1, x0 - q * x1];
  }
  return x0 < 0n ? x0 + P : x0;
};
const powMod = (b: bigint, e: bigint, mod: bigint): bigint => {
  let r = 1n;
  b %= mod;
  if (b < 0n) b += mod;
  while (e > 0n) {
    if (e & 1n) r = (r * b) % mod;
    b = (b * b) % mod;
    e >>= 1n;
  }
  return r;
};
// p ≡ 3 (mod 4) なので √a = a^((p+1)/4)
const fpSqrt = (a: bigint): bigint | null => {
  const r = powMod(a, (P + 1n) / 4n, P);
  return (r * r) % P === m(a) ? r : null;
};
const fpIsSquare = (a: bigint): boolean => {
  a = m(a);
  return a === 0n || powMod(a, (P - 1n) / 2n, P) === 1n;
};

// ═══ Fp2 = Fp[u]/(u²+1) ═════════════════════════════════════════════
const F2_0: Fp2 = [0n, 0n];
const F2_1: Fp2 = [1n, 0n];
const f2 = (a: bigint, b = 0n): Fp2 => [m(a), m(b)];
const f2add = (a: Fp2, b: Fp2): Fp2 => [m(a[0] + b[0]), m(a[1] + b[1])];
const f2sub = (a: Fp2, b: Fp2): Fp2 => [m(a[0] - b[0]), m(a[1] - b[1])];
const f2neg = (a: Fp2): Fp2 => [m(-a[0]), m(-a[1])];
const f2mul = (a: Fp2, b: Fp2): Fp2 => {
  // Karatsuba: 掛け算 3 回
  const t0 = a[0] * b[0];
  const t1 = a[1] * b[1];
  return [m(t0 - t1), m((a[0] + a[1]) * (b[0] + b[1]) - t0 - t1)];
};
const f2sqr = (a: Fp2): Fp2 => [
  m((a[0] + a[1]) * (a[0] - a[1])),
  m(2n * a[0] * a[1]),
];
const f2mulFp = (a: Fp2, k: bigint): Fp2 => [m(a[0] * k), m(a[1] * k)];
const f2conj = (a: Fp2): Fp2 => [a[0], m(-a[1])];
const f2inv = (a: Fp2): Fp2 => {
  const t = fpInv(a[0] * a[0] + a[1] * a[1]);
  return [m(a[0] * t), m(-a[1] * t)];
};
const f2eq = (a: Fp2, b: Fp2) => a[0] === b[0] && a[1] === b[1];
const f2isZero = (a: Fp2) => a[0] === 0n && a[1] === 0n;
// ξ = u + 1 を掛ける: (a0 + a1u)(1 + u) = (a0 - a1) + (a0 + a1)u
const f2mulXi = (a: Fp2): Fp2 => [m(a[0] - a[1]), m(a[0] + a[1])];
const f2pow = (a: Fp2, e: bigint): Fp2 => {
  let r = F2_1;
  let b = a;
  while (e > 0n) {
    if (e & 1n) r = f2mul(r, b);
    b = f2sqr(b);
    e >>= 1n;
  }
  return r;
};
// ノルム a0² + a1² が Fp で平方剰余なら Fp2 でも平方剰余
const f2isSquare = (a: Fp2) => fpIsSquare(a[0] * a[0] + a[1] * a[1]);
// Adj & Rodríguez-Henríquez Algorithm 9 (p ≡ 3 mod 4)
const f2sqrt = (a: Fp2): Fp2 | null => {
  if (f2isZero(a)) return F2_0;
  const a1 = f2pow(a, (P - 3n) / 4n);
  const alpha = f2mul(f2sqr(a1), a);
  const x0 = f2mul(a1, a);
  let x: Fp2;
  if (f2eq(alpha, [P - 1n, 0n])) {
    x = [m(-x0[1]), x0[0]]; // u·x0
  } else {
    const b = f2pow(f2add(F2_1, alpha), (P - 1n) / 2n);
    x = f2mul(b, x0);
  }
  return f2eq(f2sqr(x), a) ? x : null;
};
// RFC 9380 sgn0 (m = 2)
const f2sgn0 = (a: Fp2): number => {
  const sign0 = Number(a[0] & 1n);
  const zero0 = a[0] === 0n ? 1 : 0;
  const sign1 = Number(a[1] & 1n);
  return sign0 | (zero0 & sign1);
};

// ═══ Fp6 = Fp2[v]/(v³-ξ) ════════════════════════════════════════════
const F6_0: Fp6 = [F2_0, F2_0, F2_0];
const F6_1: Fp6 = [F2_1, F2_0, F2_0];
const f6add = (a: Fp6, b: Fp6): Fp6 => [
  f2add(a[0], b[0]),
  f2add(a[1], b[1]),
  f2add(a[2], b[2]),
];
const f6sub = (a: Fp6, b: Fp6): Fp6 => [
  f2sub(a[0], b[0]),
  f2sub(a[1], b[1]),
  f2sub(a[2], b[2]),
];
const f6neg = (a: Fp6): Fp6 => [f2neg(a[0]), f2neg(a[1]), f2neg(a[2])];
const f6mul = (a: Fp6, b: Fp6): Fp6 => {
  const t0 = f2mul(a[0], b[0]);
  const t1 = f2mul(a[1], b[1]);
  const t2 = f2mul(a[2], b[2]);
  const c0 = f2add(
    t0,
    f2mulXi(
      f2sub(f2sub(f2mul(f2add(a[1], a[2]), f2add(b[1], b[2])), t1), t2),
    ),
  );
  const c1 = f2add(
    f2sub(f2sub(f2mul(f2add(a[0], a[1]), f2add(b[0], b[1])), t0), t1),
    f2mulXi(t2),
  );
  const c2 = f2add(
    f2sub(f2sub(f2mul(f2add(a[0], a[2]), f2add(b[0], b[2])), t0), t2),
    t1,
  );
  return [c0, c1, c2];
};
// v を掛ける: (b0, b1, b2)·v = (ξ·b2, b0, b1)
const f6mulV = (a: Fp6): Fp6 => [f2mulXi(a[2]), a[0], a[1]];
const f6inv = (a: Fp6): Fp6 => {
  const [a0, a1, a2] = a;
  const c0 = f2sub(f2sqr(a0), f2mulXi(f2mul(a1, a2)));
  const c1 = f2sub(f2mulXi(f2sqr(a2)), f2mul(a0, a1));
  const c2 = f2sub(f2sqr(a1), f2mul(a0, a2));
  const t = f2inv(
    f2add(f2mul(a0, c0), f2mulXi(f2add(f2mul(a2, c1), f2mul(a1, c2)))),
  );
  return [f2mul(c0, t), f2mul(c1, t), f2mul(c2, t)];
};

// ═══ Fp12 = Fp6[w]/(w²-v) ═══════════════════════════════════════════
const F12_1: Fp12 = [F6_1, F6_0];
const f12mul = (a: Fp12, b: Fp12): Fp12 => {
  const t0 = f6mul(a[0], b[0]);
  const t1 = f6mul(a[1], b[1]);
  return [
    f6add(t0, f6mulV(t1)),
    f6sub(f6sub(f6mul(f6add(a[0], a[1]), f6add(b[0], b[1])), t0), t1),
  ];
};
const f12sqr = (a: Fp12): Fp12 => {
  // (a0 + a1w)² = a0² + v·a1² + 2a0a1·w
  const ab = f6mul(a[0], a[1]);
  const c0 = f6sub(
    f6sub(f6mul(f6add(a[0], a[1]), f6add(a[0], f6mulV(a[1]))), ab),
    f6mulV(ab),
  );
  return [c0, f6add(ab, ab)];
};
const f12conj = (a: Fp12): Fp12 => [a[0], f6neg(a[1])];
const f12inv = (a: Fp12): Fp12 => {
  const t = f6inv(f6sub(f6mul(a[0], a[0]), f6mulV(f6mul(a[1], a[1]))));
  return [f6mul(a[0], t), f6neg(f6mul(a[1], t))];
};
const f12eq = (a: Fp12, b: Fp12) =>
  a.every((c, i) => c.every((d, j) => f2eq(d, b[i][j])));
const f12pow = (a: Fp12, e: bigint): Fp12 => {
  let r = F12_1;
  const bits = e.toString(2);
  for (const bit of bits) {
    r = f12sqr(r);
    if (bit === "1") r = f12mul(r, a);
  }
  return r;
};

// フロベニウス写像 a ↦ a^(p^k)
//   Fp12 の元を Σ a_i·w^i (i = 0..5, a_i ∈ Fp2) と見ると
//   (a_i·w^i)^(p^k) = conj^k(a_i) · ξ^(i(p^k-1)/6) · w^i
//   この ξ^(...) を起動時に計算しておく (ハードコード不要)
// w^i の位置: i=0→c0[0], 1→c1[0], 2→c0[1], 3→c1[1], 4→c0[2], 5→c1[2]
const FROB: Fp2[][] = [1, 2, 3].map((k) => {
  const e = (P ** BigInt(k) - 1n) / 6n;
  const g = f2pow([1n, 1n], e);
  const out: Fp2[] = [F2_1];
  for (let i = 1; i < 6; i++) out.push(f2mul(out[i - 1], g));
  return out;
});
const f12frob = (a: Fp12, k: 1 | 2 | 3): Fp12 => {
  const g = FROB[k - 1];
  const c = (x: Fp2) => (k % 2 === 1 ? f2conj(x) : x);
  return [
    [c(a[0][0]), f2mul(c(a[0][1]), g[2]), f2mul(c(a[0][2]), g[4])],
    [f2mul(c(a[1][0]), g[1]), f2mul(c(a[1][1]), g[3]), f2mul(c(a[1][2]), g[5])],
  ];
};

// ═══ 楕円曲線 (y² = x³ + b, a = 0) をフィールド汎用で ═══════════════
interface Field<T> {
  add(a: T, b: T): T;
  sub(a: T, b: T): T;
  mul(a: T, b: T): T;
  sqr(a: T): T;
  neg(a: T): T;
  inv(a: T): T;
  isZero(a: T): boolean;
  eq(a: T, b: T): boolean;
  zero: T;
  one: T;
}
const FP: Field<bigint> = {
  add: (a, b) => m(a + b),
  sub: (a, b) => m(a - b),
  mul: (a, b) => (a * b) % P,
  sqr: (a) => (a * a) % P,
  neg: (a) => m(-a),
  inv: fpInv,
  isZero: (a) => a === 0n,
  eq: (a, b) => a === b,
  zero: 0n,
  one: 1n,
};
const FP2: Field<Fp2> = {
  add: f2add,
  sub: f2sub,
  mul: f2mul,
  sqr: f2sqr,
  neg: f2neg,
  inv: f2inv,
  isZero: f2isZero,
  eq: f2eq,
  zero: F2_0,
  one: F2_1,
};

class Curve<T> {
  constructor(
    readonly F: Field<T>,
    readonly b: T,
  ) {}
  get inf(): Jac<T> {
    return [this.F.one, this.F.one, this.F.zero];
  }
  isInf(p: Jac<T>) {
    return this.F.isZero(p[2]);
  }
  fromAffine(a: Aff<T>): Jac<T> {
    return a ? [a[0], a[1], this.F.one] : this.inf;
  }
  // dbl-2009-l (a = 0)
  dbl(p: Jac<T>): Jac<T> {
    const F = this.F;
    const [X, Y, Z] = p;
    if (F.isZero(Z)) return p;
    const A = F.sqr(X);
    const B = F.sqr(Y);
    const C = F.sqr(B);
    let D = F.sub(F.sub(F.sqr(F.add(X, B)), A), C);
    D = F.add(D, D);
    const E = F.add(F.add(A, A), A);
    const Fv = F.sqr(E);
    const X3 = F.sub(Fv, F.add(D, D));
    let C8 = F.add(C, C);
    C8 = F.add(C8, C8);
    C8 = F.add(C8, C8);
    const Y3 = F.sub(F.mul(E, F.sub(D, X3)), C8);
    const YZ = F.mul(Y, Z);
    return [X3, Y3, F.add(YZ, YZ)];
  }
  // add-2007-bl
  add(p: Jac<T>, q: Jac<T>): Jac<T> {
    const F = this.F;
    if (this.isInf(p)) return q;
    if (this.isInf(q)) return p;
    const [X1, Y1, Z1] = p;
    const [X2, Y2, Z2] = q;
    const Z1Z1 = F.sqr(Z1);
    const Z2Z2 = F.sqr(Z2);
    const U1 = F.mul(X1, Z2Z2);
    const U2 = F.mul(X2, Z1Z1);
    const S1 = F.mul(F.mul(Y1, Z2), Z2Z2);
    const S2 = F.mul(F.mul(Y2, Z1), Z1Z1);
    const H = F.sub(U2, U1);
    const rr = F.sub(S2, S1);
    if (F.isZero(H)) return F.isZero(rr) ? this.dbl(p) : this.inf;
    const I = F.sqr(F.add(H, H));
    const J = F.mul(H, I);
    const r2 = F.add(rr, rr);
    const V = F.mul(U1, I);
    const X3 = F.sub(F.sub(F.sqr(r2), J), F.add(V, V));
    const S1J = F.mul(S1, J);
    const Y3 = F.sub(F.mul(r2, F.sub(V, X3)), F.add(S1J, S1J));
    const Z3 = F.mul(F.sub(F.sub(F.sqr(F.add(Z1, Z2)), Z1Z1), Z2Z2), H);
    return [X3, Y3, Z3];
  }
  neg(p: Jac<T>): Jac<T> {
    return [p[0], this.F.neg(p[1]), p[2]];
  }
  mul(p: Jac<T>, k: bigint): Jac<T> {
    if (k < 0n) return this.mul(this.neg(p), -k);
    let r = this.inf;
    for (const bit of k.toString(2)) {
      r = this.dbl(r);
      if (bit === "1") r = this.add(r, p);
    }
    return r;
  }
  toAffine(p: Jac<T>): Aff<T> {
    const F = this.F;
    if (this.isInf(p)) return null;
    const zi = F.inv(p[2]);
    const zi2 = F.sqr(zi);
    return [F.mul(p[0], zi2), F.mul(F.mul(p[1], zi2), zi)];
  }
  eq(p: Jac<T>, q: Jac<T>) {
    const a = this.toAffine(p);
    const b = this.toAffine(q);
    if (!a || !b) return a === b;
    return this.F.eq(a[0], b[0]) && this.F.eq(a[1], b[1]);
  }
  isOnCurve(a: Aff<T>) {
    if (!a) return true;
    const F = this.F;
    const [x, y] = a;
    return F.eq(F.sqr(y), F.add(F.mul(F.sqr(x), x), this.b));
  }
  // r 倍して無限遠になるか (素直な部分群チェック)
  inSubgroup(p: Jac<T>) {
    return this.isInf(this.mul(p, R));
  }
}

// E1: y² = x³ + 4 over Fp
const E1 = new Curve<bigint>(FP, 4n);
// E2: y² = x³ + 4(u+1) over Fp2 (twist)
const E2 = new Curve<Fp2>(FP2, [4n, 4n]);

const G1: Jac<bigint> = [
  0x17f1d3a73197d7942695638c4fa9ac0fc3688c4f9774b905a14e3a3f171bac586c55e83ff97a1aeffb3af00adb22c6bbn,
  0x08b3f481e3aaa0f1a09e30ed741d8ae4fcf5e095d5d00af600db18cb2c04b3edd03cc744a2888ae40caa232946c5e7e1n,
  1n,
];
const G2: Jac<Fp2> = [
  [
    0x024aa2b2f08f0a91260805272dc51051c6e47ad4fa403b02b4510b647ae3d1770bac0326a805bbefd48056c8c121bdb8n,
    0x13e02b6052719f607dacd3a088274f65596bd0d09920b61ab5da61bbdc7f5049334cf11213945d57e5ac7d055d042b7en,
  ],
  [
    0x0ce5d527727d6e118cc9cdc6da2e351aadfd9baa8cbdd3a76d429a695160d12c923ac9cc3baca289e193548608b82801n,
    0x0606c4a02ea734cc32acd2b02bc28b99cb3e287e85a763af267492ab572e99ab3f370d275cec1da1aaa9075ff05f79ben,
  ],
  F2_1,
];

// ═══ ペアリング (optimal ate) ═══════════════════════════════════════
// ツイスト上の点 Q' = (x', y') は E 上の (x'/w², y'/w³) に対応する。
// 傾き λ' の直線を P = (xP, yP) ∈ E(Fp) で評価して w³ 倍すると
//   l·w³ = (λ'·xT - yT) + (-λ'·xP)·w² + yP·w³
//        = Fp12( c0 = [λ'xT - yT, -λ'xP, 0], c1 = [0, yP, 0] )
// (w³ は真部分体の元なので最終冪で消える。垂直線も同様に消える)
const lineEval = (lambda: Fp2, xT: Fp2, yT: Fp2, xP: bigint, yP: bigint): Fp12 => [
  [f2sub(f2mul(lambda, xT), yT), f2mulFp(f2neg(lambda), xP), F2_0],
  [F2_0, [yP, 0n], F2_0],
];

const millerLoop = (Pa: Aff<bigint>, Qa: Aff<Fp2>): Fp12 => {
  if (!Pa || !Qa) return F12_1;
  const [xP, yP] = Pa;
  const [xQ, yQ] = Qa;
  let xT = xQ,
    yT = yQ;
  let f = F12_1;
  const bits = X_ABS.toString(2);
  for (let i = 1; i < bits.length; i++) {
    // 接線 (T + T)
    const lam = f2mul(f2mulFp(f2sqr(xT), 3n), f2inv(f2add(yT, yT)));
    f = f12mul(f12sqr(f), lineEval(lam, xT, yT, xP, yP));
    const x3 = f2sub(f2sqr(lam), f2add(xT, xT));
    yT = f2sub(f2mul(lam, f2sub(xT, x3)), yT);
    xT = x3;
    if (bits[i] === "1") {
      // 割線 (T + Q)
      const lam2 = f2mul(f2sub(yQ, yT), f2inv(f2sub(xQ, xT)));
      f = f12mul(f, lineEval(lam2, xT, yT, xP, yP));
      const x4 = f2sub(f2sub(f2sqr(lam2), xT), xQ);
      yT = f2sub(f2mul(lam2, f2sub(xT, x4)), yT);
      xT = x4;
    }
  }
  // x < 0 なので共役を取る
  return f12conj(f);
};

// 最終冪 f^((p¹²-1)/r)
//   easy: (p⁶-1)(p²+1)  hard: (p⁴-p²+1)/r
const HARD_EXP = (P ** 4n - P ** 2n + 1n) / R;
const finalExp = (f: Fp12): Fp12 => {
  let t = f12mul(f12conj(f), f12inv(f)); // f^(p⁶-1)
  t = f12mul(f12frob(t, 2), t); // ^(p²+1)
  return f12pow(t, HARD_EXP);
};

const pairing = (Pp: Jac<bigint>, Qp: Jac<Fp2>): Fp12 =>
  finalExp(millerLoop(E1.toAffine(Pp), E2.toAffine(Qp)));

// Π e(P_i, Q_i) をまとめて計算 (最終冪は1回)
const multiPairing = (pairs: [Jac<bigint>, Jac<Fp2>][]): Fp12 => {
  let f = F12_1;
  for (const [Pp, Qp] of pairs)
    f = f12mul(f, millerLoop(E1.toAffine(Pp), E2.toAffine(Qp)));
  return finalExp(f);
};

// ═══ SHA-256 ═══════════════════════════════════════════════════════
const K256 = new Uint32Array([
  0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1,
  0x923f82a4, 0xab1c5ed5, 0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
  0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174, 0xe49b69c1, 0xefbe4786,
  0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
  0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147,
  0x06ca6351, 0x14292967, 0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
  0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85, 0xa2bfe8a1, 0xa81a664b,
  0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
  0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a,
  0x5b9cca4f, 0x682e6ff3, 0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
  0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
]);
export const sha256 = (msg: Uint8Array): Uint8Array => {
  const len = msg.length;
  const total = (((len + 9 + 63) >> 6) << 6) >>> 0;
  const buf = new Uint8Array(total);
  buf.set(msg);
  buf[len] = 0x80;
  const dv = new DataView(buf.buffer);
  dv.setUint32(total - 8, Math.floor(len / 0x20000000));
  dv.setUint32(total - 4, (len << 3) >>> 0);
  const H = new Uint32Array([
    0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c,
    0x1f83d9ab, 0x5be0cd19,
  ]);
  const W = new Uint32Array(64);
  const rotr = (x: number, n: number) => (x >>> n) | (x << (32 - n));
  for (let off = 0; off < total; off += 64) {
    for (let i = 0; i < 16; i++) W[i] = dv.getUint32(off + i * 4);
    for (let i = 16; i < 64; i++) {
      const s0 = rotr(W[i - 15], 7) ^ rotr(W[i - 15], 18) ^ (W[i - 15] >>> 3);
      const s1 = rotr(W[i - 2], 17) ^ rotr(W[i - 2], 19) ^ (W[i - 2] >>> 10);
      W[i] = (W[i - 16] + s0 + W[i - 7] + s1) >>> 0;
    }
    let [a, b, c, d, e, f, g, h] = H;
    for (let i = 0; i < 64; i++) {
      const S1 = rotr(e, 6) ^ rotr(e, 11) ^ rotr(e, 25);
      const ch = (e & f) ^ (~e & g);
      const t1 = (h + S1 + ch + K256[i] + W[i]) >>> 0;
      const S0 = rotr(a, 2) ^ rotr(a, 13) ^ rotr(a, 22);
      const maj = (a & b) ^ (a & c) ^ (b & c);
      const t2 = (S0 + maj) >>> 0;
      h = g;
      g = f;
      f = e;
      e = (d + t1) >>> 0;
      d = c;
      c = b;
      b = a;
      a = (t1 + t2) >>> 0;
    }
    H[0] += a;
    H[1] += b;
    H[2] += c;
    H[3] += d;
    H[4] += e;
    H[5] += f;
    H[6] += g;
    H[7] += h;
  }
  const out = new Uint8Array(32);
  const ov = new DataView(out.buffer);
  for (let i = 0; i < 8; i++) ov.setUint32(i * 4, H[i]);
  return out;
};

// ═══ hash-to-curve (RFC 9380) ═══════════════════════════════════════
const concat = (...arrs: Uint8Array[]): Uint8Array => {
  const out = new Uint8Array(arrs.reduce((s, a) => s + a.length, 0));
  let o = 0;
  for (const a of arrs) {
    out.set(a, o);
    o += a.length;
  }
  return out;
};
const i2osp = (v: number, len: number): Uint8Array => {
  const out = new Uint8Array(len);
  for (let i = len - 1; i >= 0; i--) {
    out[i] = v & 0xff;
    v >>>= 8;
  }
  return out;
};
const bytesToBig = (b: Uint8Array): bigint => {
  let r = 0n;
  for (const x of b) r = (r << 8n) | BigInt(x);
  return r;
};
const bigToBytes = (n: bigint, len: number): Uint8Array => {
  const out = new Uint8Array(len);
  for (let i = len - 1; i >= 0; i--) {
    out[i] = Number(n & 0xffn);
    n >>= 8n;
  }
  return out;
};

// 5.3.1 expand_message_xmd (SHA-256: b_in_bytes = 32, s_in_bytes = 64)
export const expandMessageXmd = (
  msg: Uint8Array,
  dst: Uint8Array,
  lenInBytes: number,
): Uint8Array => {
  const ell = Math.ceil(lenInBytes / 32);
  if (ell > 255 || lenInBytes > 65535 || dst.length > 255)
    throw new Error("expand_message_xmd: 長すぎ");
  const dstPrime = concat(dst, i2osp(dst.length, 1));
  const b0 = sha256(
    concat(new Uint8Array(64), msg, i2osp(lenInBytes, 2), i2osp(0, 1), dstPrime),
  );
  const bs: Uint8Array[] = [sha256(concat(b0, i2osp(1, 1), dstPrime))];
  for (let i = 2; i <= ell; i++) {
    const prev = bs[bs.length - 1];
    const x = new Uint8Array(32);
    for (let j = 0; j < 32; j++) x[j] = b0[j] ^ prev[j];
    bs.push(sha256(concat(x, i2osp(i, 1), dstPrime)));
  }
  return concat(...bs).slice(0, lenInBytes);
};

// 5.2 hash_to_field (Fp2, count = 2, L = 64)
const hashToFieldFp2 = (msg: Uint8Array, dst: Uint8Array): [Fp2, Fp2] => {
  const L = 64;
  const bytes = expandMessageXmd(msg, dst, 2 * 2 * L);
  const e = (k: number) => m(bytesToBig(bytes.subarray(k * L, (k + 1) * L)));
  return [
    [e(0), e(1)],
    [e(2), e(3)],
  ];
};

// 6.6.2 Simplified SWU on E2': y² = x³ + A'x + B'
const SSWU_A: Fp2 = [0n, 240n];
const SSWU_B: Fp2 = [1012n, 1012n];
const SSWU_Z: Fp2 = f2(-2n, -1n);
const mapToCurveSSWU = (u: Fp2): [Fp2, Fp2] => {
  const A = SSWU_A,
    B = SSWU_B,
    Z = SSWU_Z;
  const u2 = f2sqr(u);
  const zu2 = f2mul(Z, u2);
  const den = f2add(f2sqr(zu2), zu2); // Z²u⁴ + Zu²
  let x1: Fp2;
  if (f2isZero(den)) {
    x1 = f2mul(B, f2inv(f2mul(Z, A)));
  } else {
    const tv1 = f2inv(den);
    x1 = f2mul(f2mul(f2neg(B), f2inv(A)), f2add(F2_1, tv1));
  }
  const g = (x: Fp2) => f2add(f2add(f2mul(f2sqr(x), x), f2mul(A, x)), B);
  const gx1 = g(x1);
  let x: Fp2, y: Fp2;
  if (f2isSquare(gx1)) {
    x = x1;
    y = f2sqrt(gx1)!;
  } else {
    x = f2mul(zu2, x1);
    y = f2sqrt(g(x))!;
  }
  if (f2sgn0(u) !== f2sgn0(y)) y = f2neg(y);
  return [x, y];
};

// Appendix E.3: 3-isogeny E2' → E2 (係数は低次から)
const ISO = (
  [
    [
      [
        0x5c759507e8e333ebb5b7a9a47d7ed8532c52d39fd3a042a88b58423c50ae15d5c2638e343d9c71c6238aaaaaaaa97d6n,
        0x5c759507e8e333ebb5b7a9a47d7ed8532c52d39fd3a042a88b58423c50ae15d5c2638e343d9c71c6238aaaaaaaa97d6n,
      ],
      [
        0n,
        0x11560bf17baa99bc32126fced787c88f984f87adf7ae0c7f9a208c6b4f20a4181472aaa9cb8d555526a9ffffffffc71an,
      ],
      [
        0x11560bf17baa99bc32126fced787c88f984f87adf7ae0c7f9a208c6b4f20a4181472aaa9cb8d555526a9ffffffffc71en,
        0x8ab05f8bdd54cde190937e76bc3e447cc27c3d6fbd7063fcd104635a790520c0a395554e5c6aaaa9354ffffffffe38dn,
      ],
      [
        0x171d6541fa38ccfaed6dea691f5fb614cb14b4e7f4e810aa22d6108f142b85757098e38d0f671c7188e2aaaaaaaa5ed1n,
        0n,
      ],
    ],
    [
      [
        0n,
        0x1a0111ea397fe69a4b1ba7b6434bacd764774b84f38512bf6730d2a0f6b0f6241eabfffeb153ffffb9feffffffffaa63n,
      ],
      [
        0xcn,
        0x1a0111ea397fe69a4b1ba7b6434bacd764774b84f38512bf6730d2a0f6b0f6241eabfffeb153ffffb9feffffffffaa9fn,
      ],
      [1n, 0n],
    ],
    [
      [
        0x1530477c7ab4113b59a4c18b076d11930f7da5d4a07f649bf54439d87d27e500fc8c25ebf8c92f6812cfc71c71c6d706n,
        0x1530477c7ab4113b59a4c18b076d11930f7da5d4a07f649bf54439d87d27e500fc8c25ebf8c92f6812cfc71c71c6d706n,
      ],
      [
        0n,
        0x5c759507e8e333ebb5b7a9a47d7ed8532c52d39fd3a042a88b58423c50ae15d5c2638e343d9c71c6238aaaaaaaa97ben,
      ],
      [
        0x11560bf17baa99bc32126fced787c88f984f87adf7ae0c7f9a208c6b4f20a4181472aaa9cb8d555526a9ffffffffc71cn,
        0x8ab05f8bdd54cde190937e76bc3e447cc27c3d6fbd7063fcd104635a790520c0a395554e5c6aaaa9354ffffffffe38fn,
      ],
      [
        0x124c9ad43b6cf79bfbf7043de3811ad0761b0f37a1e26286b0e977c69aa274524e79097a56dc4bd9e1b371c71c718b10n,
        0n,
      ],
    ],
    [
      [
        0x1a0111ea397fe69a4b1ba7b6434bacd764774b84f38512bf6730d2a0f6b0f6241eabfffeb153ffffb9feffffffffa8fbn,
        0x1a0111ea397fe69a4b1ba7b6434bacd764774b84f38512bf6730d2a0f6b0f6241eabfffeb153ffffb9feffffffffa8fbn,
      ],
      [
        0n,
        0x1a0111ea397fe69a4b1ba7b6434bacd764774b84f38512bf6730d2a0f6b0f6241eabfffeb153ffffb9feffffffffa9d3n,
      ],
      [
        0x12n,
        0x1a0111ea397fe69a4b1ba7b6434bacd764774b84f38512bf6730d2a0f6b0f6241eabfffeb153ffffb9feffffffffaa99n,
      ],
      [1n, 0n],
    ],
  ] as Fp2[][]
);
const isoMap = (x: Fp2, y: Fp2): Jac<Fp2> => {
  // ホーナー法 (高次から)
  const ev = (k: Fp2[]) =>
    k.reduceRight<Fp2>((acc, c) => f2add(f2mul(acc, x), c), F2_0);
  const [xNum, xDen, yNum, yDen] = ISO.map(ev);
  if (f2isZero(xDen) || f2isZero(yDen)) return E2.inf;
  return [
    f2mul(xNum, f2inv(xDen)),
    f2mul(y, f2mul(yNum, f2inv(yDen))),
    F2_1,
  ];
};

export const hashToG2 = (msg: Uint8Array, dst: Uint8Array): Jac<Fp2> => {
  const [u0, u1] = hashToFieldFp2(msg, dst);
  const q0 = isoMap(...mapToCurveSSWU(u0));
  const q1 = isoMap(...mapToCurveSSWU(u1));
  return E2.mul(E2.add(q0, q1), H_EFF_G2);
};

// ═══ シリアライズ (ZCash 圧縮形式) ═════════════════════════════════
const HALF_P = (P - 1n) / 2n;

const g1ToBytes = (p: Jac<bigint>): Uint8Array => {
  const a = E1.toAffine(p);
  const out = new Uint8Array(48);
  if (!a) {
    out[0] = 0xc0;
    return out;
  }
  out.set(bigToBytes(a[0], 48));
  out[0] |= 0x80;
  if (a[1] > HALF_P) out[0] |= 0x20;
  return out;
};
const g1FromBytes = (b: Uint8Array): Jac<bigint> => {
  if (b.length !== 48) throw new Error("G1 は 48 バイト");
  const flags = b[0];
  if (!(flags & 0x80)) throw new Error("非圧縮形式は未対応");
  const body = b.slice();
  body[0] &= 0x1f;
  const x = bytesToBig(body);
  if (flags & 0x40) {
    if (x !== 0n || flags & 0x20) throw new Error("無限遠点の形式が不正");
    return E1.inf;
  }
  if (x >= P) throw new Error("x が p 以上");
  let y = fpSqrt(m(x * x * x + 4n));
  if (y === null) throw new Error("曲線上にない");
  if (y > HALF_P !== !!(flags & 0x20)) y = P - y;
  const pt: Jac<bigint> = [x, y, 1n];
  if (!E1.inSubgroup(pt)) throw new Error("G1 部分群にない");
  return pt;
};

// Fp2 の「辞書順で大きい」判定: c1 で決まる。c1 = 0 なら c0
const f2lexLarge = (y: Fp2) => (y[1] !== 0n ? y[1] > HALF_P : y[0] > HALF_P);

const g2ToBytes = (p: Jac<Fp2>): Uint8Array => {
  const a = E2.toAffine(p);
  const out = new Uint8Array(96);
  if (!a) {
    out[0] = 0xc0;
    return out;
  }
  out.set(bigToBytes(a[0][1], 48), 0); // c1 が先
  out.set(bigToBytes(a[0][0], 48), 48);
  out[0] |= 0x80;
  if (f2lexLarge(a[1])) out[0] |= 0x20;
  return out;
};
const g2FromBytes = (b: Uint8Array): Jac<Fp2> => {
  if (b.length !== 96) throw new Error("G2 は 96 バイト");
  const flags = b[0];
  if (!(flags & 0x80)) throw new Error("非圧縮形式は未対応");
  const body = b.slice();
  body[0] &= 0x1f;
  const x1 = bytesToBig(body.subarray(0, 48));
  const x0 = bytesToBig(body.subarray(48, 96));
  if (flags & 0x40) {
    if (x0 !== 0n || x1 !== 0n || flags & 0x20)
      throw new Error("無限遠点の形式が不正");
    return E2.inf;
  }
  if (x0 >= P || x1 >= P) throw new Error("x が p 以上");
  const x: Fp2 = [x0, x1];
  let y = f2sqrt(f2add(f2mul(f2sqr(x), x), E2.b));
  if (y === null) throw new Error("曲線上にない");
  if (f2lexLarge(y) !== !!(flags & 0x20)) y = f2neg(y);
  const pt: Jac<Fp2> = [x, y, F2_1];
  if (!E2.inSubgroup(pt)) throw new Error("G2 部分群にない");
  return pt;
};

// ═══ hex ═══════════════════════════════════════════════════════════
export const toHex = (b: Uint8Array): string =>
  Array.from(b, (x) => x.toString(16).padStart(2, "0")).join("");
export const fromHex = (h: string): Uint8Array => {
  h = h.trim().replace(/^0x/i, "");
  if (h.length % 2 !== 0 || /[^0-9a-fA-F]/.test(h))
    throw new Error("hex が不正");
  const out = new Uint8Array(h.length / 2);
  for (let i = 0; i < out.length; i++)
    out[i] = parseInt(h.slice(i * 2, i * 2 + 2), 16);
  return out;
};
type BytesLike = Uint8Array | string;
const bytes = (x: BytesLike) => (typeof x === "string" ? fromHex(x) : x);

// ═══ BLS 署名 本体 ═════════════════════════════════════════════════
export class BLS {
  readonly dst: Uint8Array;
  constructor(readonly dstName: string = DST_NUL) {
    this.dst = new TextEncoder().encode(dstName);
  }

  private skToScalar(sk: BytesLike): bigint {
    const b = bytes(sk);
    if (b.length !== 32) throw new Error("秘密鍵は 32 バイト");
    const s = bytesToBig(b);
    if (s === 0n || s >= R) throw new Error("秘密鍵が範囲外 (1..r-1)");
    return s;
  }

  // 秘密鍵: [1, r-1] の一様乱数 (48 バイト取って mod r で偏りを無視できるレベルに)
  generatePrivateKey(): Uint8Array {
    let s = 0n;
    while (s === 0n) {
      const b = new Uint8Array(48);
      globalThis.crypto.getRandomValues(b);
      s = bytesToBig(b) % R;
    }
    return bigToBytes(s, 32);
  }

  // pk = sk·G1
  getPublicKey(sk: BytesLike): Uint8Array {
    return g1ToBytes(E1.mul(G1, this.skToScalar(sk)));
  }

  generateKeyPair(): { privateKey: string; publicKey: string } {
    const sk = this.generatePrivateKey();
    return { privateKey: toHex(sk), publicKey: toHex(this.getPublicKey(sk)) };
  }

  hashToPoint(msg: Uint8Array): Uint8Array {
    return g2ToBytes(hashToG2(msg, this.dst));
  }

  // σ = sk·H(m)
  sign(msg: Uint8Array, sk: BytesLike): Uint8Array {
    return g2ToBytes(E2.mul(hashToG2(msg, this.dst), this.skToScalar(sk)));
  }

  // e(pk, H(m)) == e(G1, σ)  ⇔  e(-G1, σ)·e(pk, H(m)) == 1
  verify(msg: Uint8Array, pk: BytesLike, sig: BytesLike): boolean {
    try {
      const P1 = g1FromBytes(bytes(pk));
      const S = g2FromBytes(bytes(sig));
      if (E1.isInf(P1)) return false;
      const Hm = hashToG2(msg, this.dst);
      const r = multiPairing([
        [E1.neg(G1), S],
        [P1, Hm],
      ]);
      return f12eq(r, F12_1);
    } catch {
      return false;
    }
  }

  // σ_agg = Σ σ_i
  aggregateSignatures(sigs: BytesLike[]): Uint8Array {
    if (sigs.length === 0) throw new Error("署名が空");
    let acc = E2.inf;
    for (const s of sigs) acc = E2.add(acc, g2FromBytes(bytes(s)));
    return g2ToBytes(acc);
  }

  // pk_agg = Σ pk_i
  aggregatePublicKeys(pks: BytesLike[]): Uint8Array {
    if (pks.length === 0) throw new Error("公開鍵が空");
    let acc = E1.inf;
    for (const p of pks) acc = E1.add(acc, g1FromBytes(bytes(p)));
    return g1ToBytes(acc);
  }

  // 違うメッセージをまとめて検証: e(G1, σ) == Π e(pk_i, H(m_i))
  // (NUL 方式ではメッセージが全部違う必要がある)
  aggregateVerify(msgs: Uint8Array[], pks: BytesLike[], sig: BytesLike): boolean {
    try {
      if (msgs.length === 0 || msgs.length !== pks.length) return false;
      if (this.dstName === DST_NUL) {
        const seen = new Set(msgs.map(toHex));
        if (seen.size !== msgs.length) return false;
      }
      const S = g2FromBytes(bytes(sig));
      const pairs: [Jac<bigint>, Jac<Fp2>][] = [[E1.neg(G1), S]];
      for (let i = 0; i < msgs.length; i++) {
        const Pk = g1FromBytes(bytes(pks[i]));
        if (E1.isInf(Pk)) return false;
        pairs.push([Pk, hashToG2(msgs[i], this.dst)]);
      }
      return f12eq(multiPairing(pairs), F12_1);
    } catch {
      return false;
    }
  }

  // 同じメッセージに全員が署名したもの: pk を足して普通に verify
  // ※ rogue key 攻撃があるので本来は POP (所有証明) とセットで使う
  fastAggregateVerify(msg: Uint8Array, pks: BytesLike[], sig: BytesLike): boolean {
    try {
      return this.verify(msg, this.aggregatePublicKeys(pks), sig);
    } catch {
      return false;
    }
  }
}

// テスト用に中身も出しておく
export const _internal = {
  P,
  R,
  E1,
  E2,
  G1,
  G2,
  pairing,
  multiPairing,
  millerLoop,
  finalExp,
  f12eq,
  f12mul,
  f12pow,
  F12_1,
  g1ToBytes,
  g1FromBytes,
  g2ToBytes,
  g2FromBytes,
  hashToG2,
  HARD_EXP,
};
