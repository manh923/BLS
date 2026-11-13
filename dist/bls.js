// BLS署名 (Boneh–Lynn–Shacham) on BLS12-381  ── ゴリゴリ高速化版
//   - 外部ライブラリなし。bigint だけで全部書く
//   - 方式: min-pk (公開鍵 G1 48byte / 署名 G2 96byte)。Ethereum とかと同じ並び
//   - hash-to-curve: RFC 9380 BLS12381G2_XMD:SHA-256_SSWU_RO_
//   - 圧縮形式: ZCash 形式 (0x80 圧縮 / 0x40 無限遠 / 0x20 y の符号)
//
// 高速化メモ
//   - bigint の % は掛け算の約 2.6 倍重い → 遅延還元 (掛け算は全部やってから最後に1回 %)
//   - 加減算は % を使わず条件付き引き算/足し算
//   - ミラーループ: ヤコビアン座標で逆元なし + 疎な掛け算 (014) + 複数ペアで二乗を共有
//   - 最終冪: hard part を x 乗 5 回に分解 + 円分二乗 (Granger–Scott)
//   - コファクター除去: ψ 自己準同型 (Budroni–Pintore)
//   - 部分群チェック: G1 は σ(P) = -[x²]P、G2 は ψ(P) = [x]P (Scott)
//   - G1 固定基点: ウィンドウ事前計算テーブル
//   - G2 スカラー倍: GLS (ψ で 4 分割 → 64bit スカラー 4 本の同時倍算)
//   - Fp2 の平方根: ノルムを使って Fp の平方根 2〜3 回に落とす
// ─── 定数 ───────────────────────────────────────────────────────────
const P = 0x1a0111ea397fe69a4b1ba7b6434bacd764774b84f38512bf6730d2a0f6b0f6241eabfffeb153ffffb9feffffffffaaabn;
const R = 0x73eda753299d7d483339d80809a1d80553bda402fffe5bfeffffffff00000001n;
// BLS パラメータ x = -0xd201000000010000 (負)。|x| のビット列を使い回す
const X_ABS = 0xd201000000010000n;
const XBITS = X_ABS.toString(2);
// G2 の実効コファクター (テスト用。本体は ψ を使う)
const H_EFF_G2 = 0xbc69f08f2ee75b3584c6a0ea91b352888e2a8e9145ad7689986ff031508ffe1329c2f178731db956d82bf015d1212b02ec0ec69d7477c1ae954cbc06689f6a359894c0adebbf6b4e8020005aaa95551n;
export const DST_NUL = "BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_NUL_";
export const DST_POP = "BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_POP_";
// ═══ Fp ═════════════════════════════════════════════════════════════
// 何でも [0, P) に落とす (負でも 762bit でも OK)
const mod = (a) => {
    a %= P;
    return a < 0n ? a + P : a;
};
const fpAdd = (a, b) => {
    const r = a + b;
    return r >= P ? r - P : r;
};
const fpSub = (a, b) => {
    const r = a - b;
    return r < 0n ? r + P : r;
};
const fpNeg = (a) => (a === 0n ? 0n : P - a);
const fpMul = (a, b) => (a * b) % P; // a, b ∈ [0, P)
const fpInv = (a) => {
    let r0 = P, r1 = mod(a);
    if (r1 === 0n)
        throw new Error("0 の逆元はない");
    let x0 = 0n, x1 = 1n;
    while (r1 !== 0n) {
        const q = r0 / r1;
        [r0, r1] = [r1, r0 - q * r1];
        [x0, x1] = [x1, x0 - q * x1];
    }
    return x0 < 0n ? x0 + P : x0;
};
// 4bit 固定ウィンドウ冪乗 (指数が定数のときに使う)
const fpPow = (b, e) => {
    const tbl = [1n, b];
    for (let i = 2; i < 16; i++)
        tbl.push(fpMul(tbl[i - 1], b));
    let hex = e.toString(16);
    let r = tbl[parseInt(hex[0], 16)];
    for (let i = 1; i < hex.length; i++) {
        r = fpMul(r, r);
        r = fpMul(r, r);
        r = fpMul(r, r);
        r = fpMul(r, r);
        const d = parseInt(hex[i], 16);
        if (d)
            r = fpMul(r, tbl[d]);
    }
    return r;
};
// p ≡ 3 (mod 4) なので √a = a^((p+1)/4)
const SQRT_EXP = (P + 1n) / 4n;
const fpSqrt = (a) => {
    const r = fpPow(a, SQRT_EXP);
    return fpMul(r, r) === a ? r : null;
};
// 平方剰余かどうか (ルジャンドル記号) をヤコビ記号の互除法で。冪乗 (約200µs) の 1/8 くらい
//   1: 平方剰余 / -1: 非剰余 / 0: a ≡ 0
const fpLegendre = (a) => {
    a = mod(a);
    let n = P;
    let t = 1;
    while (a !== 0n) {
        while ((a & 1n) === 0n) {
            a >>= 1n;
            const r = n & 7n;
            if (r === 3n || r === 5n)
                t = -t;
        }
        [a, n] = [n, a];
        if ((a & 3n) === 3n && (n & 3n) === 3n)
            t = -t;
        a %= n;
    }
    return n === 1n ? t : 0;
};
// a^((p-3)/4) = 1/√a (a が平方剰余のとき)。√a と 1/√a が冪乗1回で両方取れる
const INV_SQRT_EXP = (P - 3n) / 4n;
// ═══ Fp2 = Fp[u]/(u²+1) ═════════════════════════════════════════════
// f2xxx: 入出力とも還元済み
// u2xxx: 還元しない (遅延還元用。値は負でも大きくてもいい)
const F2_0 = [0n, 0n];
const F2_1 = [1n, 0n];
const f2add = (a, b) => [fpAdd(a[0], b[0]), fpAdd(a[1], b[1])];
const f2sub = (a, b) => [fpSub(a[0], b[0]), fpSub(a[1], b[1])];
const f2neg = (a) => [fpNeg(a[0]), fpNeg(a[1])];
const f2dbl = (a) => f2add(a, a);
const f2mul = (a, b) => {
    // Karatsuba: 掛け算 3 回、% 2 回
    const t0 = a[0] * b[0];
    const t1 = a[1] * b[1];
    return [mod(t0 - t1), ((a[0] + a[1]) * (b[0] + b[1]) - t0 - t1) % P];
};
const f2sqr = (a) => [
    mod((a[0] + a[1]) * (a[0] - a[1])),
    ((a[0] * a[1]) << 1n) % P,
];
const f2mulFp = (a, k) => [(a[0] * k) % P, (a[1] * k) % P];
const f2conj = (a) => [a[0], fpNeg(a[1])];
const f2inv = (a) => {
    const t = fpInv(a[0] * a[0] + a[1] * a[1]);
    return [fpMul(a[0], t), fpMul(fpNeg(a[1]), t)];
};
const f2eq = (a, b) => a[0] === b[0] && a[1] === b[1];
const f2isZero = (a) => a[0] === 0n && a[1] === 0n;
// ξ = u + 1 を掛ける: (a0 + a1u)(1 + u) = (a0 - a1) + (a0 + a1)u
const f2mulXi = (a) => [fpSub(a[0], a[1]), fpAdd(a[0], a[1])];
const f2pow = (a, e) => {
    let r = F2_1;
    for (const bit of e.toString(2)) {
        r = f2sqr(r);
        if (bit === "1")
            r = f2mul(r, a);
    }
    return r;
};
// √(a0 + a1u): ノルム n = a0² + a1² の平方根 s を取って
//   t = (a0 ± s)/2,  x0 = √t,  x1 = a1 / (2x0)
// 失敗する冪乗をしないように、剰余かどうかは先にルジャンドル記号で判定する
//   非剰余なら判定 1 回 (約25µs) で終わり。剰余なら 冪乗 2 回 + 判定 2 回
// さらに y = t^((p-3)/4) = 1/x0 なので x0 = t·y、x1 = a1·y/2 で逆元もいらない
const INV2 = (P + 1n) / 2n;
const f2sqrt = (a) => {
    const [a0, a1] = a;
    if (a1 === 0n) {
        const s = fpSqrt(a0);
        if (s !== null)
            return [s, 0n];
        const t = fpSqrt(fpNeg(a0)); // (t·u)² = -t²
        return t === null ? null : [0n, t];
    }
    const n = (a0 * a0 + a1 * a1) % P;
    if (fpLegendre(n) !== 1)
        return null; // ノルムが非剰余 ⇔ a が非剰余
    const s = fpPow(n, SQRT_EXP);
    // (a0+s)/2 と (a0-s)/2 の積は -a1²/4 (非剰余) なので、どちらか片方だけが剰余
    let t = fpMul(fpAdd(a0, s), INV2);
    if (fpLegendre(t) !== 1)
        t = fpMul(fpSub(a0, s), INV2);
    const y = fpPow(t, INV_SQRT_EXP);
    const x0 = fpMul(t, y);
    if (fpMul(x0, x0) !== t)
        return null; // 念のため
    return [x0, fpMul(fpMul(a1, y), INV2)];
};
// RFC 9380 sgn0 (m = 2)
const f2sgn0 = (a) => {
    const sign0 = Number(a[0] & 1n);
    const zero0 = a[0] === 0n ? 1 : 0;
    const sign1 = Number(a[1] & 1n);
    return sign0 | (zero0 & sign1);
};
const u2mul = (a, b) => {
    const t0 = a[0] * b[0];
    const t1 = a[1] * b[1];
    return [t0 - t1, (a[0] + a[1]) * (b[0] + b[1]) - t0 - t1];
};
const u2sqr = (a) => [(a[0] + a[1]) * (a[0] - a[1]), (a[0] * a[1]) << 1n];
const u2add = (a, b) => [a[0] + b[0], a[1] + b[1]];
const u2sub = (a, b) => [a[0] - b[0], a[1] - b[1]];
const u2xi = (a) => [a[0] - a[1], a[0] + a[1]];
const r2 = (a) => [mod(a[0]), mod(a[1])];
// ═══ Fp6 = Fp2[v]/(v³-ξ) ════════════════════════════════════════════
const F6_0 = [F2_0, F2_0, F2_0];
const F6_1 = [F2_1, F2_0, F2_0];
const u6add = (a, b) => [
    u2add(a[0], b[0]),
    u2add(a[1], b[1]),
    u2add(a[2], b[2]),
];
const u6sub = (a, b) => [
    u2sub(a[0], b[0]),
    u2sub(a[1], b[1]),
    u2sub(a[2], b[2]),
];
const r6 = (a) => [r2(a[0]), r2(a[1]), r2(a[2])];
const f6neg = (a) => [f2neg(a[0]), f2neg(a[1]), f2neg(a[2])];
// v を掛ける: (b0, b1, b2)·v = (ξ·b2, b0, b1)  (還元済みでも未還元でも使える)
const f6mulV = (a) => [u2xi(a[2]), a[0], a[1]];
// Karatsuba (Fp2 掛け算 6 回)。出力は未還元
const f6mulU = (a, b) => {
    const t0 = u2mul(a[0], b[0]);
    const t1 = u2mul(a[1], b[1]);
    const t2 = u2mul(a[2], b[2]);
    return [
        u2add(t0, u2xi(u2sub(u2sub(u2mul(u2add(a[1], a[2]), u2add(b[1], b[2])), t1), t2))),
        u2add(u2sub(u2sub(u2mul(u2add(a[0], a[1]), u2add(b[0], b[1])), t0), t1), u2xi(t2)),
        u2add(u2sub(u2sub(u2mul(u2add(a[0], a[2]), u2add(b[0], b[2])), t0), t2), t1),
    ];
};
const f6mul = (a, b) => r6(f6mulU(a, b));
// a·(b0 + b1·v)  Fp2 掛け算 5 回
const mulBy01U = (a, b0, b1) => {
    const t0 = u2mul(a[0], b0);
    const t1 = u2mul(a[1], b1);
    return [
        u2add(t0, u2xi(u2mul(a[2], b1))),
        u2sub(u2sub(u2mul(u2add(a[0], a[1]), u2add(b0, b1)), t0), t1),
        u2add(u2mul(a[2], b0), t1),
    ];
};
// a·(b1·v)  Fp2 掛け算 3 回
const mulBy1U = (a, b1) => [
    u2xi(u2mul(a[2], b1)),
    u2mul(a[0], b1),
    u2mul(a[1], b1),
];
const f6inv = (a) => {
    const [a0, a1, a2] = a;
    const c0 = f2sub(f2sqr(a0), f2mulXi(f2mul(a1, a2)));
    const c1 = f2sub(f2mulXi(f2sqr(a2)), f2mul(a0, a1));
    const c2 = f2sub(f2sqr(a1), f2mul(a0, a2));
    const t = f2inv(f2add(f2mul(a0, c0), f2mulXi(f2add(f2mul(a2, c1), f2mul(a1, c2)))));
    return [f2mul(c0, t), f2mul(c1, t), f2mul(c2, t)];
};
// ═══ Fp12 = Fp6[w]/(w²-v) ═══════════════════════════════════════════
const F12_1 = [F6_1, F6_0];
// Karatsuba: Fp6 掛け算 3 回。% は最後に 12 回だけ
const f12mul = (a, b) => {
    const t0 = f6mulU(a[0], b[0]);
    const t1 = f6mulU(a[1], b[1]);
    const t2 = f6mulU(u6add(a[0], a[1]), u6add(b[0], b[1]));
    return [r6(u6add(t0, f6mulV(t1))), r6(u6sub(u6sub(t2, t0), t1))];
};
// (a0 + a1w)² = a0² + v·a1² + 2a0a1·w
//   a0² + v·a1² = (a0 + a1)(a0 + v·a1) - a0a1 - v·a0a1
const f12sqr = (a) => {
    const ab = f6mulU(a[0], a[1]);
    const t = f6mulU(u6add(a[0], a[1]), u6add(a[0], f6mulV(a[1])));
    return [r6(u6sub(u6sub(t, ab), f6mulV(ab))), r6(u6add(ab, ab))];
};
// f · (c0 + c1·v + c4·v·w)  直線の値は3か所しか埋まってないのでそこだけ掛ける
const f12mul014 = (f, c0, c1, c4) => {
    const t0 = mulBy01U(f[0], c0, c1);
    const t1 = mulBy1U(f[1], c4);
    const t2 = mulBy01U(u6add(f[0], f[1]), c0, u2add(c1, c4));
    return [r6(u6add(t0, f6mulV(t1))), r6(u6sub(u6sub(t2, t0), t1))];
};
const f12conj = (a) => [a[0], f6neg(a[1])];
const f12inv = (a) => {
    const t = f6inv(r6(u6sub(f6mulU(a[0], a[0]), f6mulV(f6mulU(a[1], a[1])))));
    return [f6mul(a[0], t), f6neg(f6mul(a[1], t))];
};
const f12eq = (a, b) => a.every((c, i) => c.every((d, j) => f2eq(d, b[i][j])));
// 汎用の冪乗 (テスト用)
const f12pow = (a, e) => {
    let r = F12_1;
    for (const bit of e.toString(2)) {
        r = f12sqr(r);
        if (bit === "1")
            r = f12mul(r, a);
    }
    return r;
};
// 円分部分群専用の二乗 (Granger–Scott)
//   Fp12 を Fp4 × 3 と見て、Fp4 の二乗 3 回で済ませる (Fp2 の二乗 9 回)
const fp4sqU = (a, b) => {
    const A = u2sqr(a);
    const B = u2sqr(b);
    return [u2add(A, u2xi(B)), u2sub(u2sub(u2sqr(u2add(a, b)), A), B)];
};
// 3t - 2z / 3t + 2z を1回の % で
const m3m2 = (t, z) => [
    mod(3n * t[0] - 2n * z[0]),
    mod(3n * t[1] - 2n * z[1]),
];
const m3p2 = (t, z) => [
    mod(3n * t[0] + 2n * z[0]),
    mod(3n * t[1] + 2n * z[1]),
];
const cycSqr = (f) => {
    const z0 = f[0][0], z4 = f[0][1], z3 = f[0][2], z2 = f[1][0], z1 = f[1][1], z5 = f[1][2];
    const [A0, A1] = fp4sqU(z0, z1);
    const [B0, B1] = fp4sqU(z2, z3);
    const [C0, C1] = fp4sqU(z4, z5);
    return [
        [m3m2(A0, z0), m3m2(B0, z4), m3m2(C0, z3)],
        [m3p2(u2xi(C1), z2), m3p2(A1, z1), m3p2(B1, z5)],
    ];
};
// フロベニウス写像 a ↦ a^(p^k)
//   Fp12 の元を Σ a_i·w^i (i = 0..5, a_i ∈ Fp2) と見ると
//   (a_i·w^i)^(p^k) = conj^k(a_i) · ξ^(i(p^k-1)/6) · w^i
//   この ξ^(...) を起動時に計算しておく (ハードコード不要)
// w^i の位置: i=0→c0[0], 1→c1[0], 2→c0[1], 3→c1[1], 4→c0[2], 5→c1[2]
const XI = [1n, 1n];
const FROB = [1, 2, 3].map((k) => {
    const g = f2pow(XI, (P ** BigInt(k) - 1n) / 6n);
    const out = [F2_1];
    for (let i = 1; i < 6; i++)
        out.push(f2mul(out[i - 1], g));
    return out;
});
const f12frob = (a, k) => {
    const g = FROB[k - 1];
    const c = (x) => (k % 2 === 1 ? f2conj(x) : x);
    return [
        [c(a[0][0]), f2mul(c(a[0][1]), g[2]), f2mul(c(a[0][2]), g[4])],
        [f2mul(c(a[1][0]), g[1]), f2mul(c(a[1][1]), g[3]), f2mul(c(a[1][2]), g[5])],
    ];
};
const FP = {
    add: fpAdd,
    sub: fpSub,
    mul: fpMul,
    sqr: (a) => (a * a) % P,
    neg: fpNeg,
    inv: fpInv,
    isZero: (a) => a === 0n,
    eq: (a, b) => a === b,
    zero: 0n,
    one: 1n,
};
const FP2 = {
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
class Curve {
    F;
    b;
    constructor(F, b) {
        this.F = F;
        this.b = b;
    }
    get inf() {
        return [this.F.one, this.F.one, this.F.zero];
    }
    isInf(p) {
        return this.F.isZero(p[2]);
    }
    // dbl-2009-l (a = 0)  1M + 5S
    dbl(p) {
        const F = this.F;
        const [X, Y, Z] = p;
        if (F.isZero(Z))
            return p;
        const A = F.sqr(X);
        const B = F.sqr(Y);
        const C = F.sqr(B);
        let D = F.sub(F.sub(F.sqr(F.add(X, B)), A), C);
        D = F.add(D, D);
        const E = F.add(F.add(A, A), A);
        const X3 = F.sub(F.sqr(E), F.add(D, D));
        let C8 = F.add(C, C);
        C8 = F.add(C8, C8);
        C8 = F.add(C8, C8);
        const Y3 = F.sub(F.mul(E, F.sub(D, X3)), C8);
        const YZ = F.mul(Y, Z);
        return [X3, Y3, F.add(YZ, YZ)];
    }
    // add-2007-bl  11M + 5S  (q が Z=1 なら madd に回す)
    add(p, q) {
        const F = this.F;
        if (this.isInf(p))
            return q;
        if (this.isInf(q))
            return p;
        if (F.eq(q[2], F.one))
            return this.madd(p, q[0], q[1]);
        if (F.eq(p[2], F.one))
            return this.madd(q, p[0], p[1]);
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
        if (F.isZero(H))
            return F.isZero(rr) ? this.dbl(p) : this.inf;
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
    // madd-2007-bl (q はアフィン)  7M + 4S
    madd(p, x2, y2) {
        const F = this.F;
        if (this.isInf(p))
            return [x2, y2, F.one];
        const [X1, Y1, Z1] = p;
        const Z1Z1 = F.sqr(Z1);
        const U2 = F.mul(x2, Z1Z1);
        const S2 = F.mul(F.mul(y2, Z1), Z1Z1);
        const H = F.sub(U2, X1);
        const rr = F.sub(S2, Y1);
        if (F.isZero(H))
            return F.isZero(rr) ? this.dbl(p) : this.inf;
        const HH = F.sqr(H);
        let I = F.add(HH, HH);
        I = F.add(I, I);
        const J = F.mul(H, I);
        const r2 = F.add(rr, rr);
        const V = F.mul(X1, I);
        const X3 = F.sub(F.sub(F.sqr(r2), J), F.add(V, V));
        const Y1J = F.mul(Y1, J);
        const Y3 = F.sub(F.mul(r2, F.sub(V, X3)), F.add(Y1J, Y1J));
        const Z3 = F.sub(F.sub(F.sqr(F.add(Z1, H)), Z1Z1), HH);
        return [X3, Y3, Z3];
    }
    neg(p) {
        return [p[0], this.F.neg(p[1]), p[2]];
    }
    // 素朴な double-and-add (テストと初期化用)
    mul(p, k) {
        if (k < 0n)
            return this.mul(this.neg(p), -k);
        let r = this.inf;
        for (const bit of k.toString(2)) {
            r = this.dbl(r);
            if (bit === "1")
                r = this.add(r, p);
        }
        return r;
    }
    // [|x|]P  (|x| は 1 が 6 個しかない)
    mulAbsX(p) {
        let r = p;
        for (let i = 1; i < XBITS.length; i++) {
            r = this.dbl(r);
            if (XBITS[i] === "1")
                r = this.add(r, p);
        }
        return r;
    }
    // [x]P (x < 0)
    mulX(p) {
        return this.neg(this.mulAbsX(p));
    }
    toAffine(p) {
        const F = this.F;
        if (this.isInf(p))
            return null;
        const zi = F.inv(p[2]);
        const zi2 = F.sqr(zi);
        return [F.mul(p[0], zi2), F.mul(F.mul(p[1], zi2), zi)];
    }
    // まとめてアフィンに (逆元 1 回: Montgomery のトリック)
    toAffineBatch(ps) {
        const F = this.F;
        const n = ps.length;
        if (n === 0)
            return [];
        const acc = new Array(n);
        acc[0] = ps[0][2];
        for (let i = 1; i < n; i++)
            acc[i] = F.mul(acc[i - 1], ps[i][2]);
        let inv = F.inv(acc[n - 1]);
        const out = new Array(n);
        for (let i = n - 1; i >= 0; i--) {
            const zi = i > 0 ? F.mul(inv, acc[i - 1]) : inv;
            inv = F.mul(inv, ps[i][2]);
            const zi2 = F.sqr(zi);
            out[i] = [F.mul(ps[i][0], zi2), F.mul(F.mul(ps[i][1], zi2), zi)];
        }
        return out;
    }
    // 逆元なしで比較: X1·Z2² == X2·Z1² && Y1·Z2³ == Y2·Z1³
    eq(p, q) {
        const F = this.F;
        const ip = this.isInf(p), iq = this.isInf(q);
        if (ip || iq)
            return ip && iq;
        const z1z1 = F.sqr(p[2]);
        const z2z2 = F.sqr(q[2]);
        return (F.eq(F.mul(p[0], z2z2), F.mul(q[0], z1z1)) &&
            F.eq(F.mul(F.mul(p[1], z2z2), q[2]), F.mul(F.mul(q[1], z1z1), p[2])));
    }
    isOnCurve(a) {
        if (!a)
            return true;
        const F = this.F;
        const [x, y] = a;
        return F.eq(F.sqr(y), F.add(F.mul(F.sqr(x), x), this.b));
    }
    // r 倍して無限遠になるか (素朴版。テスト用)
    inSubgroupSlow(p) {
        return this.isInf(this.mul(p, R));
    }
}
// E1: y² = x³ + 4 over Fp
const E1 = new Curve(FP, 4n);
// E2: y² = x³ + 4(u+1) over Fp2 (twist)
const E2 = new Curve(FP2, [4n, 4n]);
const G1 = [
    0x17f1d3a73197d7942695638c4fa9ac0fc3688c4f9774b905a14e3a3f171bac586c55e83ff97a1aeffb3af00adb22c6bbn,
    0x08b3f481e3aaa0f1a09e30ed741d8ae4fcf5e095d5d00af600db18cb2c04b3edd03cc744a2888ae40caa232946c5e7e1n,
    1n,
];
const G2 = [
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
const NEG_G1_AFF = [G1[0], fpNeg(G1[1])];
// ─── 自己準同型 ─────────────────────────────────────────────────────
// ψ = twist ∘ Frobenius ∘ untwist  (G2 上では [x] 倍と同じ)
//   ψ(x, y) = (conj(x)·ξ^(-(p-1)/3), conj(y)·ξ^(-(p-1)/2))
const PSI_X = f2inv(f2pow(XI, (P - 1n) / 3n));
const PSI_Y = f2inv(f2pow(XI, (P - 1n) / 2n));
const psi = (p) => [
    f2mul(f2conj(p[0]), PSI_X),
    f2mul(f2conj(p[1]), PSI_Y),
    f2conj(p[2]),
];
// σ(x, y) = (β·x, y)  β は 1 の原始 3 乗根。G1 上では [-x²] 倍になる方を選ぶ
const BETA = (() => {
    let g = 2n;
    let b = 1n;
    while (b === 1n)
        b = fpPow(g++, (P - 1n) / 3n);
    const minusX2G1 = E1.neg(E1.mulAbsX(E1.mulAbsX(G1)));
    for (const cand of [b, fpMul(b, b)])
        if (E1.eq([fpMul(G1[0], cand), G1[1], 1n], minusX2G1))
            return cand;
    throw new Error("β が見つからない");
})();
// 部分群チェック (Scott 2021)
const g1InSubgroup = (p) => E1.eq([fpMul(p[0], BETA), p[1], p[2]], E1.neg(E1.mulAbsX(E1.mulAbsX(p))));
const g2InSubgroup = (p) => E2.eq(psi(p), E2.mulX(p));
// ─── G1 固定基点スカラー倍 (ウィンドウ事前計算) ───────────────────
//   k = Σ d_i·2^(W·i) と分けて、表 T[i][d] = d·2^(W·i)·G1 を足すだけ
//   倍算ゼロ、加算 (255/W) 回
const G1_W = 8;
let G1_TABLE = null;
const g1Table = () => {
    if (G1_TABLE)
        return G1_TABLE;
    const rows = Math.ceil(255 / G1_W);
    const size = 1 << G1_W;
    const flat = [];
    let base = G1;
    for (let i = 0; i < rows; i++) {
        const bAff = E1.toAffine(base);
        let acc = [bAff[0], bAff[1], 1n];
        flat.push(acc);
        for (let d = 2; d < size; d++) {
            acc = E1.madd(acc, bAff[0], bAff[1]);
            flat.push(acc);
        }
        for (let j = 0; j < G1_W; j++)
            base = E1.dbl(base);
    }
    const aff = E1.toAffineBatch(flat);
    G1_TABLE = [];
    for (let i = 0; i < rows; i++)
        G1_TABLE.push(aff.slice(i * (size - 1), (i + 1) * (size - 1)));
    return G1_TABLE;
};
const g1MulBase = (k) => {
    const T = g1Table();
    const mask = BigInt((1 << G1_W) - 1);
    let r = E1.inf;
    for (let i = 0; k > 0n; i++, k >>= BigInt(G1_W)) {
        const d = Number(k & mask);
        if (d)
            r = E1.madd(r, T[i][d - 1][0], T[i][d - 1][1]);
    }
    return r;
};
// ─── G2 スカラー倍 (GLS) ───────────────────────────────────────────
//   φ = -ψ は G2 上で [|x|] 倍。r < |x|⁴ なので
//   k = k0 + k1|x| + k2|x|² + k3|x|³ (各 64bit) に分けて
//   [k]Q = k0·Q + k1·φ(Q) + k2·φ²(Q) + k3·φ³(Q) を同時に計算 (倍算 64 回)
//   ※ G2 部分群の点にしか使えない
const g2MulGLS = (q, k) => {
    k %= R;
    if (k < 0n)
        k += R;
    if (k === 0n || E2.isInf(q))
        return E2.inf;
    const ks = [];
    for (let i = 0; i < 4; i++) {
        ks.push(k % X_ABS);
        k /= X_ABS;
    }
    const phi = (p) => E2.neg(psi(p));
    const base = [q];
    for (let i = 1; i < 4; i++)
        base.push(phi(base[i - 1]));
    // 16 通りの部分和を作ってアフィンに揃える
    const sums = [E2.inf];
    for (let m = 1; m < 16; m++) {
        const low = m & -m;
        sums.push(E2.add(sums[m ^ low], base[31 - Math.clz32(low)]));
    }
    const nz = sums.slice(1).map((p, i) => [p, i + 1]).filter(([p]) => !E2.isInf(p));
    const aff = E2.toAffineBatch(nz.map(([p]) => p));
    const tbl = new Array(16).fill(null);
    nz.forEach(([, m], i) => (tbl[m] = aff[i]));
    let r = E2.inf;
    for (let bit = 63; bit >= 0; bit--) {
        r = E2.dbl(r);
        const b = BigInt(bit);
        const idx = Number((ks[0] >> b) & 1n) |
            (Number((ks[1] >> b) & 1n) << 1) |
            (Number((ks[2] >> b) & 1n) << 2) |
            (Number((ks[3] >> b) & 1n) << 3);
        const t = tbl[idx];
        if (t)
            r = E2.madd(r, t[0], t[1]);
    }
    return r;
};
const millerLoop = (pairs) => {
    const n = pairs.length;
    const T = pairs.map(([, q]) => [q[0], q[1], F2_1]);
    let f = F12_1;
    for (let i = 1; i < XBITS.length; i++) {
        if (i > 1)
            f = f12sqr(f); // 二乗は全ペアで共有
        for (let j = 0; j < n; j++) {
            const [xP, yP] = pairs[j][0];
            const [X, Y, Z] = T[j];
            const XX = f2sqr(X);
            const YY = f2sqr(Y);
            const ZZ = f2sqr(Z);
            const C = f2sqr(YY);
            const E = f2add(f2add(XX, XX), XX);
            const D = f2dbl(f2sub(f2sub(f2sqr(f2add(X, YY)), XX), C));
            const X3 = f2sub(f2sqr(E), f2dbl(D));
            const Y3 = f2sub(f2mul(E, f2sub(D, X3)), f2dbl(f2dbl(f2dbl(C))));
            const Z3 = f2dbl(f2mul(Y, Z));
            T[j] = [X3, Y3, Z3];
            f = f12mul014(f, f2sub(f2mul(E, X), f2dbl(YY)), f2mulFp(f2neg(f2mul(E, ZZ)), xP), f2mulFp(f2mul(Z3, ZZ), yP));
        }
        if (XBITS[i] === "1") {
            for (let j = 0; j < n; j++) {
                const [xP, yP] = pairs[j][0];
                const [xQ, yQ] = pairs[j][1];
                const [X, Y, Z] = T[j];
                const ZZ = f2sqr(Z);
                const U2 = f2mul(xQ, ZZ);
                const S2 = f2mul(f2mul(yQ, Z), ZZ);
                const H = f2sub(U2, X);
                const HH = f2sqr(H);
                const I = f2dbl(f2dbl(HH));
                const J = f2mul(H, I);
                const rr = f2dbl(f2sub(S2, Y));
                const V = f2mul(X, I);
                const X3 = f2sub(f2sub(f2sqr(rr), J), f2dbl(V));
                const Y3 = f2sub(f2mul(rr, f2sub(V, X3)), f2dbl(f2mul(Y, J)));
                const Z3 = f2sub(f2sub(f2sqr(f2add(Z, H)), ZZ), HH);
                T[j] = [X3, Y3, Z3];
                f = f12mul014(f, f2sub(f2mul(rr, xQ), f2mul(yQ, Z3)), f2mulFp(f2neg(rr), xP), f2mulFp(Z3, yP));
            }
        }
    }
    // x < 0 なので共役を取る
    return f12conj(f);
};
const cycCompress = (f) => [f[0][1], f[0][2], f[1][0], f[1][2]];
const cycSqrC = (c) => {
    const [g1, g2, g3, g5] = c;
    const [B0, B1] = fp4sqU(g3, g2); // g3² + ξg2²,  2g3g2
    const [C0, C1] = fp4sqU(g1, g5); // g1² + ξg5²,  2g1g5
    return [m3m2(B0, g1), m3m2(C0, g2), m3p2(u2xi(C1), g3), m3p2(B1, g5)];
};
// 復元: g4 = (ξg5² + 3g1² - 2g2) / (4g3)   (g3 = 0 のときは g4 = 2g1g5 / g2)
//       g0 = ξ(2g4² + g3g5 - 3g1g2) + 1
// 分母の逆元はまとめて 1 回で (Montgomery のトリック)
const cycDecompressBatch = (cs) => {
    const nums = [];
    const dens = [];
    for (const [g1, g2, g3, g5] of cs) {
        if (!f2isZero(g3)) {
            const g1s = u2sqr(g1);
            nums.push(r2(u2sub(u2add(u2xi(u2sqr(g5)), u2add(u2add(g1s, g1s), g1s)), u2add(g2, g2))));
            dens.push(f2dbl(f2dbl(g3)));
        }
        else {
            nums.push(f2dbl(f2mul(g1, g5)));
            dens.push(g2);
        }
    }
    // まとめて逆元 (分母が 0 のものは 0 扱い: 単位元など)
    const n = dens.length;
    const acc = new Array(n);
    let prod = F2_1;
    for (let i = 0; i < n; i++) {
        acc[i] = prod;
        if (!f2isZero(dens[i]))
            prod = f2mul(prod, dens[i]);
    }
    let inv = f2inv(prod);
    const invs = new Array(n);
    for (let i = n - 1; i >= 0; i--) {
        if (f2isZero(dens[i])) {
            invs[i] = F2_0;
            continue;
        }
        invs[i] = f2mul(inv, acc[i]);
        inv = f2mul(inv, dens[i]);
    }
    return cs.map(([g1, g2, g3, g5], i) => {
        const g4 = f2mul(nums[i], invs[i]);
        const g4s = u2sqr(g4);
        const g12 = u2mul(g1, g2);
        const inner = u2sub(u2add(u2add(g4s, g4s), u2mul(g3, g5)), u2add(u2add(g12, g12), g12));
        const g0 = r2(u2add(u2xi(inner), [1n, 0n]));
        return [
            [g0, g1, g2],
            [g3, g4, g5],
        ];
    });
};
// f^x (x < 0)。円分部分群の元に限る
//   f^|x| = Π f^(2^k) (|x| の立っているビット k について)
//   f を圧縮したまま 63 回二乗して、必要な 6 個だけまとめて復元して掛ける
const XBITS_SET = [];
for (let k = 0; k < 64; k++)
    if ((X_ABS >> BigInt(k)) & 1n)
        XBITS_SET.push(k);
const cycExp = (f) => {
    let c = cycCompress(f);
    let k = 0;
    const picks = [];
    for (const pos of XBITS_SET) {
        while (k < pos) {
            c = cycSqrC(c);
            k++;
        }
        picks.push(c);
    }
    const fs = cycDecompressBatch(picks);
    let r = fs[0];
    for (let i = 1; i < fs.length; i++)
        r = f12mul(r, fs[i]);
    return f12conj(r);
};
// 比較用: 圧縮しない版
const cycExpGS = (f) => {
    let r = f;
    for (let i = 1; i < XBITS.length; i++) {
        r = cycSqr(r);
        if (XBITS[i] === "1")
            r = f12mul(r, f);
    }
    return f12conj(r);
};
// 最終冪 f^(3(p¹²-1)/r)
//   easy: (p⁶-1)(p²+1)
//   hard: 3(p⁴-p²+1)/r = λ0 + λ1·p + λ2·p² + λ3·p³
//         λ3 = (x-1)², λ2 = λ3·x, λ1 = λ2·x - λ3, λ0 = λ1·x + 3
//   (3 倍してあるけど r と互いに素なのでペアリングとしては問題なし)
const finalExp = (f) => {
    let t = f12mul(f12conj(f), f12inv(f)); // f^(p⁶-1)
    t = f12mul(f12frob(t, 2), t); // ^(p²+1)  ここから円分部分群
    const a = f12mul(cycExp(t), f12conj(t)); // t^(x-1)
    const A3 = f12mul(cycExp(a), f12conj(a)); // t^λ3
    const A2 = cycExp(A3); // t^λ2
    const A1 = f12mul(cycExp(A2), f12conj(A3)); // t^λ1
    const A0 = f12mul(f12mul(cycExp(A1), cycSqr(t)), t); // t^λ0
    return f12mul(f12mul(A0, f12frob(A1, 1)), f12mul(f12frob(A2, 2), f12frob(A3, 3)));
};
const toPairs = (pairs) => {
    const out = [];
    for (const [p, q] of pairs) {
        const a = E1.toAffine(p);
        const b = E2.toAffine(q);
        if (a && b)
            out.push([a, b]); // 無限遠を含むペアは 1
    }
    return out;
};
const pairing = (p, q) => finalExp(millerLoop(toPairs([[p, q]])));
// Π e(P_i, Q_i)  ミラーループの二乗と最終冪を共有
const multiPairing = (pairs) => finalExp(millerLoop(toPairs(pairs)));
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
const SHA_W = new Uint32Array(64);
export const sha256 = (msg) => {
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
    const W = SHA_W;
    const rotr = (x, n) => (x >>> n) | (x << (32 - n));
    for (let off = 0; off < total; off += 64) {
        for (let i = 0; i < 16; i++)
            W[i] = dv.getUint32(off + i * 4);
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
    for (let i = 0; i < 8; i++)
        ov.setUint32(i * 4, H[i]);
    return out;
};
// ═══ hash-to-curve (RFC 9380) ═══════════════════════════════════════
const concat = (...arrs) => {
    const out = new Uint8Array(arrs.reduce((s, a) => s + a.length, 0));
    let o = 0;
    for (const a of arrs) {
        out.set(a, o);
        o += a.length;
    }
    return out;
};
const i2osp = (v, len) => {
    const out = new Uint8Array(len);
    for (let i = len - 1; i >= 0; i--) {
        out[i] = v & 0xff;
        v >>>= 8;
    }
    return out;
};
const bytesToBig = (b) => {
    let r = 0n;
    for (const x of b)
        r = (r << 8n) | BigInt(x);
    return r;
};
const bigToBytes = (n, len) => {
    const out = new Uint8Array(len);
    for (let i = len - 1; i >= 0; i--) {
        out[i] = Number(n & 0xffn);
        n >>= 8n;
    }
    return out;
};
// 5.3.1 expand_message_xmd (SHA-256: b_in_bytes = 32, s_in_bytes = 64)
export const expandMessageXmd = (msg, dst, lenInBytes) => {
    const ell = Math.ceil(lenInBytes / 32);
    if (ell > 255 || lenInBytes > 65535 || dst.length > 255)
        throw new Error("expand_message_xmd: 長すぎ");
    const dstPrime = concat(dst, i2osp(dst.length, 1));
    const b0 = sha256(concat(new Uint8Array(64), msg, i2osp(lenInBytes, 2), i2osp(0, 1), dstPrime));
    const bs = [sha256(concat(b0, i2osp(1, 1), dstPrime))];
    for (let i = 2; i <= ell; i++) {
        const prev = bs[bs.length - 1];
        const x = new Uint8Array(32);
        for (let j = 0; j < 32; j++)
            x[j] = b0[j] ^ prev[j];
        bs.push(sha256(concat(x, i2osp(i, 1), dstPrime)));
    }
    return concat(...bs).slice(0, lenInBytes);
};
// 5.2 hash_to_field (Fp2, count = 2, L = 64)
const hashToFieldFp2 = (msg, dst) => {
    const L = 64;
    const bytes = expandMessageXmd(msg, dst, 2 * 2 * L);
    const e = (k) => bytesToBig(bytes.subarray(k * L, (k + 1) * L)) % P;
    return [
        [e(0), e(1)],
        [e(2), e(3)],
    ];
};
// 6.6.2 Simplified SWU on E2': y² = x³ + A'x + B'
const SSWU_A = [0n, 240n];
const SSWU_B = [1012n, 1012n];
const SSWU_Z = [P - 2n, P - 1n];
const SSWU_MB_A = f2mul(f2neg(SSWU_B), f2inv(SSWU_A)); // -B/A
const SSWU_B_ZA = f2mul(SSWU_B, f2inv(f2mul(SSWU_Z, SSWU_A))); // B/(ZA)
const sswuG = (x) => f2add(f2mul(f2add(f2sqr(x), SSWU_A), x), SSWU_B); // x³ + Ax + B
const mapToCurveSSWU = (u) => {
    const zu2 = f2mul(SSWU_Z, f2sqr(u));
    const den = f2add(f2sqr(zu2), zu2); // Z²u⁴ + Zu²
    const x1 = f2isZero(den)
        ? SSWU_B_ZA
        : f2mul(SSWU_MB_A, f2add(F2_1, f2inv(den)));
    // gx1 が平方剰余なら x1、ダメなら x2 = Zu²·x1 (どっちかは必ず剰余)
    let x = x1;
    let y = f2sqrt(sswuG(x1));
    if (y === null) {
        x = f2mul(zu2, x1);
        y = f2sqrt(sswuG(x));
    }
    if (f2sgn0(u) !== f2sgn0(y))
        y = f2neg(y);
    return [x, y];
};
// Appendix E.3: 3-isogeny E2' → E2 (係数は低次から)
const ISO = [
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
];
// 結果を分数のままヤコビアンに入れて逆元を消す
//   Z = xD·yD,  X = xN·xD·yD²,  Y = y·yN·xD³·yD²
const isoMap = (x, y) => {
    const ev = (k) => k.reduceRight((acc, c) => f2add(f2mul(acc, x), c), F2_0);
    const [xN, xD, yN, yD] = ISO.map(ev);
    if (f2isZero(xD) || f2isZero(yD))
        return E2.inf;
    const Z = f2mul(xD, yD);
    const yD2 = f2sqr(yD);
    const xD2 = f2sqr(xD);
    return [
        f2mul(f2mul(xN, xD), yD2),
        f2mul(f2mul(f2mul(y, yN), f2mul(xD2, xD)), yD2),
        Z,
    ];
};
// RFC 9380 G.3 (Budroni–Pintore): h_eff 倍を ψ と [x] 倍 2 回で
const clearCofactorG2 = (p) => {
    const t1 = E2.mulX(p);
    let t2 = psi(p);
    let t3 = psi(psi(E2.dbl(p)));
    t3 = E2.add(t3, E2.neg(t2));
    t2 = E2.mulX(E2.add(t1, t2));
    t3 = E2.add(t3, t2);
    t3 = E2.add(t3, E2.neg(t1));
    return E2.add(t3, E2.neg(p));
};
export const hashToG2 = (msg, dst) => {
    const [u0, u1] = hashToFieldFp2(msg, dst);
    const q0 = isoMap(...mapToCurveSSWU(u0));
    const q1 = isoMap(...mapToCurveSSWU(u1));
    return clearCofactorG2(E2.add(q0, q1));
};
// ═══ シリアライズ (ZCash 圧縮形式) ═════════════════════════════════
const HALF_P = (P - 1n) / 2n;
const g1ToBytes = (p) => {
    const a = E1.toAffine(p);
    const out = new Uint8Array(48);
    if (!a) {
        out[0] = 0xc0;
        return out;
    }
    out.set(bigToBytes(a[0], 48));
    out[0] |= 0x80;
    if (a[1] > HALF_P)
        out[0] |= 0x20;
    return out;
};
const g1FromBytes = (b) => {
    if (b.length !== 48)
        throw new Error("G1 は 48 バイト");
    const flags = b[0];
    if (!(flags & 0x80))
        throw new Error("非圧縮形式は未対応");
    const body = b.slice();
    body[0] &= 0x1f;
    const x = bytesToBig(body);
    if (flags & 0x40) {
        if (x !== 0n || flags & 0x20)
            throw new Error("無限遠点の形式が不正");
        return E1.inf;
    }
    if (x >= P)
        throw new Error("x が p 以上");
    let y = fpSqrt(mod(x * x * x + 4n));
    if (y === null)
        throw new Error("曲線上にない");
    if (y > HALF_P !== !!(flags & 0x20))
        y = P - y;
    const pt = [x, y, 1n];
    if (!g1InSubgroup(pt))
        throw new Error("G1 部分群にない");
    return pt;
};
// Fp2 の「辞書順で大きい」判定: c1 で決まる。c1 = 0 なら c0
const f2lexLarge = (y) => (y[1] !== 0n ? y[1] > HALF_P : y[0] > HALF_P);
const g2ToBytes = (p) => {
    const a = E2.toAffine(p);
    const out = new Uint8Array(96);
    if (!a) {
        out[0] = 0xc0;
        return out;
    }
    out.set(bigToBytes(a[0][1], 48), 0); // c1 が先
    out.set(bigToBytes(a[0][0], 48), 48);
    out[0] |= 0x80;
    if (f2lexLarge(a[1]))
        out[0] |= 0x20;
    return out;
};
const g2FromBytes = (b) => {
    if (b.length !== 96)
        throw new Error("G2 は 96 バイト");
    const flags = b[0];
    if (!(flags & 0x80))
        throw new Error("非圧縮形式は未対応");
    const body = b.slice();
    body[0] &= 0x1f;
    const x1 = bytesToBig(body.subarray(0, 48));
    const x0 = bytesToBig(body.subarray(48, 96));
    if (flags & 0x40) {
        if (x0 !== 0n || x1 !== 0n || flags & 0x20)
            throw new Error("無限遠点の形式が不正");
        return E2.inf;
    }
    if (x0 >= P || x1 >= P)
        throw new Error("x が p 以上");
    const x = [x0, x1];
    let y = f2sqrt(f2add(f2mul(f2sqr(x), x), E2.b));
    if (y === null)
        throw new Error("曲線上にない");
    if (f2lexLarge(y) !== !!(flags & 0x20))
        y = f2neg(y);
    const pt = [x, y, F2_1];
    if (!g2InSubgroup(pt))
        throw new Error("G2 部分群にない");
    return pt;
};
// ═══ hex ═══════════════════════════════════════════════════════════
export const toHex = (b) => Array.from(b, (x) => x.toString(16).padStart(2, "0")).join("");
export const fromHex = (h) => {
    h = h.trim().replace(/^0x/i, "");
    if (h.length % 2 !== 0 || /[^0-9a-fA-F]/.test(h))
        throw new Error("hex が不正");
    const out = new Uint8Array(h.length / 2);
    for (let i = 0; i < out.length; i++)
        out[i] = parseInt(h.slice(i * 2, i * 2 + 2), 16);
    return out;
};
const bytes = (x) => (typeof x === "string" ? fromHex(x) : x);
// ─── 公開鍵のキャッシュ ───────────────────────────────────────────────
// 公開鍵の復元 (平方根 + 部分群チェック) は約1ms。同じ公開鍵は何度も来るので、
// チェックに通った点だけ覚えておく (古いものから捨てる)
const PK_CACHE = new Map();
let PK_CACHE_MAX = 4096;
export const setPublicKeyCacheSize = (n) => {
    PK_CACHE_MAX = n;
    while (PK_CACHE.size > n)
        PK_CACHE.delete(PK_CACHE.keys().next().value);
};
const g1FromBytesCached = (b) => {
    if (PK_CACHE_MAX <= 0)
        return g1FromBytes(b);
    const key = toHex(b);
    const hit = PK_CACHE.get(key);
    if (hit)
        return hit;
    const pt = g1FromBytes(b);
    PK_CACHE.set(key, pt);
    if (PK_CACHE.size > PK_CACHE_MAX)
        PK_CACHE.delete(PK_CACHE.keys().next().value);
    return pt;
};
// バッチ検証用の 64bit の乱数 (0 以外)
const randScalar64 = () => {
    const b = new Uint8Array(8);
    let r = 0n;
    while (r === 0n) {
        globalThis.crypto.getRandomValues(b);
        r = bytesToBig(b);
    }
    return r;
};
// Σ k_i·P_i を、2倍算を全員で共有してまとめて計算 (Straus / Shamir のトリック)
//   2倍算は (最大のビット数) 回だけ。P_i は Z=1 (アフィン) なら madd になる
const msm = (C, ps, ks) => {
    let bits = 0;
    for (const k of ks)
        bits = Math.max(bits, k.toString(2).length);
    let r = C.inf;
    for (let b = bits - 1; b >= 0; b--) {
        r = C.dbl(r);
        const bb = BigInt(b);
        for (let i = 0; i < ps.length; i++)
            if ((ks[i] >> bb) & 1n)
                r = C.add(r, ps[i]);
    }
    return r;
};
// ═══ BLS 署名 本体 ═════════════════════════════════════════════════
export class BLS {
    dstName;
    dst;
    // 直前の呼び出しの内訳 (ms)。cryptos の _prof と同じノリ
    prof = {};
    constructor(dstName = DST_NUL) {
        this.dstName = dstName;
        this.dst = new TextEncoder().encode(dstName);
    }
    step(name, fn) {
        const t = performance.now();
        const r = fn();
        this.prof[name] = (this.prof[name] ?? 0) + performance.now() - t;
        return r;
    }
    skToScalar(sk) {
        const b = bytes(sk);
        if (b.length !== 32)
            throw new Error("秘密鍵は 32 バイト");
        const s = bytesToBig(b);
        if (s === 0n || s >= R)
            throw new Error("秘密鍵が範囲外 (1..r-1)");
        return s;
    }
    // 秘密鍵: [1, r-1] の一様乱数 (48 バイト取って mod r で偏りを無視できるレベルに)
    generatePrivateKey() {
        let s = 0n;
        while (s === 0n) {
            const b = new Uint8Array(48);
            globalThis.crypto.getRandomValues(b);
            s = bytesToBig(b) % R;
        }
        return bigToBytes(s, 32);
    }
    // pk = sk·G1
    getPublicKey(sk) {
        this.prof = {};
        const k = this.skToScalar(sk);
        const pt = this.step("sk·G1 (固定基点テーブル)", () => g1MulBase(k));
        return this.step("圧縮 (G1)", () => g1ToBytes(pt));
    }
    generateKeyPair() {
        const sk = this.generatePrivateKey();
        return { privateKey: toHex(sk), publicKey: toHex(this.getPublicKey(sk)) };
    }
    hashToPoint(msg) {
        return g2ToBytes(hashToG2(msg, this.dst));
    }
    // σ = sk·H(m)
    sign(msg, sk) {
        this.prof = {};
        const k = this.skToScalar(sk);
        const Hm = this.step("H(m) hash-to-G2", () => hashToG2(msg, this.dst));
        const S = this.step("sk·H(m) (GLS)", () => g2MulGLS(Hm, k));
        return this.step("圧縮 (G2)", () => g2ToBytes(S));
    }
    // e(pk, H(m)) == e(G1, σ)  ⇔  e(-G1, σ)·e(pk, H(m)) == 1
    verify(msg, pk, sig) {
        this.prof = {};
        try {
            const P1 = this.step("公開鍵の復元+部分群チェック (G1)", () => g1FromBytesCached(bytes(pk)));
            const S = this.step("署名の復元+部分群チェック (G2)", () => g2FromBytes(bytes(sig)));
            if (E1.isInf(P1))
                return false;
            const Hm = this.step("H(m) hash-to-G2", () => hashToG2(msg, this.dst));
            const pairs = [[E1.toAffine(P1), E2.toAffine(Hm)]];
            const Sa = E2.toAffine(S);
            if (Sa)
                pairs.push([NEG_G1_AFF, Sa]);
            const f = this.step("ミラーループ (2ペア)", () => millerLoop(pairs));
            const e = this.step("最終冪", () => finalExp(f));
            return f12eq(e, F12_1);
        }
        catch {
            return false;
        }
    }
    // σ_agg = Σ σ_i
    aggregateSignatures(sigs) {
        this.prof = {};
        if (sigs.length === 0)
            throw new Error("署名が空");
        let acc = E2.inf;
        for (const s of sigs) {
            const pt = this.step("署名の復元+部分群チェック (G2)", () => g2FromBytes(bytes(s)));
            acc = this.step("G2 加算", () => E2.add(acc, pt));
        }
        return this.step("圧縮 (G2)", () => g2ToBytes(acc));
    }
    // pk_agg = Σ pk_i
    aggregatePublicKeys(pks) {
        this.prof = {};
        if (pks.length === 0)
            throw new Error("公開鍵が空");
        let acc = E1.inf;
        for (const p of pks) {
            const pt = this.step("公開鍵の復元+部分群チェック (G1)", () => g1FromBytesCached(bytes(p)));
            acc = this.step("G1 加算", () => E1.add(acc, pt));
        }
        return this.step("圧縮 (G1)", () => g1ToBytes(acc));
    }
    // 違うメッセージをまとめて検証: e(G1, σ) == Π e(pk_i, H(m_i))
    // (NUL 方式ではメッセージが全部違う必要がある)
    aggregateVerify(msgs, pks, sig) {
        this.prof = {};
        try {
            if (msgs.length === 0 || msgs.length !== pks.length)
                return false;
            if (this.dstName === DST_NUL) {
                const seen = new Set(msgs.map(toHex));
                if (seen.size !== msgs.length)
                    return false;
            }
            const S = this.step("署名の復元+部分群チェック (G2)", () => g2FromBytes(bytes(sig)));
            const pairs = [[E1.neg(G1), S]];
            for (let i = 0; i < msgs.length; i++) {
                const Pk = this.step("公開鍵の復元+部分群チェック (G1)", () => g1FromBytesCached(bytes(pks[i])));
                if (E1.isInf(Pk))
                    return false;
                pairs.push([Pk, this.step("H(m) hash-to-G2", () => hashToG2(msgs[i], this.dst))]);
            }
            const f = this.step(`ミラーループ (${pairs.length}ペア)`, () => millerLoop(toPairs(pairs)));
            const e = this.step("最終冪", () => finalExp(f));
            return f12eq(e, F12_1);
        }
        catch {
            return false;
        }
    }
    // 同じメッセージに全員が署名したもの: pk を足して普通に verify
    // ※ rogue key 攻撃があるので本来は POP (所有証明) とセットで使う
    fastAggregateVerify(msg, pks, sig) {
        try {
            const t = performance.now();
            const apk = this.aggregatePublicKeys(pks);
            const aggMs = performance.now() - t;
            const ok = this.verify(msg, apk, sig);
            this.prof = { [`公開鍵の集約 (${pks.length}個)`]: aggMs, ...this.prof };
            return ok;
        }
        catch {
            return false;
        }
    }
    // 別々の署名をまとめて検証 (バッチ検証)
    //   ランダムな 64bit の係数 r_i を掛けて
    //     e(-G1, Σ r_i·σ_i) · Π e(r_i·pk_i, H(m_i)) == 1
    //   をミラーループ1回 (二乗を共有) + 最終冪1回で確かめる
    //   1つでも不正な署名が混ざっていれば、確率 1 - 2^-64 で false
    //   (どれが不正かは分からないので、false なら1個ずつ verify し直す)
    verifyBatch(items) {
        this.prof = {};
        try {
            if (items.length === 0)
                return false;
            const rs = items.map(() => randScalar64());
            const rPks = [];
            const Hs = [];
            const sigs = [];
            for (const it of items) {
                const pk = this.step("公開鍵の復元+部分群チェック (G1)", () => g1FromBytesCached(bytes(it.pk)));
                if (E1.isInf(pk))
                    return false;
                sigs.push(this.step("署名の復元+部分群チェック (G2)", () => g2FromBytes(bytes(it.sig))));
                Hs.push(this.step("H(m) hash-to-G2", () => hashToG2(it.msg, this.dst)));
                rPks.push(pk);
            }
            const P = this.step("r_i·pk_i (64bit)", () => rPks.map((p, i) => E1.mul(p, rs[i])));
            const S = this.step("Σ r_i·σ_i (同時倍算)", () => msm(E2, sigs, rs));
            const pairs = this.step("アフィンにまとめて変換", () => {
                const pa = E1.toAffineBatch(P);
                const qa = E2.toAffineBatch(E2.isInf(S) ? Hs : [...Hs, S]);
                const out = pa.map((p, i) => [p, qa[i]]);
                if (!E2.isInf(S))
                    out.push([NEG_G1_AFF, qa[Hs.length]]);
                return out;
            });
            const f = this.step(`ミラーループ (${pairs.length}ペア)`, () => millerLoop(pairs));
            return f12eq(this.step("最終冪", () => finalExp(f)), F12_1);
        }
        catch {
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
    H_EFF_G2,
    pairing,
    multiPairing,
    millerLoop,
    finalExp,
    f12eq,
    f12mul,
    f12sqr,
    f12pow,
    f12conj,
    f12inv,
    f12frob,
    cycSqr,
    cycExp,
    cycExpGS,
    fpLegendre,
    F12_1,
    g1ToBytes,
    g1FromBytes,
    g2ToBytes,
    g2FromBytes,
    g1InSubgroup,
    g2InSubgroup,
    g1FromBytesCached,
    msm,
    toPairs,
    NEG_G1_AFF,
    randScalar64,
    g1MulBase,
    g2MulGLS,
    clearCofactorG2,
    hashToG2,
    isoMap,
    mapToCurveSSWU,
    f2sqrt,
    f2sqr,
    psi,
    HARD_EXP: (P ** 4n - P ** 2n + 1n) / R,
};
