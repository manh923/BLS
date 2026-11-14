// 格子署名のおもちゃ ── 「格子署名をどこまで小さくできるか」の研究ごっこ用
//   ML-DSA-44 (FIPS 204) と同じ格子: R_q = Z_q[X]/(X^256 + 1), q = 8380417, (k, l) = (4, 4), η = 2, τ = 39
//   縮める技を 1 段ずつ足した版 V0〜V4 を並べて、署名と公開鍵のサイズを比べる
//   ※ おもちゃ: 定数時間ではない、ガウス分布のサンプリングは浮動小数点、ハッシュは SHA-256 で代用
import { sha256 } from "./bls.js";

export const Q = 8380417;
export const N = 256;
const ZETA = 1753; // 1 の原始 512 乗根 (mod q)

// ─── 数の計算 (q < 2^23 なので積は 2^46 未満、number で正確に計算できる) ──
const mod = (a: number) => {
  a %= Q;
  return a < 0 ? a + Q : a;
};
const mulmod = (a: number, b: number) => (a * b) % Q;
const powmod = (b: number, e: number) => {
  let r = 1;
  b = mod(b);
  while (e > 0) {
    if (e & 1) r = mulmod(r, b);
    b = mulmod(b, b);
    e = Math.floor(e / 2);
  }
  return r;
};
// 中心化: [0, q) → (-(q-1)/2, (q-1)/2]
const centered = (a: number) => (a > (Q - 1) / 2 ? a - Q : a);

// ─── 多項式と NTT ───────────────────────────────────────────────────
export type Poly = Int32Array; // 係数 256 個、[0, q)
const zero = () => new Int32Array(N);
const brv8 = (k: number) => {
  let r = 0;
  for (let i = 0; i < 8; i++) r |= ((k >> i) & 1) << (7 - i);
  return r;
};
const ZETAS = Array.from({ length: 256 }, (_, k) => powmod(ZETA, brv8(k)));
const N_INV = 8347681; // 256⁻¹ mod q

// FIPS 204 Algorithm 41
export const ntt = (a: Poly): Poly => {
  const w = Int32Array.from(a);
  let m = 0;
  for (let len = 128; len >= 1; len >>= 1) {
    for (let start = 0; start < N; start += 2 * len) {
      const z = ZETAS[++m];
      for (let j = start; j < start + len; j++) {
        const t = mulmod(z, w[j + len]);
        w[j + len] = mod(w[j] - t);
        w[j] = mod(w[j] + t);
      }
    }
  }
  return w;
};
// FIPS 204 Algorithm 42
export const invNtt = (a: Poly): Poly => {
  const w = Int32Array.from(a);
  let m = 256;
  for (let len = 1; len < N; len <<= 1) {
    for (let start = 0; start < N; start += 2 * len) {
      const z = Q - ZETAS[--m];
      for (let j = start; j < start + len; j++) {
        const t = w[j];
        w[j] = mod(t + w[j + len]);
        w[j + len] = mulmod(z, mod(t - w[j + len]));
      }
    }
  }
  for (let j = 0; j < N; j++) w[j] = mulmod(w[j], N_INV);
  return w;
};
const pmul = (a: Poly, b: Poly) => a.map((x, i) => mulmod(x, b[i])) as Poly; // NTT 領域で掛け算
const padd = (a: Poly, b: Poly) => a.map((x, i) => mod(x + b[i])) as Poly;
const psub = (a: Poly, b: Poly) => a.map((x, i) => mod(x - b[i])) as Poly;
// テスト用: X^256 = -1 の素朴な掛け算
export const schoolbookMul = (a: Poly, b: Poly): Poly => {
  const r = new Array(N).fill(0);
  for (let i = 0; i < N; i++)
    for (let j = 0; j < N; j++) {
      const p = mulmod(a[i], b[j]);
      if (i + j < N) r[i + j] = mod(r[i + j] + p);
      else r[i + j - N] = mod(r[i + j - N] - p);
    }
  return Int32Array.from(r);
};
type Vec = Poly[];
const vadd = (a: Vec, b: Vec) => a.map((p, i) => padd(p, b[i]));
const vsub = (a: Vec, b: Vec) => a.map((p, i) => psub(p, b[i]));
const vntt = (a: Vec) => a.map(ntt);
const vinv = (a: Vec) => a.map(invNtt);
// Â · v̂ (NTT 領域) → 普通の領域
const matVec = (A: Vec[], v: Vec): Vec =>
  A.map((row) => invNtt(row.reduce((acc, a, j) => padd(acc, pmul(a, v[j])), zero())));
const infNorm = (v: Vec) => {
  let m = 0;
  for (const p of v) for (const x of p) m = Math.max(m, Math.abs(centered(x)));
  return m;
};
const l2sq = (v: Vec) => {
  let s = 0;
  for (const p of v) for (const x of p) s += centered(x) ** 2;
  return s;
};

// ─── ハッシュ (SHA-256 のカウンタモードで XOF の代わり) ──────────────────
const concat = (...a: Uint8Array[]) => {
  const out = new Uint8Array(a.reduce((s, x) => s + x.length, 0));
  let o = 0;
  for (const x of a) {
    out.set(x, o);
    o += x.length;
  }
  return out;
};
const H = (...a: Uint8Array[]) => sha256(concat(...a));
class Xof {
  private buf: Uint8Array = new Uint8Array(0);
  private pos = 0;
  private ctr = 0;
  constructor(private seed: Uint8Array) {}
  byte(): number {
    if (this.pos >= this.buf.length) {
      const c = new Uint8Array(4);
      new DataView(c.buffer).setUint32(0, this.ctr++);
      this.buf = H(this.seed, c);
      this.pos = 0;
    }
    return this.buf[this.pos++];
  }
}
const polyBytes = (v: Vec) => concat(...v.map((p) => new Uint8Array(p.buffer.slice(0))));

// A を種から作る (NTT 領域の値として直接サンプル)
const expandA = (rho: Uint8Array, k: number, l: number): Vec[] =>
  Array.from({ length: k }, (_, i) =>
    Array.from({ length: l }, (_, j) => {
      const x = new Xof(concat(rho, Uint8Array.of(j, i)));
      const p = zero();
      for (let n = 0; n < N; ) {
        const v = x.byte() | (x.byte() << 8) | ((x.byte() & 0x7f) << 16);
        if (v < Q) p[n++] = v;
      }
      return p;
    }),
  );
// 秘密: 係数を [-η, η] から一様に (4bit のニブルで棄却サンプリング)
const sampleEta = (seed: Uint8Array, idx: number, eta: number): Poly => {
  const x = new Xof(concat(seed, Uint8Array.of(idx)));
  const p = zero();
  const m = 2 * eta + 1;
  const lim = 15 - (15 % m); // 0..lim-1 を m で割った余りは一様
  for (let n = 0; n < N; ) {
    const b = x.byte();
    for (const nib of [b & 15, b >> 4]) if (nib < lim && n < N) p[n++] = mod(eta - (nib % m));
  }
  return p;
};
// チャレンジ c: ±1 が τ 個 (FIPS 204 SampleInBall)
const sampleInBall = (seed: Uint8Array, tau: number): Poly => {
  const x = new Xof(seed);
  let signs = 0n;
  for (let i = 0; i < 8; i++) signs |= BigInt(x.byte()) << BigInt(8 * i);
  const c = zero();
  for (let i = N - tau; i < N; i++) {
    let j: number;
    do j = x.byte();
    while (j > i);
    c[i] = c[j];
    c[j] = signs & 1n ? Q - 1 : 1;
    signs >>= 1n;
  }
  return c;
};

// ─── 乱数 ───────────────────────────────────────────────────────────
const randBytes = (n: number) => globalThis.crypto.getRandomValues(new Uint8Array(n));
// [0, 1) の一様乱数 (暗号用の乱数から)
const rand01 = () => globalThis.crypto.getRandomValues(new Uint32Array(1))[0] / 4294967296;
// [-γ1+1, γ1] の一様分布 (γ1 = 2^17)
const sampleUniformY = (gamma1: number): Poly => {
  const r = globalThis.crypto.getRandomValues(new Uint32Array(N));
  const bits = Math.log2(gamma1) + 1;
  return Int32Array.from(r, (x) => mod(gamma1 - (x & ((1 << bits) - 1))));
};
// 平均 0・標準偏差 σ のガウス分布を丸めたもの (Box–Muller。おもちゃ)
const sampleGaussY = (sigma: number): Poly => {
  const r = globalThis.crypto.getRandomValues(new Uint32Array(N + 2));
  const p = zero();
  for (let i = 0; i < N; i += 2) {
    const u1 = (r[i] + 1) / 4294967297;
    const u2 = r[i + 1] / 4294967296;
    const rad = Math.sqrt(-2 * Math.log(u1));
    p[i] = mod(Math.round(sigma * rad * Math.cos(2 * Math.PI * u2)));
    p[i + 1] = mod(Math.round(sigma * rad * Math.sin(2 * Math.PI * u2)));
  }
  return p;
};

// ─── 丸め (FIPS 204) ────────────────────────────────────────────────
const modPm = (r: number, a: number) => {
  let x = r % a;
  if (x > a / 2) x -= a;
  return x;
};
const decompose = (r: number, g2: number): [number, number] => {
  const rp = mod(r);
  let r0 = modPm(rp, 2 * g2);
  if (rp - r0 === Q - 1) return [0, r0 - 1];
  return [(rp - r0) / (2 * g2), r0];
};
const highBits = (v: Vec, g2: number) => v.map((p) => p.map((x) => decompose(x, g2)[0]) as Poly);
const lowBits = (v: Vec, g2: number) => v.map((p) => p.map((x) => mod(decompose(x, g2)[1])) as Poly);
const power2Round = (v: Vec, d: number): [Vec, Vec] => {
  const t1 = v.map((p) => p.map((x) => (x - modPm(x, 1 << d)) >> d) as Poly);
  const t0 = v.map((p) => p.map((x) => mod(modPm(x, 1 << d))) as Poly);
  return [t1, t0];
};
const makeHint = (z: Vec, r: Vec, g2: number) => {
  const a = highBits(r, g2);
  const b = highBits(vadd(r, z), g2);
  return a.map((p, i) => p.map((x, j) => (x !== b[i][j] ? 1 : 0)) as Poly);
};
const useHint = (h: Vec, r: Vec, g2: number) => {
  const m = (Q - 1) / (2 * g2);
  return r.map((p, i) =>
    p.map((x, j) => {
      const [r1, r0] = decompose(x, g2);
      if (!h[i][j]) return r1;
      return r0 > 0 ? (r1 + 1) % m : (r1 - 1 + m) % m;
    }) as Poly,
  );
};

// ─── ビット単位の書き込み・読み出し ──────────────────────────────────
class BitWriter {
  private bytes: number[] = [];
  private acc = 0;
  private n = 0;
  write(v: number, bits: number) {
    for (let i = 0; i < bits; i++) {
      this.acc |= ((v >>> i) & 1) << this.n;
      if (++this.n === 8) {
        this.bytes.push(this.acc);
        this.acc = 0;
        this.n = 0;
      }
    }
  }
  bytesOut() {
    return Uint8Array.from(this.n ? [...this.bytes, this.acc] : this.bytes);
  }
}
class BitReader {
  private pos = 0;
  constructor(private b: Uint8Array) {}
  read(bits: number) {
    let v = 0;
    for (let i = 0; i < bits; i++) {
      const byte = this.b[this.pos >> 3];
      if (byte === undefined) throw new Error("署名が短い");
      v |= ((byte >> (this.pos & 7)) & 1) << i;
      this.pos++;
    }
    return v >>> 0;
  }
  get bitPos() {
    return this.pos;
  }
}
// 一様な z: γ1 - z を (log2 γ1 + 1) bit で
const packUniform = (w: BitWriter, v: Vec, gamma1: number) => {
  const bits = Math.log2(gamma1) + 1;
  for (const p of v) for (const x of p) w.write(gamma1 - centered(x), bits);
};
const unpackUniform = (r: BitReader, n: number, gamma1: number): Vec => {
  const bits = Math.log2(gamma1) + 1;
  return Array.from({ length: n }, () => {
    const p = zero();
    for (let i = 0; i < N; i++) p[i] = mod(gamma1 - r.read(bits));
    return p;
  });
};
// 山型の z: ライス符号 (符号 1bit + 下位 L bit + 上位を 1 の連続で)
const packRice = (w: BitWriter, v: Vec, L: number) => {
  for (const p of v)
    for (const x of p) {
      const c = centered(x);
      const a = Math.abs(c);
      w.write(c < 0 ? 1 : 0, 1);
      w.write(a & ((1 << L) - 1), L);
      for (let i = 0; i < a >> L; i++) w.write(1, 1);
      w.write(0, 1);
    }
};
const unpackRice = (r: BitReader, n: number, L: number): Vec =>
  Array.from({ length: n }, () => {
    const p = zero();
    for (let i = 0; i < N; i++) {
      const s = r.read(1);
      let a = r.read(L);
      let hi = 0;
      while (r.read(1)) if (++hi > 64) throw new Error("署名が壊れている");
      a += hi << L;
      if (s && a === 0) throw new Error("署名が壊れている (-0)");
      p[i] = mod(s ? -a : a);
    }
    return p;
  });
// ヒント (FIPS 204 HintBitPack: ω + k バイト)
const packHint = (h: Vec, omega: number): Uint8Array => {
  const out = new Uint8Array(omega + h.length);
  let idx = 0;
  h.forEach((p, i) => {
    p.forEach((x, j) => {
      if (x) out[idx++] = j;
    });
    out[omega + i] = idx;
  });
  return out;
};
const unpackHint = (b: Uint8Array, k: number, omega: number): Vec | null => {
  const h = Array.from({ length: k }, zero);
  let idx = 0;
  for (let i = 0; i < k; i++) {
    const end = b[omega + i];
    if (end < idx || end > omega) return null;
    for (let first = idx; idx < end; idx++) {
      if (idx > first && b[idx - 1] >= b[idx]) return null; // 昇順で一意
      h[i][b[idx]] = 1;
    }
  }
  for (let i = idx; i < omega; i++) if (b[i]) return null;
  return h;
};

// ヒントの圧縮版: 1 の個数 (7bit) と、1 の位置の差をゴロム符号 (下位 4bit + 上位を 1 の連続) で
//   位置は k 本の多項式をつなげた 0〜k·256-1 で数える
const packHintGolomb = (w: BitWriter, h: Vec) => {
  const pos: number[] = [];
  h.forEach((p, i) => p.forEach((x, j) => x && pos.push(i * N + j)));
  w.write(pos.length, 7);
  let prev = -1;
  for (const q of pos) {
    const g = q - prev - 1;
    w.write(g & 15, 4);
    for (let i = 0; i < g >> 4; i++) w.write(1, 1);
    w.write(0, 1);
    prev = q;
  }
};
const unpackHintGolomb = (r: BitReader, k: number, omega: number): Vec | null => {
  const cnt = r.read(7);
  if (cnt > omega) return null;
  const h = Array.from({ length: k }, zero);
  let prev = -1;
  for (let i = 0; i < cnt; i++) {
    let g = r.read(4);
    let hi = 0;
    while (r.read(1)) if (++hi > k * 16) return null;
    g += hi << 4;
    const q = prev + 1 + g;
    if (q >= k * N) return null;
    h[Math.floor(q / N)][q % N] = 1;
    prev = q;
  }
  return h;
};

// ═══ 署名の各版 ═══════════════════════════════════════════════════
export interface Params {
  id: string;
  name: string;
  desc: string;
  k: number;
  l: number;
  eta: number;
  tau: number;
  gamma1: number;
  gamma2: number;
  omega: number;
  d: number;
  // 0: [A|I] で z1, z2 を両方送る / 1: Bai–Galbraith (z2 を送らない) / 2: + 公開鍵の下位ビットを捨ててヒント
  mode: 0 | 1 | 2;
  // ガウス分布版: σ = α·T (T は ‖c·s1‖ の上限。超えたら作り直し)
  gauss?: { alpha: number; T: number };
  // ヒントを位置の差のゴロム符号で送る (ω + k バイト固定の代わり)
  hintGolomb?: boolean;
}
const base = { k: 4, l: 4, tau: 39, gamma1: 1 << 17, gamma2: (Q - 1) / 88, omega: 80, d: 13 };
export const VARIANTS: Params[] = [
  { ...base, id: "V0", name: "V0 素", desc: "[A|I]·(z1, z2) をそのまま送る", eta: 2, mode: 0 },
  { ...base, id: "V1", name: "V1 Bai–Galbraith", desc: "HighBits だけハッシュして z2 を送らない", eta: 2, mode: 1 },
  { ...base, id: "V2", name: "V2 公開鍵の下位ビットを捨てる", desc: "t の下位 13bit を捨ててヒントで補う (= ML-DSA-44 の形)", eta: 2, mode: 2 },
  { ...base, id: "V3", name: "V3 山型の z + ライス符号", desc: "y をガウス分布にして z を圧縮 (前に話したハフマンの発想)", eta: 2, mode: 2, gauss: { alpha: 11, T: 420 } },
  { ...base, id: "V4", name: "V4 秘密を 0/±1 に", desc: "V3 の秘密を η = 1 にして ‖c·s1‖ を小さく", eta: 1, mode: 2, gauss: { alpha: 11, T: 260 } },
  { ...base, id: "V5", name: "V5 T を詰めてヒントも圧縮", desc: "‖c·s1‖ の上限 T を実測の最大 (約178) まで詰めて、ヒントの位置をゴロム符号で", eta: 1, mode: 2, gauss: { alpha: 11, T: 180 }, hintGolomb: true },
  { ...base, id: "V6", name: "V6 α を 4 に", desc: "V5 の σ = α·T をさらに小さく (やり直しが増える)", eta: 1, mode: 2, gauss: { alpha: 4, T: 180 }, hintGolomb: true },
  { ...base, id: "V7", name: "V7 α を 3 に", desc: "V6 よりさらに小さく (やり直しがもっと増える)", eta: 1, mode: 2, gauss: { alpha: 3, T: 180 }, hintGolomb: true },
];

export interface SecretKey {
  P: Params;
  pk: Uint8Array;
  tr: Uint8Array;
  Ahat: Vec[];
  s1: Vec;
  s2: Vec;
  s1hat: Vec;
  s2hat: Vec;
  t0hat: Vec;
}

const beta = (P: Params) => P.tau * P.eta;
const sigmaOf = (P: Params) => P.gauss!.alpha * P.gauss!.T;
const riceL = (P: Params) => Math.floor(Math.log2(sigmaOf(P)));
const l2Bound = (P: Params) => 1.2 * sigmaOf(P) * Math.sqrt(P.l * N);

// 公開鍵: ρ (32B) + t (23bit × k·256) か t1 (10bit × k·256)
const encodePk = (P: Params, rho: Uint8Array, t: Vec) => {
  const w = new BitWriter();
  const bits = P.mode === 2 ? 23 - P.d : 23;
  for (const p of t) for (const x of p) w.write(x, bits);
  return concat(rho, w.bytesOut());
};
const decodePk = (P: Params, pk: Uint8Array) => {
  const r = new BitReader(pk.subarray(32));
  const bits = P.mode === 2 ? 23 - P.d : 23;
  const t = Array.from({ length: P.k }, () => {
    const p = zero();
    for (let i = 0; i < N; i++) p[i] = r.read(bits);
    return p;
  });
  return { rho: pk.subarray(0, 32), t };
};

export const keygen = (P: Params): { pk: Uint8Array; sk: SecretKey } => {
  const rho = randBytes(32);
  const seed = randBytes(32);
  const Ahat = expandA(rho, P.k, P.l);
  const s1 = Array.from({ length: P.l }, (_, i) => sampleEta(seed, i, P.eta));
  const s2 = Array.from({ length: P.k }, (_, i) => sampleEta(seed, P.l + i, P.eta));
  const s1hat = vntt(s1);
  const t = vadd(matVec(Ahat, s1hat), s2);
  let pkT = t;
  let t0hat: Vec = [];
  if (P.mode === 2) {
    const [t1, t0] = power2Round(t, P.d);
    pkT = t1;
    t0hat = vntt(t0);
  }
  const pk = encodePk(P, rho, pkT);
  return { pk, sk: { P, pk, tr: H(pk), Ahat, s1, s2, s1hat, s2hat: vntt(s2), t0hat } };
};

// 直前の署名で何回やり直したか
export let lastAttempts = 0;

export const sign = (sk: SecretKey, msg: Uint8Array): Uint8Array => {
  const P = sk.P;
  const B = beta(P);
  const mu = H(sk.tr, msg);
  for (let attempt = 1; attempt <= 10000; attempt++) {
    const y = Array.from({ length: P.l }, () => (P.gauss ? sampleGaussY(sigmaOf(P)) : sampleUniformY(P.gamma1)));
    const y2 = P.mode === 0 ? Array.from({ length: P.k }, () => sampleUniformY(P.gamma1)) : [];
    let w = matVec(sk.Ahat, vntt(y));
    if (P.mode === 0) w = vadd(w, y2);
    const ch = H(mu, polyBytes(P.mode === 0 ? w : highBits(w, P.gamma2)));
    const chat = ntt(sampleInBall(ch, P.tau));
    const cs1 = vinv(sk.s1hat.map((s) => pmul(chat, s)));
    const cs2 = vinv(sk.s2hat.map((s) => pmul(chat, s)));
    const z = vadd(y, cs1);

    if (P.gauss) {
      // ガウス分布の棄却サンプリング: z が c·s1 を含まない分布に見えるように確率的に捨てる
      const v2 = l2sq(cs1);
      if (Math.sqrt(v2) > P.gauss.T) continue; // 上限 T を超える c·s1 は作り直し
      let dot = 0;
      for (let i = 0; i < P.l; i++) for (let j = 0; j < N; j++) dot += centered(z[i][j]) * centered(cs1[i][j]);
      const s2v = sigmaOf(P) ** 2;
      const a = P.gauss.alpha;
      const M = Math.exp(12 / a + 1 / (2 * a * a));
      const accept = Math.exp((-2 * dot + v2) / (2 * s2v)) / M;
      if (rand01() >= accept) continue;
      if (Math.sqrt(l2sq(z)) > l2Bound(P)) continue;
    } else if (infNorm(z) >= P.gamma1 - B) continue;

    const wr = new BitWriter();
    if (P.mode === 0) {
      const z2 = vadd(y2, cs2);
      if (infNorm(z2) >= P.gamma1 - B) continue;
      packUniform(wr, z, P.gamma1);
      packUniform(wr, z2, P.gamma1);
      lastAttempts = attempt;
      return concat(ch, wr.bytesOut());
    }
    // Bai–Galbraith: w - c·s2 の下位ビットが小さければ、HighBits は w と同じになる
    if (infNorm(lowBits(vsub(w, cs2), P.gamma2)) >= P.gamma2 - B) continue;
    if (P.gauss) packRice(wr, z, riceL(P));
    else packUniform(wr, z, P.gamma1);
    if (P.mode === 1) {
      lastAttempts = attempt;
      return concat(ch, wr.bytesOut());
    }
    // 公開鍵の下位ビット t0 を捨てた分をヒントで補う
    const ct0 = vinv(sk.t0hat.map((t) => pmul(chat, t)));
    if (infNorm(ct0) >= P.gamma2) continue;
    const h = makeHint(
      ct0.map((p) => p.map((x) => mod(-x)) as Poly),
      vadd(vsub(w, cs2), ct0),
      P.gamma2,
    );
    const weight = h.reduce((s, p) => s + p.reduce((a, x) => a + x, 0), 0);
    if (weight > P.omega) continue;
    lastAttempts = attempt;
    if (P.hintGolomb) {
      // ヒントと z を 1 本のビット列に (ヒントが先)
      const w2 = new BitWriter();
      packHintGolomb(w2, h);
      if (P.gauss) packRice(w2, z, riceL(P));
      else packUniform(w2, z, P.gamma1);
      return concat(ch, w2.bytesOut());
    }
    return concat(ch, packHint(h, P.omega), wr.bytesOut());
  }
  throw new Error("署名できなかった (やり直しすぎ)");
};

export const verify = (P: Params, pk: Uint8Array, msg: Uint8Array, sig: Uint8Array): boolean => {
  try {
    const B = beta(P);
    const { rho, t } = decodePk(P, pk);
    const Ahat = expandA(rho, P.k, P.l);
    const mu = H(H(pk), msg);
    const ch = sig.subarray(0, 32);
    let off = 32;
    let h: Vec | null = null;
    if (P.mode === 2 && !P.hintGolomb) {
      h = unpackHint(sig.subarray(32, 32 + P.omega + P.k), P.k, P.omega);
      if (!h) return false;
      off += P.omega + P.k;
    }
    const r = new BitReader(sig.subarray(off));
    if (P.mode === 2 && P.hintGolomb) {
      h = unpackHintGolomb(r, P.k, P.omega);
      if (!h) return false;
    }
    const z = P.gauss ? unpackRice(r, P.l, riceL(P)) : unpackUniform(r, P.l, P.gamma1);
    if (P.gauss) {
      if (Math.sqrt(l2sq(z)) > l2Bound(P)) return false;
    } else if (infNorm(z) >= P.gamma1 - B) return false;
    let z2: Vec = [];
    if (P.mode === 0) {
      z2 = unpackUniform(r, P.k, P.gamma1);
      if (infNorm(z2) >= P.gamma1 - B) return false;
    }
    // 余分なバイトがないか (署名は一意に)
    if (Math.ceil(r.bitPos / 8) !== sig.length - off) return false;
    if (r.bitPos & 7 && sig[sig.length - 1] >> (r.bitPos & 7)) return false; // 余りのビットは 0
    const chat = ntt(sampleInBall(ch, P.tau));
    const Az = matVec(Ahat, vntt(z));
    let wPrime: Vec;
    if (P.mode === 2) {
      const t1d = t.map((p) => p.map((x) => mod(x * (1 << P.d))) as Poly);
      const approx = vsub(Az, vinv(vntt(t1d).map((p) => pmul(chat, p))));
      wPrime = useHint(h!, approx, P.gamma2);
    } else {
      const ct = vinv(vntt(t).map((p) => pmul(chat, p)));
      wPrime = vsub(Az, ct);
      if (P.mode === 0) wPrime = vadd(wPrime, z2);
      else wPrime = highBits(wPrime, P.gamma2);
    }
    const ch2 = H(mu, polyBytes(wPrime));
    return ch2.every((x, i) => x === ch[i]);
  } catch {
    return false;
  }
};

// 理論上のサイズの目安
export const info = (P: Params) => ({
  sigma: P.gauss ? sigmaOf(P) : null,
  riceL: P.gauss ? riceL(P) : null,
  beta: beta(P),
});
