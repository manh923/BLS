// Rust で書いた BLS12-381 (rust/) の WASM 版を呼ぶ。API は TS 版の BLS と同じ形
//   dist/bls12381.wasm を読み込む (npm run build:wasm で作る)
import { DST_NUL, fromHex, toHex } from "./bls.js";

type BytesLike = Uint8Array | string;
const bytes = (x: BytesLike) => (typeof x === "string" ? fromHex(x) : x);
const enc = new TextEncoder();
const g = globalThis as any;
const isNode = !!g.process?.versions?.node;

interface Exports {
  memory: WebAssembly.Memory;
  bls_alloc(n: number): number;
  bls_free(p: number, n: number): void;
  bls_keygen(rand: number, out: number): number;
  bls_sk_to_pk(sk: number, out: number): number;
  bls_sign(sk: number, msg: number, msgLen: number, dst: number, dstLen: number, out: number): number;
  bls_verify(pk: number, msg: number, msgLen: number, sig: number, dst: number, dstLen: number): number;
  bls_aggregate_sigs(sigs: number, n: number, out: number): number;
  bls_aggregate_pks(pks: number, n: number, out: number): number;
  bls_aggregate_verify(msgs: number, lens: number, n: number, pks: number, sig: number, dst: number, dstLen: number): number;
  bls_verify_batch(msgs: number, lens: number, n: number, pks: number, sigs: number, rs: number, dst: number, dstLen: number): number;
}

const concat = (arrs: Uint8Array[]) => {
  const out = new Uint8Array(arrs.reduce((s, a) => s + a.length, 0));
  let o = 0;
  for (const a of arrs) {
    out.set(a, o);
    o += a.length;
  }
  return out;
};
const u32le = (xs: number[]) => {
  const out = new Uint8Array(xs.length * 4);
  const dv = new DataView(out.buffer);
  xs.forEach((x, i) => dv.setUint32(i * 4, x, true));
  return out;
};

export class BLSWasm {
  readonly dst: Uint8Array;
  private constructor(
    private ex: Exports,
    readonly dstName: string,
  ) {
    this.dst = enc.encode(dstName);
  }

  static async load(dstName = DST_NUL, url = new URL("./bls12381.wasm", import.meta.url)): Promise<BLSWasm> {
    let buf: ArrayBuffer;
    if (isNode) {
      const name = "node:fs/promises";
      const fs: any = await import(name);
      buf = await fs.readFile(url);
    } else {
      buf = await (await fetch(url)).arrayBuffer();
    }
    const { instance } = await WebAssembly.instantiate(buf, {});
    return new BLSWasm(instance.exports as unknown as Exports, dstName);
  }

  // 入力を WASM のメモリにコピー → 呼ぶ → 出力を読む → 解放
  private run(inputs: Uint8Array[], outLen: number, fn: (ptrs: number[], out: number) => number) {
    const ex = this.ex;
    const ptrs = inputs.map((a) => ex.bls_alloc(a.length));
    const out = ex.bls_alloc(outLen);
    // alloc でメモリが伸びると古い view は使えなくなるので、全部確保してから書く
    const mem = new Uint8Array(ex.memory.buffer);
    inputs.forEach((a, i) => mem.set(a, ptrs[i]));
    try {
      const rc = fn(ptrs, out);
      const res = new Uint8Array(ex.memory.buffer, out, outLen).slice();
      return { rc, out: res };
    } finally {
      inputs.forEach((a, i) => ex.bls_free(ptrs[i], a.length));
      ex.bls_free(out, outLen);
    }
  }

  generatePrivateKey(): Uint8Array {
    for (;;) {
      const r = globalThis.crypto.getRandomValues(new Uint8Array(48));
      const { rc, out } = this.run([r], 32, ([p], o) => this.ex.bls_keygen(p, o));
      if (rc) return out;
    }
  }
  getPublicKey(sk: BytesLike): Uint8Array {
    const { rc, out } = this.run([bytes(sk)], 48, ([p], o) => this.ex.bls_sk_to_pk(p, o));
    if (!rc) throw new Error("秘密鍵が範囲外 (1..r-1)");
    return out;
  }
  generateKeyPair(): { privateKey: string; publicKey: string } {
    const sk = this.generatePrivateKey();
    return { privateKey: toHex(sk), publicKey: toHex(this.getPublicKey(sk)) };
  }
  sign(msg: Uint8Array, sk: BytesLike): Uint8Array {
    const { rc, out } = this.run([bytes(sk), msg, this.dst], 96, ([s, m, d], o) =>
      this.ex.bls_sign(s, m, msg.length, d, this.dst.length, o),
    );
    if (!rc) throw new Error("秘密鍵が範囲外 (1..r-1)");
    return out;
  }
  verify(msg: Uint8Array, pk: BytesLike, sig: BytesLike): boolean {
    const p = bytes(pk);
    const s = bytes(sig);
    if (p.length !== 48 || s.length !== 96) return false;
    return !!this.run([p, msg, s, this.dst], 0, ([pp, m, ss, d]) =>
      this.ex.bls_verify(pp, m, msg.length, ss, d, this.dst.length),
    ).rc;
  }
  aggregateSignatures(sigs: BytesLike[]): Uint8Array {
    const all = sigs.map(bytes);
    if (!all.length || all.some((s) => s.length !== 96)) throw new Error("署名が不正");
    const { rc, out } = this.run([concat(all)], 96, ([p], o) => this.ex.bls_aggregate_sigs(p, all.length, o));
    if (!rc) throw new Error("署名が不正");
    return out;
  }
  aggregatePublicKeys(pks: BytesLike[]): Uint8Array {
    const all = pks.map(bytes);
    if (!all.length || all.some((p) => p.length !== 48)) throw new Error("公開鍵が不正");
    const { rc, out } = this.run([concat(all)], 48, ([p], o) => this.ex.bls_aggregate_pks(p, all.length, o));
    if (!rc) throw new Error("公開鍵が不正");
    return out;
  }
  aggregateVerify(msgs: Uint8Array[], pks: BytesLike[], sig: BytesLike): boolean {
    const ps = pks.map(bytes);
    const s = bytes(sig);
    if (!msgs.length || msgs.length !== ps.length || ps.some((p) => p.length !== 48) || s.length !== 96) return false;
    return !!this.run([concat(msgs), u32le(msgs.map((m) => m.length)), concat(ps), s, this.dst], 0, ([m, l, p, ss, d]) =>
      this.ex.bls_aggregate_verify(m, l, msgs.length, p, ss, d, this.dst.length),
    ).rc;
  }
  fastAggregateVerify(msg: Uint8Array, pks: BytesLike[], sig: BytesLike): boolean {
    try {
      return this.verify(msg, this.aggregatePublicKeys(pks), sig);
    } catch {
      return false;
    }
  }
  // バッチ検証 (64bit のランダム係数は JS 側で作って渡す)
  verifyBatch(items: { msg: Uint8Array; pk: BytesLike; sig: BytesLike }[]): boolean {
    const n = items.length;
    if (!n) return false;
    const ps = items.map((it) => bytes(it.pk));
    const ss = items.map((it) => bytes(it.sig));
    if (ps.some((p) => p.length !== 48) || ss.some((s) => s.length !== 96)) return false;
    const rs = new Uint8Array(n * 8);
    globalThis.crypto.getRandomValues(rs);
    for (let i = 0; i < n; i++) if (rs.subarray(i * 8, i * 8 + 8).every((x) => x === 0)) rs[i * 8] = 1;
    const msgs = items.map((it) => it.msg);
    return !!this.run([concat(msgs), u32le(msgs.map((m) => m.length)), concat(ps), concat(ss), rs, this.dst], 0, ([m, l, p, s, r, d]) =>
      this.ex.bls_verify_batch(m, l, n, p, s, r, d, this.dst.length),
    ).rc;
  }
}
