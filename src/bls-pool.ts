// Worker を何本か立てて、BLS の検証を並列にする
//   各 Worker が担当分の (復元・hash-to-G2・ミラーループ) をやり、
//   こっちで Fp12 を掛け合わせて最終冪を1回だけやる
import { _internal as I, DST_NUL, toHex, fromHex } from "./bls.js";
import type { WorkerJob, WorkerResult } from "./bls-worker.js";

type BytesLike = Uint8Array | string;
const bytes = (x: BytesLike) => (typeof x === "string" ? fromHex(x) : x);

interface W {
  post(job: WorkerJob): void;
  onResult(fn: (r: WorkerResult) => void): void;
  terminate(): void;
}

const g = globalThis as any;
const isNode = !!g.process?.versions?.node;

const spawn = async (url: URL): Promise<W> => {
  if (isNode) {
    const name = "node:worker_threads";
    const wt: any = await import(name);
    const w = new wt.Worker(url);
    return {
      post: (j) => w.postMessage(j),
      onResult: (fn) => w.on("message", fn),
      terminate: () => w.terminate(),
    };
  }
  const w = new Worker(url, { type: "module" });
  return {
    post: (j) => w.postMessage(j),
    onResult: (fn) => w.addEventListener("message", (e: MessageEvent) => fn(e.data)),
    terminate: () => w.terminate(),
  };
};

// 配列を k 個にだいたい均等に分ける
const split = <T>(xs: T[], k: number): T[][] => {
  const out: T[][] = [];
  const n = Math.min(k, xs.length);
  for (let i = 0; i < n; i++) out.push(xs.slice(Math.floor((i * xs.length) / n), Math.floor(((i + 1) * xs.length) / n)));
  return out;
};

export class BLSPool {
  private nextId = 1;
  private pending = new Map<number, (r: WorkerResult) => void>();
  // 直前の呼び出しの内訳 (ms)
  prof: Record<string, number> = {};

  private constructor(
    private workers: W[],
    readonly dstName: string,
  ) {
    for (const w of workers)
      w.onResult((r) => {
        const fn = this.pending.get(r.id);
        this.pending.delete(r.id);
        fn?.(r);
      });
  }

  // n: Worker の数 (省略時はコア数)
  static async create(n?: number, dstName = DST_NUL): Promise<BLSPool> {
    if (n === undefined) {
      if (isNode) {
        const name = "node:os";
        const os: any = await import(name);
        n = os.availableParallelism?.() ?? os.cpus().length;
      } else n = g.navigator?.hardwareConcurrency ?? 4;
    }
    const url = new URL("./bls-worker.js", import.meta.url);
    const ws = await Promise.all(Array.from({ length: Math.max(1, n!) }, () => spawn(url)));
    return new BLSPool(ws, dstName);
  }

  get size() {
    return this.workers.length;
  }

  private run(w: W, job: Omit<WorkerJob, "id" | "dst">): Promise<WorkerResult> {
    const id = this.nextId++;
    return new Promise((res) => {
      this.pending.set(id, res);
      w.post({ ...job, id, dst: this.dstName });
    });
  }

  // バッチ検証 (BLS.verifyBatch の並列版)
  async verifyBatch(items: { msg: Uint8Array; pk: BytesLike; sig: BytesLike }[]): Promise<boolean> {
    this.prof = {};
    if (items.length === 0) return false;
    const t0 = performance.now();
    const jobs = items.map((it) => ({ msg: it.msg, pk: bytes(it.pk), sig: bytes(it.sig), r: I.randScalar64() }));
    const chunks = split(jobs, this.workers.length);
    const results = await Promise.all(chunks.map((c, i) => this.run(this.workers[i], { kind: "batch", items: c })));
    const t1 = performance.now();
    this.prof[`Worker ${chunks.length}本 (復元・hash・ミラーループ)`] = t1 - t0;
    if (results.some((r) => !r.ok)) return false;
    // 署名の部分和を足して、e(-G1, Σ r_i·σ_i) の分だけここで計算
    let S = I.E2.inf;
    for (const r of results) if (r.S) S = I.E2.add(S, [...(r.S as any), [1n, 0n]] as any);
    let f = I.F12_1;
    for (const r of results) f = I.f12mul(f, r.f as any);
    const Sa = I.E2.toAffine(S);
    if (Sa) f = I.f12mul(f, I.millerLoop([[I.NEG_G1_AFF, Sa]]));
    const t2 = performance.now();
    this.prof["まとめ (Fp12 の積 + 署名のペア)"] = t2 - t1;
    const ok = I.f12eq(I.finalExp(f), I.F12_1);
    this.prof["最終冪"] = performance.now() - t2;
    return ok;
  }

  // 集約検証 (別々のメッセージ) の並列版。署名側のペアはこっちで同時に計算する
  async aggregateVerify(msgs: Uint8Array[], pks: BytesLike[], sig: BytesLike): Promise<boolean> {
    this.prof = {};
    if (msgs.length === 0 || msgs.length !== pks.length) return false;
    if (this.dstName === DST_NUL && new Set(msgs.map(toHex)).size !== msgs.length) return false;
    const t0 = performance.now();
    const jobs = msgs.map((m, i) => ({ msg: m, pk: bytes(pks[i]) }));
    const chunks = split(jobs, this.workers.length);
    const pending = Promise.all(chunks.map((c, i) => this.run(this.workers[i], { kind: "agg", items: c })));
    // Worker が動いている間に、こっちは署名の復元とそのペアのミラーループ
    let fSig;
    try {
      const S = I.g2FromBytes(bytes(sig));
      const Sa = I.E2.toAffine(S);
      fSig = Sa ? I.millerLoop([[I.NEG_G1_AFF, Sa]]) : I.F12_1;
    } catch {
      await pending;
      return false;
    }
    const results = await pending;
    const t1 = performance.now();
    this.prof[`Worker ${chunks.length}本 + 署名側`] = t1 - t0;
    if (results.some((r) => !r.ok)) return false;
    let f = fSig;
    for (const r of results) f = I.f12mul(f, r.f as any);
    const ok = I.f12eq(I.finalExp(f), I.F12_1);
    this.prof["最終冪"] = performance.now() - t1;
    return ok;
  }

  terminate() {
    for (const w of this.workers) w.terminate();
    this.workers = [];
  }
}
