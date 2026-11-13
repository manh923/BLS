// BLS の重い部分 (復元・hash-to-G2・ミラーループ) を別スレッドで計算する Worker
//   ブラウザ: new Worker(url, { type: "module" })
//   Node:     new (await import("node:worker_threads")).Worker(url)
// 最終冪はやらずに、ミラーループの値 (Fp12) と署名の部分和を返す。まとめるのは呼び出し側
import { _internal as I } from "./bls.js";
const enc = new TextEncoder();
const handle = (job) => {
    const t0 = performance.now();
    try {
        const { E1, E2 } = I;
        const dst = enc.encode(job.dst);
        const Ps = [];
        const Hs = [];
        const sigs = [];
        const rs = [];
        for (const it of job.items) {
            const pk = I.g1FromBytesCached(it.pk);
            if (E1.isInf(pk))
                return { id: job.id, ok: false, error: "公開鍵が無限遠点" };
            Hs.push(I.hashToG2(it.msg, dst));
            if (job.kind === "batch") {
                sigs.push(I.g2FromBytes(it.sig));
                rs.push(it.r);
                Ps.push(E1.mul(pk, it.r));
            }
            else {
                Ps.push(pk);
            }
        }
        const pa = E1.toAffineBatch(Ps);
        const qa = E2.toAffineBatch(Hs);
        const f = I.millerLoop(pa.map((p, i) => [p, qa[i]]));
        let S = null;
        if (job.kind === "batch")
            S = E2.toAffine(I.msm(E2, sigs, rs));
        return { id: job.id, ok: true, f, S, ms: performance.now() - t0 };
    }
    catch (e) {
        return { id: job.id, ok: false, error: e.message };
    }
};
// 実行環境に合わせてメッセージを受ける
const g = globalThis;
if (typeof g.WorkerGlobalScope !== "undefined" && g instanceof g.WorkerGlobalScope) {
    g.onmessage = (e) => g.postMessage(handle(e.data));
}
else {
    const name = "node:worker_threads";
    const wt = await import(name);
    if (wt.parentPort)
        wt.parentPort.on("message", (job) => wt.parentPort.postMessage(handle(job)));
}
