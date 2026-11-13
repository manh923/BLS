// Worker 並列版のテスト + 速さの比較
import { BLS, _internal as I } from "../dist/bls.js";
import { BLSPool } from "../dist/bls-pool.js";

let fail = 0;
const ok = (name, cond) => { console.log(`${cond ? "ok  " : "FAIL"} ${name}`); if (!cond) fail++; };
const enc = new TextEncoder();
const bls = new BLS();
const pool = await BLSPool.create();
console.log(`Worker: ${pool.size} 本`);

const N = Number(process.argv[2] ?? 32);
const ks = Array.from({ length: N }, () => bls.generateKeyPair());
const ms = ks.map((_, i) => enc.encode("pool-" + i));
const items = ks.map((k, i) => ({ msg: ms[i], pk: k.publicKey, sig: bls.sign(ms[i], k.privateKey) }));

ok(`pool.verifyBatch ${N}件 ok`, await pool.verifyBatch(items));
const bad = items.map((x) => ({ ...x }));
bad[N - 1] = { ...bad[N - 1], sig: items[0].sig };
ok("pool.verifyBatch 1件だけ不正なら NG", !(await pool.verifyBatch(bad)));
const D = I.E2.mul(I.G2, 7n);
const cancel = items.map((x) => ({ ...x }));
cancel[0] = { ...cancel[0], sig: I.g2ToBytes(I.E2.add(I.g2FromBytes(items[0].sig), D)) };
cancel[N - 1] = { ...cancel[N - 1], sig: I.g2ToBytes(I.E2.add(I.g2FromBytes(items[N - 1].sig), I.E2.neg(D))) };
ok("pool.verifyBatch 打ち消し合う2件も見抜く", !(await pool.verifyBatch(cancel)));
const agg = bls.aggregateSignatures(items.map((x) => x.sig));
ok(`pool.aggregateVerify ${N}人 ok`, await pool.aggregateVerify(ms, ks.map((k) => k.publicKey), agg));
ok("pool.aggregateVerify 順番を入れ替えると NG", !(await pool.aggregateVerify([ms[1], ms[0], ...ms.slice(2)], ks.map((k) => k.publicKey), agg)));

// 速さ (3回の平均)
const time = async (label, fn, n = 3) => { await fn(); const s = performance.now(); for (let i = 0; i < n; i++) await fn(); const t = (performance.now() - s) / n; console.log(`  ${label.padEnd(30)} ${t.toFixed(1).padStart(7)} ms  (1件あたり ${(t / N).toFixed(2)} ms)`); };
console.log(`\n${N}件の速さ:`);
await time("1件ずつ verify", () => { for (const it of items) bls.verify(it.msg, it.pk, it.sig); });
await time("verifyBatch (1スレッド)", () => bls.verifyBatch(items));
await time(`pool.verifyBatch (${pool.size}並列)`, () => pool.verifyBatch(items));
console.log("    内訳:", Object.fromEntries(Object.entries(pool.prof).map(([k, v]) => [k, v.toFixed(1) + " ms"])));
await time("aggregateVerify (1スレッド)", () => bls.aggregateVerify(ms, ks.map((k) => k.publicKey), agg));
await time(`pool.aggregateVerify (${pool.size}並列)`, () => pool.aggregateVerify(ms, ks.map((k) => k.publicKey), agg));

pool.terminate();
console.log(fail ? `\n${fail} 件失敗` : "\nWorker 並列 全部 ok");
process.exit(fail ? 1 : 0);
