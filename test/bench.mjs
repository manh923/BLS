// ターミナルでベンチ: npm run bench
import { BLS, toHex } from "../dist/bls.js";
const enc = new TextEncoder();
const bls = new BLS();
const N = Number(process.argv[2] ?? 20);

const bench = (label, fn) => {
  for (let i = 0; i < 3; i++) fn(); // ウォームアップ
  const prof = {};
  const s = performance.now();
  for (let i = 0; i < N; i++) {
    fn();
    for (const [k, v] of Object.entries(bls.prof)) prof[k] = (prof[k] ?? 0) + v;
  }
  const ms = (performance.now() - s) / N;
  console.log(`\n${label}: ${ms.toFixed(2)} ms (平均 ${N} 回)`);
  const rows = {};
  for (const [k, v] of Object.entries(prof)) rows[k] = { ms: +(v / N).toFixed(2), "%": +((v / N / ms) * 100).toFixed(1) };
  if (Object.keys(rows).length) console.table(rows);
};

console.time("初回の鍵生成 (テーブル作成込み)");
const kp = bls.generateKeyPair();
console.timeEnd("初回の鍵生成 (テーブル作成込み)");

const msg = enc.encode("Hello, BLS!");
const sig = toHex(bls.sign(msg, kp.privateKey));
bench("鍵生成", () => bls.generateKeyPair());
bench("署名", () => bls.sign(msg, kp.privateKey));
bench("検証", () => bls.verify(msg, kp.publicKey, sig));

const keys = Array.from({ length: 8 }, () => bls.generateKeyPair());
const msgs = keys.map((_, i) => enc.encode("msg-" + i));
const agg = bls.aggregateSignatures(keys.map((k, i) => bls.sign(msgs[i], k.privateKey)));
bench("集約検証 (8人・別メッセージ)", () => bls.aggregateVerify(msgs, keys.map((k) => k.publicKey), agg));
const aggSame = bls.aggregateSignatures(keys.map((k) => bls.sign(msg, k.privateKey)));
bench("集約検証 (8人・同じメッセージ)", () => bls.fastAggregateVerify(msg, keys.map((k) => k.publicKey), aggSame));
