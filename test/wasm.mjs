// Rust (WASM) 版を TS 版・noble と突き合わせる + 速さ比べ
import { BLS, toHex, fromHex } from "../dist/bls.js";
import { BLSWasm } from "../dist/bls-wasm.js";
import { bls12_381 as nb } from "@noble/curves/bls12-381";

let fail = 0;
const ok = (name, cond) => { console.log(`${cond ? "ok  " : "FAIL"} ${name}`); if (!cond) fail++; };
const enc = new TextEncoder();
const ts = new BLS();
const w = await BLSWasm.load();

for (let i = 0; i < 3; i++) {
  const kp = ts.generateKeyPair();
  const msg = enc.encode("wasm-" + i + "-" + "x".repeat(i * 50));
  ok(`#${i} 公開鍵 = TS版`, toHex(w.getPublicKey(kp.privateKey)) === kp.publicKey);
  const sw = w.sign(msg, kp.privateKey);
  ok(`#${i} 署名 = TS版 = noble`, toHex(sw) === toHex(ts.sign(msg, kp.privateKey)) && toHex(sw) === toHex(nb.sign(msg, fromHex(kp.privateKey))));
  ok(`#${i} WASM で検証 OK`, w.verify(msg, kp.publicKey, sw));
  ok(`#${i} 改ざんは NG`, !w.verify(enc.encode("other"), kp.publicKey, sw));
}
const kp = w.generateKeyPair();
ok("WASM の鍵生成 → TS版でも同じ公開鍵", toHex(ts.getPublicKey(kp.privateKey)) === kp.publicKey);

const ks = Array.from({ length: 6 }, () => w.generateKeyPair());
const ms = ks.map((_, i) => enc.encode("agg-" + i));
const sigs = ks.map((k, i) => w.sign(ms[i], k.privateKey));
const agg = w.aggregateSignatures(sigs);
ok("集約署名 = TS版", toHex(agg) === toHex(ts.aggregateSignatures(sigs)));
ok("集約公開鍵 = TS版", toHex(w.aggregatePublicKeys(ks.map((k) => k.publicKey))) === toHex(ts.aggregatePublicKeys(ks.map((k) => k.publicKey))));
ok("aggregateVerify OK", w.aggregateVerify(ms, ks.map((k) => k.publicKey), agg));
ok("aggregateVerify 入れ替え NG", !w.aggregateVerify([ms[1], ms[0], ...ms.slice(2)], ks.map((k) => k.publicKey), agg));
const items = ks.map((k, i) => ({ msg: ms[i], pk: k.publicKey, sig: sigs[i] }));
ok("verifyBatch OK", w.verifyBatch(items));
const bad = items.map((x) => ({ ...x }));
bad[3] = { ...bad[3], sig: sigs[4] };
ok("verifyBatch 1件不正で NG", !w.verifyBatch(bad));
ok("壊れた署名は NG (例外にならない)", !w.verify(ms[0], ks[0].publicKey, new Uint8Array(96).fill(0xff)));

// 速さ
const t = (label, fn, n = 20) => { for (let i = 0; i < 3; i++) fn(); const s = performance.now(); for (let i = 0; i < n; i++) fn(); const ms = (performance.now() - s) / n; console.log(`  ${label.padEnd(24)} ${ms.toFixed(2).padStart(8)} ms`); return ms; };
const m = enc.encode("hello"), sk = fromHex(ks[0].privateKey), pk = fromHex(ks[0].publicKey);
const sTs = ts.sign(m, sk);
console.log("\n速さ (TS版 / Rust→WASM):");
const a1 = t("TS 署名", () => ts.sign(m, sk)), b1 = t("WASM 署名", () => w.sign(m, sk));
const a2 = t("TS 検証", () => ts.verify(m, pk, sTs)), b2 = t("WASM 検証", () => w.verify(m, pk, sTs));
const N = 16;
const many = Array.from({ length: N }, (_, i) => { const k = w.generateKeyPair(); const mm = enc.encode("b" + i); return { msg: mm, pk: k.publicKey, sig: w.sign(mm, k.privateKey) }; });
const a3 = t(`TS バッチ(${N}件)`, () => ts.verifyBatch(many), 5), b3 = t(`WASM バッチ(${N}件)`, () => w.verifyBatch(many), 5);
console.log(`  → 署名 ${(a1 / b1).toFixed(1)} 倍、検証 ${(a2 / b2).toFixed(1)} 倍、バッチ ${(a3 / b3).toFixed(1)} 倍`);

console.log(fail ? `\n${fail} 件失敗` : "\nWASM 全部 ok");
process.exit(fail ? 1 : 0);
