// WASM 同士の速さ比べ: 自前 (Rust→WASM) vs blst (C→WASM) vs TS版
//   blst の WASM は rust-bench を wasm32 向けにビルドしたもの (引数でパスを渡す)
import fs from "fs";
import { BLS, fromHex, toHex } from "../dist/bls.js";
import { BLSWasm } from "../dist/bls-wasm.js";

const blstPath = process.argv[2];
const mod = await WebAssembly.compile(fs.readFileSync(blstPath));
console.log("blst wasm の import:", WebAssembly.Module.imports(mod).map((i) => i.module + "." + i.name).join(", ") || "なし");
const inst = await WebAssembly.instantiate(mod, {});
const bx = inst.exports;
const put = (data) => { const p = bx.blst_alloc(data.length); new Uint8Array(bx.memory.buffer).set(data, p); return p; };

const enc = new TextEncoder();
const ts = new BLS();
const w = await BLSWasm.load();
const kp = ts.generateKeyPair();
const sk = fromHex(kp.privateKey), pk = fromHex(kp.publicKey), msg = enc.encode("hello BLS");
// blst 用の入力を WASM メモリに置く (使い回す)
const pSk = put(sk), pPk = put(pk), pMsg = put(msg), pOut = bx.blst_alloc(96);
const blstSign = () => { bx.blst_bench_sign(pSk, pMsg, msg.length, pOut); return new Uint8Array(bx.memory.buffer, pOut, 96).slice(); };
const sigBlst = blstSign();
const sig = w.sign(msg, sk);
console.log("署名が一致 (自前WASM = blst = TS):", toHex(sig) === toHex(sigBlst) && toHex(sig) === toHex(ts.sign(msg, sk)));
const pSig = put(sig);

const t = (label, fn, n = 30) => { for (let i = 0; i < 5; i++) fn(); const s = performance.now(); for (let i = 0; i < n; i++) fn(); const ms = (performance.now() - s) / n; console.log(`  ${label.padEnd(20)} ${ms.toFixed(2).padStart(7)} ms`); return ms; };
console.log("\n署名:");
const s1 = t("TS版", () => ts.sign(msg, sk));
const s2 = t("自前 Rust→WASM", () => w.sign(msg, sk));
const s3 = t("blst C→WASM", blstSign);
console.log("検証:");
const v1 = t("TS版", () => ts.verify(msg, pk, sig));
const v2 = t("自前 Rust→WASM", () => w.verify(msg, pk, sig));
const v3 = t("blst C→WASM", () => { if (!bx.blst_bench_verify(pPk, pMsg, msg.length, pSig)) throw new Error("NG"); });
console.log(`\n自前WASM は blst WASM の 署名 ${(s2 / s3).toFixed(2)} 倍、検証 ${(v2 / v3).toFixed(2)} 倍 の時間 (1 未満なら自前が速い)`);
console.log(`TS版 は blst WASM の 署名 ${(s1 / s3).toFixed(2)} 倍、検証 ${(v1 / v3).toFixed(2)} 倍 の時間`);
