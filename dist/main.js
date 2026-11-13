import { BLS, toHex } from "./bls.js";
import { BLSPool } from "./bls-pool.js";
import { BLSWasm } from "./bls-wasm.js";
const bls = new BLS();
const enc = new TextEncoder();
const $ = (id) => document.getElementById(id);
const val = (id) => $(id).value.trim();
const lines = (id) => $(id)
    .value.split("\n")
    .map((s) => s.trim())
    .filter((s) => s !== "");
// ボタンを押したら実行。エラーは出力先に出す
// 時間は console.time で全体、console.table で内訳。ページにもボタンの横に出す
const on = (btn, out, label, fn) => {
    const b = $(btn);
    const timing = document.createElement("span");
    b.insertAdjacentText("afterend", " ");
    b.insertAdjacentElement("afterend", timing);
    b.addEventListener("click", () => {
        const o = $(out);
        const set = (s) => o instanceof HTMLTextAreaElement ? (o.value = s) : (o.textContent = s);
        set("計算中...");
        timing.textContent = "";
        // 再描画させてから重い計算をする
        setTimeout(() => {
            try {
                console.time(label);
                const t0 = performance.now();
                const r = fn();
                const ms = performance.now() - t0;
                console.timeEnd(label);
                const rows = {};
                for (const [k, v] of Object.entries(bls.prof))
                    rows[k] = v.toFixed(2) + " ms";
                if (Object.keys(rows).length)
                    console.table(rows);
                timing.textContent = ` ${ms.toFixed(1)} ms`;
                set(r);
            }
            catch (e) {
                console.timeEnd(label);
                set("エラー: " + e.message);
            }
        }, 0);
    });
};
const okng = (b) => (b ? "✓ 有効" : "✗ 無効");
on("keygen", "keygen-sk", "鍵生成", () => {
    const kp = bls.generateKeyPair();
    $("keygen-pk").value = kp.publicKey;
    return kp.privateKey;
});
on("derive", "derive-pk", "公開鍵導出", () => toHex(bls.getPublicKey(val("derive-sk"))));
on("sign", "sign-sig", "署名", () => toHex(bls.sign(enc.encode($("sign-msg").value), val("sign-sk"))));
on("verify", "verify-result", "検証", () => okng(bls.verify(enc.encode($("verify-msg").value), val("verify-pk"), val("verify-sig"))));
on("agg", "agg-sig", "署名の集約", () => toHex(bls.aggregateSignatures(lines("agg-sigs"))));
on("aggv", "aggv-result", "集約検証", () => okng(bls.aggregateVerify($("aggv-msgs").value.split("\n").filter((s) => s !== "").map((s) => enc.encode(s)), lines("aggv-pks"), val("aggv-sig"))));
on("fagg", "fagg-result", "集約検証 (同じメッセージ)", () => okng(bls.fastAggregateVerify(enc.encode($("fagg-msg").value), lines("fagg-pks"), val("fagg-sig"))));
let raceItems = [];
let pool = null;
const show = (id, s) => ($(id).textContent = s);
const per = (ms) => `${ms.toFixed(0)} ms (1件あたり ${(ms / raceItems.length).toFixed(2)} ms)`;
const later = (fn) => setTimeout(fn, 0);
$("race-gen").addEventListener("click", () => {
    show("race-gen-status", "作成中...");
    later(() => {
        const n = Math.max(1, Number($("race-n").value) || 32);
        raceItems = [];
        for (let i = 0; i < n; i++) {
            const kp = bls.generateKeyPair();
            const msg = enc.encode("tx-" + i + "-" + Math.random());
            raceItems.push({ msg, pk: kp.publicKey, sig: bls.sign(msg, kp.privateKey) });
        }
        show("race-gen-status", `${n} 件できた`);
    });
});
const need = () => {
    if (!raceItems.length)
        throw new Error("先に「署名を作る」");
};
const race = (btn, out, label, fn) => $(btn).addEventListener("click", () => {
    show(out, "計算中...");
    later(async () => {
        try {
            need();
            console.time(label);
            const t0 = performance.now();
            const ok = await fn();
            const ms = performance.now() - t0;
            console.timeEnd(label);
            show(out, `${ok ? "✓ 全部有効" : "✗ 不正あり"} / ${per(ms)}`);
        }
        catch (e) {
            show(out, "エラー: " + e.message);
        }
    });
});
const getPool = async () => (pool ??= await BLSPool.create());
race("race-one", "race-one-out", "1件ずつ verify", () => raceItems.every((it) => bls.verify(it.msg, it.pk, it.sig)));
race("race-batch", "race-batch-out", "バッチ検証", () => {
    const ok = bls.verifyBatch(raceItems);
    console.table(Object.fromEntries(Object.entries(bls.prof).map(([k, v]) => [k, v.toFixed(2) + " ms"])));
    return ok;
});
race("race-pool", "race-pool-out", "バッチ検証 (Worker 並列)", async () => {
    const p = await getPool();
    const ok = await p.verifyBatch(raceItems);
    console.log(`Worker ${p.size} 本`);
    console.table(Object.fromEntries(Object.entries(p.prof).map(([k, v]) => [k, v.toFixed(2) + " ms"])));
    return ok;
});
race("race-bad", "race-bad-out", "1件だけ壊してバッチ検証", async () => {
    const p = await getPool();
    const bad = raceItems.map((x) => ({ ...x }));
    const j = Math.floor(Math.random() * bad.length);
    bad[j] = { ...bad[j], msg: enc.encode("改ざん") };
    console.log(`${j} 番目のメッセージを改ざん`);
    return p.verifyBatch(bad);
});
// Rust → WASM 版
let wasm = null;
const getWasm = async () => (wasm ??= await BLSWasm.load());
race("race-wasm-one", "race-wasm-one-out", "1件ずつ verify (WASM)", async () => {
    const w = await getWasm();
    return raceItems.every((it) => w.verify(it.msg, it.pk, it.sig));
});
race("race-wasm-batch", "race-wasm-batch-out", "バッチ検証 (WASM)", async () => (await getWasm()).verifyBatch(raceItems));
