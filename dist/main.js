import { BLS, toHex } from "./bls.js";
const bls = new BLS();
const enc = new TextEncoder();
const $ = (id) => document.getElementById(id);
const val = (id) => $(id).value.trim();
const lines = (id) => $(id)
    .value.split("\n")
    .map((s) => s.trim())
    .filter((s) => s !== "");
// ボタンを押したら実行。エラーは出力先に出す。かかった時間も出す
const on = (btn, out, fn) => {
    $(btn).addEventListener("click", () => {
        const o = $(out);
        const set = (s) => o instanceof HTMLTextAreaElement ? (o.value = s) : (o.textContent = s);
        set("計算中...");
        // 再描画させてから重い計算をする
        setTimeout(() => {
            try {
                const s = performance.now();
                const r = fn();
                set(r);
                console.log(`${btn}: ${(performance.now() - s).toFixed(0)} ms`);
            }
            catch (e) {
                set("エラー: " + e.message);
            }
        }, 0);
    });
};
const okng = (b) => (b ? "✓ 有効" : "✗ 無効");
on("keygen", "keygen-sk", () => {
    const kp = bls.generateKeyPair();
    $("keygen-pk").value = kp.publicKey;
    return kp.privateKey;
});
on("derive", "derive-pk", () => toHex(bls.getPublicKey(val("derive-sk"))));
on("sign", "sign-sig", () => toHex(bls.sign(enc.encode($("sign-msg").value), val("sign-sk"))));
on("verify", "verify-result", () => okng(bls.verify(enc.encode($("verify-msg").value), val("verify-pk"), val("verify-sig"))));
on("agg", "agg-sig", () => toHex(bls.aggregateSignatures(lines("agg-sigs"))));
on("aggv", "aggv-result", () => okng(bls.aggregateVerify($("aggv-msgs").value.split("\n").filter((s) => s !== "").map((s) => enc.encode(s)), lines("aggv-pks"), val("aggv-sig"))));
on("fagg", "fagg-result", () => okng(bls.fastAggregateVerify(enc.encode($("fagg-msg").value), lines("fagg-pks"), val("fagg-sig"))));
