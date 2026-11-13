import { BLS, toHex } from "./bls.js";
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
