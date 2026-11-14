import { BLS, toHex } from "./bls.js";
import { BLSPool } from "./bls-pool.js";
// UI は cryptos の「ECでシュノアしたら速くなるんじゃね？」と同じ作り
(() => {
    const enc = new TextEncoder();
    const bls = new BLS();
    const style = document.createElement("style");
    style.textContent = `
    *, *::before, *::after { box-sizing: border-box; touch-action: manipulation; }
    :root {
      --bg: #f7f6f3; --surface: #ffffff; --border: #e2e0db;
      --text: #1a1917; --muted: #8a8780;
      --success: #2d6a4f; --error: #c1121f;
      --valid-bg: #d8f3dc; --invalid-bg: #ffe0e0;
      --mono: 'JetBrains Mono', monospace; --sans: 'DM Sans', sans-serif;
    }
    @media (prefers-color-scheme: dark) {
      :root:not([data-theme="light"]) {
        --bg: #161514; --surface: #1f1e1c; --border: #34322e;
        --text: #ecebe8; --muted: #9a978f;
        --success: #74c69d; --error: #ff6b6b;
        --valid-bg: #1b3a2a; --invalid-bg: #3a1b1e;
      }
    }
    :root[data-theme="dark"] {
      --bg: #161514; --surface: #1f1e1c; --border: #34322e;
      --text: #ecebe8; --muted: #9a978f;
      --success: #74c69d; --error: #ff6b6b;
      --valid-bg: #1b3a2a; --invalid-bg: #3a1b1e;
    }
    body { margin:0; padding:0; background:var(--bg); color:var(--text); font-family:var(--sans); font-size:14px; line-height:1.6; min-height:100vh; }
    #ct-header { padding:32px 40px 24px; border-bottom:1px solid var(--border); background:var(--surface); }
    #ct-header h1 { margin:0; font-family:var(--mono); font-size:18px; font-weight:400; letter-spacing:0.05em; }
    #ct-header p { margin:4px 0 0; font-size:12px; color:var(--muted); font-family:var(--mono); }
    #ct-header a { color:var(--muted); }
    #ct-tabs { display:flex; padding:0 40px; background:var(--surface); border-bottom:1px solid var(--border); overflow-x:auto; -webkit-overflow-scrolling:touch; scrollbar-width:none; }
    #ct-tabs::-webkit-scrollbar { display:none; }
    .ct-tab { padding:12px 20px; font-family:var(--mono); font-size:12px; color:var(--muted); cursor:pointer; border:none; background:none; border-bottom:2px solid transparent; margin-bottom:-1px; transition:color 0.15s,border-color 0.15s; letter-spacing:0.05em; white-space:nowrap; flex-shrink:0; }
    .ct-tab:hover { color:var(--text); }
    .ct-tab.active { color:var(--text); border-bottom-color:var(--text); }
    #ct-panels { max-width:720px; margin:0 auto; padding:32px 40px; }
    .ct-panel { display:none; }
    .ct-panel.active { display:block; }
    .ct-field { margin-bottom:20px; }
    .ct-label { display:block; font-family:var(--mono); font-size:11px; font-weight:500; letter-spacing:0.08em; color:var(--muted); text-transform:uppercase; margin-bottom:6px; }
    .ct-input, .ct-textarea { width:100%; padding:10px 12px; font-family:var(--mono); font-size:12px; line-height:1.6; color:var(--text); background:var(--surface); border:1px solid var(--border); border-radius:4px; outline:none; resize:vertical; transition:border-color 0.15s; }
    .ct-input:focus, .ct-textarea:focus { border-color:var(--text); }
    .ct-textarea { min-height:72px; }
    .ct-output { width:100%; padding:10px 12px; font-family:var(--mono); font-size:11px; line-height:1.7; color:var(--text); background:var(--bg); border:1px solid var(--border); border-radius:4px; word-break:break-all; min-height:40px; white-space:pre-wrap; }
    .ct-output-wrap { position:relative; }
    .ct-copy { position:absolute; top:6px; right:6px; padding:3px 8px; font-family:var(--mono); font-size:10px; color:var(--muted); background:var(--surface); border:1px solid var(--border); border-radius:3px; cursor:pointer; }
    .ct-copy:hover { color:var(--text); border-color:var(--text); }
    .ct-btn { padding:10px 20px; font-family:var(--mono); font-size:12px; font-weight:500; color:var(--bg); background:var(--text); border:none; border-radius:4px; cursor:pointer; transition:opacity 0.15s; }
    .ct-btn:hover { opacity:0.8; }
    .ct-time { margin-left:10px; font-family:var(--mono); font-size:11px; color:var(--muted); }
    .ct-badge { display:inline-block; padding:4px 10px; font-family:var(--mono); font-size:11px; font-weight:500; border-radius:3px; margin-top:8px; margin-right:6px; }
    .ct-badge.valid { background:var(--valid-bg); color:var(--success); }
    .ct-badge.invalid { background:var(--invalid-bg); color:var(--error); }
    .ct-step { margin:28px 0 12px; padding-top:20px; border-top:1px solid var(--border); font-family:var(--mono); font-size:12px; font-weight:500; letter-spacing:0.05em; }
    .ct-step:first-child { margin-top:0; padding-top:0; border-top:none; }
    .ct-note { margin:0 0 20px; font-size:12px; color:var(--muted); }
    .ct-keep-case .ct-label { text-transform:none; } /* σ や r が Σ や R に化けないように */
    @media (max-width:600px) { #ct-header, #ct-tabs { padding-left:16px; padding-right:16px; } #ct-panels { padding:24px 16px; } }
  `;
    document.head.appendChild(style);
    const link = document.createElement("link");
    link.rel = "stylesheet";
    link.href =
        "https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@300;400;500&family=DM+Sans:wght@300;400;500&display=swap";
    document.head.appendChild(link);
    // ── ヘルパー ──
    const el = (tag, cls = "", text = "") => {
        const e = document.createElement(tag);
        if (cls)
            e.className = cls;
        if (text)
            e.textContent = text;
        return e;
    };
    const addField = (parent, labelText, child) => {
        const f = el("div", "ct-field");
        f.appendChild(el("label", "ct-label", labelText));
        f.appendChild(child);
        parent.appendChild(f);
        return child;
    };
    const addOutput = (parent, labelText) => {
        const f = el("div", "ct-field");
        f.appendChild(el("label", "ct-label", labelText));
        const wrap = el("div", "ct-output-wrap");
        const out = el("div", "ct-output");
        out.textContent = "—";
        const copy = el("button", "ct-copy", "copy");
        copy.addEventListener("click", () => {
            if (out.textContent === "—")
                return;
            navigator.clipboard.writeText(out.textContent ?? "").then(() => {
                copy.textContent = "copied";
                setTimeout(() => (copy.textContent = "copy"), 1200);
            });
        });
        wrap.appendChild(out);
        wrap.appendChild(copy);
        f.appendChild(wrap);
        parent.appendChild(f);
        return out;
    };
    const mkTextarea = (placeholder = "", value = "") => {
        const t = el("textarea", "ct-textarea");
        t.placeholder = placeholder;
        t.value = value;
        return t;
    };
    const mkInput = (placeholder = "", value = "") => {
        const i = el("input", "ct-input");
        i.type = "text";
        i.placeholder = placeholder;
        i.value = value;
        return i;
    };
    const step = (parent, text) => parent.appendChild(el("div", "ct-step", text));
    const note = (parent, text) => parent.appendChild(el("p", "ct-note", text));
    const badge = (ok, yes = "✓ 署名有効", no = "✗ 署名無効") => `<span class="ct-badge ${ok ? "valid" : "invalid"}">${ok ? yes : no}</span>`;
    const errBadge = (e) => `<span class="ct-badge invalid">エラー: ${e.message}</span>`;
    // ボタン: 押したら再描画してから実行。時間はボタンの横と console に出す
    //   onError を渡さないと、エラーはボタンの横に出す
    const addBtn = (parent, text, label, onClick, prof = () => bls.prof) => {
        const f = el("div", "ct-field");
        const b = el("button", "ct-btn", text);
        const time = el("span", "ct-time");
        b.addEventListener("click", () => {
            time.textContent = "計算中...";
            setTimeout(async () => {
                console.time(label);
                const t0 = performance.now();
                try {
                    await onClick();
                    time.textContent = `${(performance.now() - t0).toFixed(1)} ms`;
                    const rows = {};
                    for (const [k, v] of Object.entries(prof()))
                        rows[k] = v.toFixed(2) + " ms";
                    if (Object.keys(rows).length)
                        console.table(rows);
                }
                catch (e) {
                    time.textContent = "エラー: " + e.message;
                }
                console.timeEnd(label);
            }, 0);
        });
        f.appendChild(b);
        f.appendChild(time);
        parent.appendChild(f);
        return f;
    };
    const lines = (t) => t.value
        .split("\n")
        .map((s) => s.trim())
        .filter((s) => s !== "");
    // ── ヘッダー ──
    const header = el("div");
    header.id = "ct-header";
    header.innerHTML = `<h1>BLS署名</h1><p>BLS12-381 / 公開鍵 G1 48byte・署名 G2 96byte / bigint だけで全部自前 · <a href="./webauthn.html">WebAuthn →</a></p>`;
    document.body.appendChild(header);
    const tabBar = el("div");
    tabBar.id = "ct-tabs";
    document.body.appendChild(tabBar);
    const panelContainer = el("div");
    panelContainer.id = "ct-panels";
    document.body.appendChild(panelContainer);
    const tabs = [];
    const panelEls = [];
    const addTab = (name, build) => {
        const tab = el("button", "ct-tab", name);
        tabBar.appendChild(tab);
        tabs.push(tab);
        const panel = el("div", "ct-panel");
        panelContainer.appendChild(panel);
        panelEls.push(panel);
        build(panel);
        tab.addEventListener("click", () => {
            tabs.forEach((t) => t.classList.remove("active"));
            panelEls.forEach((p) => p.classList.remove("active"));
            tab.classList.add("active");
            panel.classList.add("active");
        });
    };
    // ── keygen ──
    addTab("keygen", (p) => {
        const privOut = addOutput(p, "private key (hex)");
        const pubOut = addOutput(p, "public key (hex)");
        addBtn(p, "鍵を生成する", "鍵生成", () => {
            const kp = bls.generateKeyPair();
            privOut.textContent = kp.privateKey;
            pubOut.textContent = kp.publicKey;
        });
    });
    // ── priv→pub ──
    addTab("priv→pub", (p) => {
        const privIn = addField(p, "private key (hex)", mkInput("秘密鍵の hex (64文字)"));
        const out = addOutput(p, "public key (hex)");
        addBtn(p, "公開鍵を導出する", "公開鍵導出", () => {
            out.textContent = toHex(bls.getPublicKey(privIn.value.trim()));
        });
    });
    // ── sign ──
    addTab("sign", (p) => {
        const ta = addField(p, "message", mkTextarea("署名するメッセージ"));
        const privIn = addField(p, "private key (hex)", mkInput("秘密鍵の hex (64文字)"));
        const out = addOutput(p, "signature (hex)");
        addBtn(p, "署名する", "署名", () => {
            out.textContent = toHex(bls.sign(enc.encode(ta.value), privIn.value.trim()));
        });
    });
    // ── verify ──
    addTab("verify", (p) => {
        const ta = addField(p, "message", mkTextarea("検証するメッセージ"));
        const sigIn = addField(p, "signature (hex)", mkInput("署名の hex (192文字)"));
        const pubIn = addField(p, "public key (hex)", mkInput("公開鍵の hex (96文字)"));
        const res = el("div");
        addBtn(p, "検証する", "検証", () => {
            res.innerHTML = badge(bls.verify(enc.encode(ta.value), pubIn.value.trim(), sigIn.value.trim()));
        });
        p.appendChild(res);
    });
    // ── blind ──
    addTab("blind", (p) => {
        p.classList.add("ct-keep-case");
        note(p, "ブラインド署名: 署名者は中身を見ないまま署名する。目隠しを外すと普通の BLS 署名 sk·H(m) になり、署名者は自分がどれに署名したか結び付けられない。");
        step(p, "0. 署名者 (銀行) の鍵 ─ ブラインド署名専用");
        const skOut = addOutput(p, "署名者の private key (秘密)");
        const pkOut = addOutput(p, "署名者の public key (公開)");
        addBtn(p, "署名者の鍵を作る", "署名者の鍵", () => {
            const kp = bls.generateKeyPair();
            skOut.textContent = kp.privateKey;
            pkOut.textContent = kp.publicKey;
            bsSk.value = kp.privateKey;
        });
        step(p, "1. 利用者: 目隠しする  M' = r·H(m)");
        const msgIn = addField(p, "message", mkTextarea("署名してほしいメッセージ", "100円券 #0001"));
        const blindedOut = addOutput(p, "目隠しした値 M' (署名者に送る)");
        const rOut = addOutput(p, "r (手元に残す・秘密)");
        addBtn(p, "目隠しする", "目隠し", () => {
            const { blinded, r } = bls.blind(enc.encode(msgIn.value));
            blindedOut.textContent = toHex(blinded);
            rOut.textContent = toHex(r);
            bsIn.value = toHex(blinded);
            ubR.value = toHex(r);
        });
        step(p, "2. 署名者: 中身を見ずに署名する  σ' = sk·M'");
        note(p, "署名者に見えるのは M' だけ。メッセージも、最終的な署名も分からない。");
        const bsIn = addField(p, "受け取った M' (hex)", mkTextarea("目隠しした値"));
        const bsSk = addField(p, "署名者の private key (hex)", mkInput("署名者の秘密鍵"));
        const bsOut = addOutput(p, "σ' (利用者に返す)");
        addBtn(p, "中身を見ずに署名する", "ブラインド署名", () => {
            const s = toHex(bls.blindSign(bsIn.value.trim(), bsSk.value.trim()));
            bsOut.textContent = s;
            ubIn.value = s;
        });
        step(p, "3. 利用者: 目隠しを外す  σ = r⁻¹·σ'");
        const ubIn = addField(p, "署名者から返ってきた σ' (hex)", mkTextarea("署名者の返事"));
        const ubR = addField(p, "r (hex)", mkInput("目隠しに使った r"));
        const ubOut = addOutput(p, "署名 σ (普通の BLS 署名)");
        addBtn(p, "目隠しを外す", "目隠しを外す", () => {
            const s = toHex(bls.unblind(ubIn.value.trim(), ubR.value.trim()));
            ubOut.textContent = s;
            vSig.value = s;
            vPk.value = pkOut.textContent === "—" ? "" : pkOut.textContent ?? "";
            vMsg.value = msgIn.value;
        });
        step(p, "4. 誰でも: 普通の verify で検証する");
        const vMsg = addField(p, "message", mkTextarea("メッセージ"));
        const vSig = addField(p, "signature σ (hex)", mkInput("署名"));
        const vPk = addField(p, "署名者の public key (hex)", mkInput("署名者の公開鍵"));
        const vRes = el("div");
        addBtn(p, "検証する", "ブラインド署名の検証", () => {
            const ok = bls.verify(enc.encode(vMsg.value), vPk.value.trim(), vSig.value.trim());
            let html = badge(ok);
            // デモ用: 署名者の秘密鍵が手元にあれば、普通に署名した結果と同じか見せる
            const sk = bsSk.value.trim();
            if (sk && vSig.value.trim()) {
                try {
                    const same = toHex(bls.sign(enc.encode(vMsg.value), sk)) === vSig.value.trim();
                    html += badge(same, "= 普通に署名した結果と一致", "≠ 普通に署名した結果と違う");
                }
                catch { }
            }
            vRes.innerHTML = html;
        });
        p.appendChild(vRes);
    });
    // ── aggregate ──
    addTab("aggregate", (p) => {
        const ta = addField(p, "signatures (hex, 1行に1つ)", mkTextarea("署名を1行ずつ"));
        const out = addOutput(p, "aggregated signature (hex)");
        addBtn(p, "署名を集約する", "署名の集約", () => {
            out.textContent = toHex(bls.aggregateSignatures(lines(ta)));
        });
    });
    // ── agg verify ──
    addTab("agg verify", (p) => {
        note(p, "メッセージがそれぞれ違う場合 (NUL 方式なのでメッセージの重複は不可)");
        const msgs = addField(p, "messages (1行に1つ)", mkTextarea("メッセージを1行ずつ"));
        const pks = addField(p, "public keys (hex, 1行に1つ。メッセージと同じ順番)", mkTextarea("公開鍵を1行ずつ"));
        const sig = addField(p, "aggregated signature (hex)", mkInput("集約署名"));
        const res = el("div");
        addBtn(p, "検証する", "集約検証", () => {
            const ms = msgs.value.split("\n").filter((s) => s !== "").map((s) => enc.encode(s));
            res.innerHTML = badge(bls.aggregateVerify(ms, lines(pks), sig.value.trim()));
        });
        p.appendChild(res);
    });
    // ── fast agg ──
    addTab("fast agg", (p) => {
        note(p, "全員が同じメッセージに署名した場合。rogue key 攻撃があるので本来は POP とセットで使う");
        const msg = addField(p, "message", mkTextarea("メッセージ"));
        const pks = addField(p, "public keys (hex, 1行に1つ)", mkTextarea("公開鍵を1行ずつ"));
        const sig = addField(p, "aggregated signature (hex)", mkInput("集約署名"));
        const res = el("div");
        addBtn(p, "検証する", "集約検証 (同じメッセージ)", () => {
            res.innerHTML = badge(bls.fastAggregateVerify(enc.encode(msg.value), lines(pks), sig.value.trim()));
        });
        p.appendChild(res);
    });
    // ── batch (速さ比べ) ──
    addTab("batch", (p) => {
        note(p, "別々の署名をまとめて検証する速さ比べ。バッチ検証はランダム係数で最終冪1回にまとめる。");
        let items = [];
        let pool = null;
        const getPool = async () => (pool ??= await BLSPool.create());
        const nIn = addField(p, "件数", mkInput("32", "32"));
        const genOut = addOutput(p, "status");
        addBtn(p, "署名を作る", "署名を作る", () => {
            const n = Math.max(1, Number(nIn.value) || 32);
            items = [];
            for (let i = 0; i < n; i++) {
                const kp = bls.generateKeyPair();
                const msg = enc.encode("tx-" + i + "-" + Math.random());
                items.push({ msg, pk: kp.publicKey, sig: bls.sign(msg, kp.privateKey) });
            }
            genOut.textContent = `${n} 件できた`;
        });
        const res = addOutput(p, "結果");
        const log = [];
        const race = (text, label, fn, prof) => addBtn(p, text, label, async () => {
            if (!items.length)
                throw new Error("先に「署名を作る」");
            const t0 = performance.now();
            const ok = await fn();
            const ms = performance.now() - t0;
            log.unshift(`${ok ? "✓ 全部有効" : "✗ 不正あり"}  ${text}: ${ms.toFixed(0)} ms (1件あたり ${(ms / items.length).toFixed(2)} ms)`);
            res.textContent = log.slice(0, 8).join("\n");
        }, prof);
        race("1件ずつ verify", "1件ずつ verify", () => items.every((it) => bls.verify(it.msg, it.pk, it.sig)), () => ({}));
        race("バッチ検証 (1スレッド)", "バッチ検証", () => bls.verifyBatch(items));
        race("バッチ検証 (Worker 並列)", "バッチ検証 (Worker 並列)", async () => (await getPool()).verifyBatch(items), () => pool?.prof ?? {});
        race("1件だけ壊してバッチ検証 (Worker 並列)", "1件だけ壊してバッチ検証", async () => {
            const bad = items.map((x) => ({ ...x }));
            const j = Math.floor(Math.random() * bad.length);
            bad[j] = { ...bad[j], msg: enc.encode("改ざん") };
            console.log(`${j} 番目のメッセージを改ざん`);
            return (await getPool()).verifyBatch(bad);
        }, () => pool?.prof ?? {});
    });
    // 最初のタブをアクティブに
    tabs[0]?.classList.add("active");
    panelEls[0]?.classList.add("active");
})();
