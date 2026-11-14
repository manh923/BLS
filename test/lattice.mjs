// 格子署名のおもちゃ: 各版の正しさとサイズ
import { VARIANTS, keygen, sign, verify, ntt, invNtt, schoolbookMul, Q, info } from "../dist/lattice.js";

let fail = 0;
const ok = (name, cond) => { console.log(`${cond ? "ok  " : "FAIL"} ${name}`); if (!cond) fail++; };
const enc = new TextEncoder();

// NTT の掛け算 = 素朴な掛け算 (X^256 = -1)
const rp = () => Int32Array.from({ length: 256 }, () => Math.floor(Math.random() * Q));
const a = rp(), b = rp();
const viaNtt = invNtt(ntt(a).map((x, i) => Number((BigInt(x) * BigInt(ntt(b)[i])) % BigInt(Q))));
ok("NTT の掛け算 = 素朴な掛け算", viaNtt.every((x, i) => x === schoolbookMul(a, b)[i]));
ok("invNtt(ntt(a)) = a", invNtt(ntt(a)).every((x, i) => x === a[i]));

const SIGS = Number(process.argv[2] ?? 20);
const rows = [];
for (const P of VARIANTS) {
  const { pk, sk } = keygen(P);
  let total = 0, attempts = 0, tSign = 0, tVer = 0, min = Infinity, max = 0, good = true;
  let attemptsSum = 0;
  for (let i = 0; i < SIGS; i++) {
    const m = enc.encode(`msg-${P.id}-${i}`);
    let s = performance.now();
    const sig = sign(sk, m);
    tSign += performance.now() - s;
    const { lastAttempts } = await import("../dist/lattice.js");
    attemptsSum += lastAttempts;
    s = performance.now();
    if (!verify(P, pk, m, sig)) good = false;
    tVer += performance.now() - s;
    total += sig.length; min = Math.min(min, sig.length); max = Math.max(max, sig.length);
    if (i === 0) {
      ok(`${P.id} 別のメッセージは NG`, !verify(P, pk, enc.encode("other"), sig));
      const bad = sig.slice(); bad[40] ^= 1;
      ok(`${P.id} 署名を1ビット壊すと NG`, !verify(P, pk, m, bad));
      ok(`${P.id} 末尾にゴミを足すと NG`, !verify(P, pk, m, Uint8Array.from([...sig, 0])));
      ok(`${P.id} 別の鍵では NG`, !verify(P, keygen(P).pk, m, sig));
    }
  }
  ok(`${P.id} ${SIGS} 回 署名→検証 OK`, good);
  const inf = info(P);
  rows.push({
    版: P.name,
    "署名 (B)": min === max ? `${min}` : `${Math.round(total / SIGS)} (${min}〜${max})`,
    "公開鍵 (B)": pk.length,
    "合計 (B)": Math.round(total / SIGS) + pk.length,
    "やり直し平均": +(attemptsSum / SIGS).toFixed(1),
    "署名 ms": +(tSign / SIGS).toFixed(1),
    "検証 ms": +(tVer / SIGS).toFixed(1),
    σ: inf.sigma ?? "-",
  });
}
console.table(rows);
const v2 = rows[2];
ok("V2 のサイズは ML-DSA-44 と同じ (署名 2420B / 公開鍵 1312B)", v2["署名 (B)"] === "2420" && v2["公開鍵 (B)"] === 1312);

console.log(fail ? `\n${fail} 件失敗` : "\n格子 全部 ok");
process.exit(fail ? 1 : 0);
