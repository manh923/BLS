// cryptos の Dilithium2 (コピー) と、それを改造して小さくした版の比較
import { Dilithium2 } from "../dist/dilithium/Dilithium2.js";
import { Dilithium2Small } from "../dist/dilithium/Dilithium2Small.js";

let fail = 0;
const ok = (name, cond) => { console.log(`${cond ? "ok  " : "FAIL"} ${name}`); if (!cond) fail++; };
const enc = new TextEncoder();
const N = Number(process.argv[2] ?? 8);

const rows = [];
for (const [name, d] of [
  ["元の Dilithium2 (cryptos)", new Dilithium2()],
  ["改造版 η=2 (ガウス + ライス符号)", new Dilithium2Small({ eta: 2 })],
  ["改造版 η=1", new Dilithium2Small({ eta: 1 })],
  ["改造版 η=1 T=180 + ヒント圧縮", new Dilithium2Small({ eta: 1, T: 180, hintGolomb: true })],
  ["改造版 η=1 T=180 + ヒント圧縮 + α=3", new Dilithium2Small({ eta: 1, T: 180, alpha: 3, hintGolomb: true })],
]) {
  const { pk, sk } = d.keyGen();
  let size = 0, min = Infinity, max = 0, att = 0, ts = 0, tv = 0, good = true;
  for (let i = 0; i < N; i++) {
    const m = enc.encode(`${name}-${i}`);
    let t = performance.now();
    const sig = d.sign(sk, m);
    ts += performance.now() - t;
    att += d.lastAttempts ?? 0;
    t = performance.now();
    if (!sig || !d.verify(pk, m, sig)) good = false;
    tv += performance.now() - t;
    size += sig.length; min = Math.min(min, sig.length); max = Math.max(max, sig.length);
    if (i === 0) {
      ok(`${name}: 別のメッセージは NG`, !d.verify(pk, enc.encode("other"), sig));
      const bad = sig.slice(); bad[100] ^= 1;
      ok(`${name}: 署名の z を1ビット壊すと NG`, !d.verify(pk, m, bad));
      ok(`${name}: 同じメッセージなら同じ署名 (決定的)`, Buffer.from(d.sign(sk, m)).equals(Buffer.from(sig)));
    }
  }
  ok(`${name}: ${N} 回 署名→検証 OK`, good);
  rows.push({
    版: name,
    "署名 (B)": min === max ? min : `${Math.round(size / N)} (${min}〜${max})`,
    "公開鍵 (B)": pk.length,
    "秘密鍵 (B)": sk.length,
    やり直し: att ? +(att / N).toFixed(1) : "-",
    "署名 ms": Math.round(ts / N),
    "検証 ms": Math.round(tv / N),
  });
}
console.table(rows);
ok("元の Dilithium2 は ML-DSA-44 と同じサイズ (署名 2420B / 公開鍵 1312B / 秘密鍵 2560B)",
  rows[0]["署名 (B)"] === 2420 && rows[0]["公開鍵 (B)"] === 1312 && rows[0]["秘密鍵 (B)"] === 2560);
console.log(fail ? `\n${fail} 件失敗` : "\nDilithium 全部 ok");
process.exit(fail ? 1 : 0);
