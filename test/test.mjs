// 自前実装を @noble/curves と突き合わせるテスト
import { BLS, _internal as I, toHex, fromHex, DST_NUL } from "../dist/bls.js";
import { bls12_381 as nb } from "@noble/curves/bls12-381";

let fail = 0;
const ok = (name, cond) => {
  console.log(`${cond ? "ok  " : "FAIL"} ${name}`);
  if (!cond) fail++;
};
const enc = new TextEncoder();
const t = (label, fn) => {
  const s = performance.now();
  const r = fn();
  console.log(`     ${label}: ${(performance.now() - s).toFixed(0)} ms`);
  return r;
};

const { E1, E2, G1, G2, P, R } = I;
ok("HARD_EXP は割り切れる", (P ** 4n - P ** 2n + 1n) % R === 0n);
ok("G1 は曲線上", E1.isOnCurve(E1.toAffine(G1)));
ok("G2 は曲線上", E2.isOnCurve(E2.toAffine(G2)));
ok("r·G1 = O", E1.inSubgroupSlow(G1));
ok("r·G2 = O", E2.inSubgroupSlow(G2));

// ─── 高速化した部品を素朴版と突き合わせる ───
const rnd = () => { const b = new Uint8Array(48); crypto.getRandomValues(b); let r = 0n; for (const x of b) r = (r << 8n) | BigInt(x); return r; };
{
  // 円分二乗 = 普通の二乗 (円分部分群の元で)
  const f0 = I.millerLoop([[E1.toAffine(G1), E2.toAffine(G2)]]);
  let t = I.f12mul(I.f12conj(f0), I.f12inv(f0));
  t = I.f12mul(I.f12frob(t, 2), t);
  ok("cycSqr = f12sqr (円分部分群)", I.f12eq(I.cycSqr(t), I.f12sqr(t)));
  ok("cycExp (Karabina 圧縮) = cycExp (Granger–Scott)", I.f12eq(I.cycExp(t), I.cycExpGS(t)));
  ok("cycExp(1) = 1", I.f12eq(I.cycExp(I.F12_1), I.F12_1));
  // 最終冪 = 素朴版の 3 乗
  const slow = I.f12pow(t, I.HARD_EXP);
  ok("finalExp = (素朴な最終冪)^3", I.f12eq(I.finalExp(f0), I.f12mul(I.f12mul(slow, slow), slow)));
}
{
  // Fp2 の平方根: 平方剰余なら √ が合う、非剰余なら null
  let good = true, nonres = 0;
  for (let i = 0; i < 40; i++) {
    const a = [rnd() % P, rnd() % P];
    const sq = I.f2sqr(a);
    const r = I.f2sqrt(sq);
    if (!r || I.f2sqr(r).join() !== sq.join()) good = false;
    const b = [rnd() % P, rnd() % P];
    const rb = I.f2sqrt(b);
    if (rb === null) nonres++; else if (I.f2sqr(rb).join() !== b.join()) good = false;
  }
  ok(`f2sqrt (平方剰余40個 OK, ランダム40個中 非剰余 ${nonres} 個)`, good && nonres > 5 && nonres < 35);
  let lg = true;
  for (let i = 0; i < 40; i++) { const a = rnd() % P; const s = (a * a) % P; if (I.fpLegendre(s) !== 1) lg = false; }
  ok("fpLegendre(平方) = 1", lg && I.fpLegendre(0n) === 0 && I.fpLegendre(P - 1n) === -1);
}
for (let i = 0; i < 3; i++) {
  const k = rnd() % R;
  ok(`g1MulBase = 素朴なスカラー倍 #${i}`, E1.eq(I.g1MulBase(k), E1.mul(G1, k)));
  ok(`g2MulGLS = 素朴なスカラー倍 #${i}`, E2.eq(I.g2MulGLS(G2, k), E2.mul(G2, k)));
  // 部分群に入ってない曲線上の点
  let p1; for (let x = rnd() % P; ; x++) { const y = I.f2sqrt([(x * x * x + 4n) % P, 0n]); if (y && y[1] === 0n) { p1 = [x, y[0], 1n]; break; } }
  ok(`G1 部分群チェック (外の点) #${i}`, I.g1InSubgroup(p1) === E1.inSubgroupSlow(p1) && !I.g1InSubgroup(p1));
  const in1 = E1.mul(p1, 0x396c8c005555e1568c00aaab0000aaabn); // cofactor h1
  ok(`G1 部分群チェック (中の点) #${i}`, I.g1InSubgroup(in1) && E1.inSubgroupSlow(in1));
  let p2; for (let x0 = rnd() % P; ; x0++) { const x = [x0, 1n]; const y = I.f2sqrt(I.E2.F.add(I.E2.F.mul(I.f2sqr(x), x), [4n, 4n])); if (y) { p2 = [x, y, [1n, 0n]]; break; } }
  ok(`G2 部分群チェック (外の点) #${i}`, I.g2InSubgroup(p2) === E2.inSubgroupSlow(p2) && !I.g2InSubgroup(p2));
  const cc = I.clearCofactorG2(p2);
  ok(`clearCofactor(ψ版) = h_eff 倍 #${i}`, E2.eq(cc, E2.mul(p2, I.H_EFF_G2)));
  ok(`G2 部分群チェック (中の点) #${i}`, I.g2InSubgroup(cc) && E2.inSubgroupSlow(cc));
}

// ペアリングの双線形性
const e = t("pairing", () => I.pairing(G1, G2));
{
  const ne = nb.pairing(nb.G1.ProjectivePoint.BASE, nb.G2.ProjectivePoint.BASE);
  const flat = (f) => [f.c0.c0.c0, f.c0.c0.c1, f.c0.c1.c0, f.c0.c1.c1, f.c0.c2.c0, f.c0.c2.c1, f.c1.c0.c0, f.c1.c0.c1, f.c1.c1.c0, f.c1.c1.c1, f.c1.c2.c0, f.c1.c2.c1];
  ok("e(G1,G2) = noble の pairing", flat(ne).join() === e.flat(2).join());
}
ok("e(G1,G2) ≠ 1", !I.f12eq(e, I.F12_1));
ok("e(G1,G2)^r = 1", I.f12eq(I.f12pow(e, R), I.F12_1));
const a = 123456789n, b = 987654321n;
const eab = I.pairing(E1.mul(G1, a), E2.mul(G2, b));
ok("e(aG1, bG2) = e(G1,G2)^(ab)", I.f12eq(eab, I.f12pow(e, a * b)));
ok("e(aG1, bG2) = e(abG1, G2)", I.f12eq(eab, I.pairing(E1.mul(G1, a * b), G2)));

// シリアライズ (noble と一致するか)
ok("G1 bytes = noble", toHex(I.g1ToBytes(G1)) === nb.G1.ProjectivePoint.BASE.toHex(true));
ok("G2 bytes = noble", toHex(I.g2ToBytes(G2)) === nb.G2.ProjectivePoint.BASE.toHex(true));
for (const k of [2n, 3n, 0xdeadbeefn, R - 1n]) {
  ok(`(${k.toString(16).slice(0, 8)})·G1 bytes = noble`,
    toHex(I.g1ToBytes(E1.mul(G1, k))) === nb.G1.ProjectivePoint.BASE.multiply(k).toHex(true));
  ok(`(${k.toString(16).slice(0, 8)})·G2 bytes = noble`,
    toHex(I.g2ToBytes(E2.mul(G2, k))) === nb.G2.ProjectivePoint.BASE.multiply(k).toHex(true));
}

// hash-to-curve: RFC 9380 J.10.1 のテストベクタ (QUUX DST)
{
  const dst = enc.encode("QUUX-V01-CS02-with-BLS12381G2_XMD:SHA-256_SSWU_RO_");
  const h = I.E2.toAffine(I.hashToG2(enc.encode(""), dst));
  ok("hash_to_G2('') RFC ベクタ x.c0",
    h[0][0] === 0x0141ebfbdca40eb85b87142e130ab689c673cf60f1a3e98d69335266f30d9b8d4ac44c1038e9dcdd5393faf5c41fb78an);
  for (const msg of ["", "abc", "abcdef0123456789", "a".repeat(300)]) {
    const ours = toHex(I.g2ToBytes(I.hashToG2(enc.encode(msg), dst)));
    const theirs = nb.G2.hashToCurve(enc.encode(msg), { DST: dst }).toHex(true);
    ok(`hash_to_G2(${JSON.stringify(msg.slice(0, 10))}) = noble`, ours === theirs);
  }
}

// 署名
const bls = new BLS();
const kp = t("keygen", () => bls.generateKeyPair());
ok("pk = noble", kp.publicKey === toHex(nb.getPublicKey(fromHex(kp.privateKey))));
const msg = enc.encode("Hello, BLS!");
const sig = t("sign", () => toHex(bls.sign(msg, kp.privateKey)));
ok("sig = noble", sig === toHex(nb.sign(msg, fromHex(kp.privateKey))));
ok("verify ok", t("verify", () => bls.verify(msg, kp.publicKey, sig)));
ok("noble.verify(自前署名)", nb.verify(fromHex(sig), msg, fromHex(kp.publicKey)));
ok("改ざんメッセージは NG", !bls.verify(enc.encode("Hello, BLS?"), kp.publicKey, sig));
const kp2 = bls.generateKeyPair();
ok("別の鍵は NG", !bls.verify(msg, kp2.publicKey, sig));
ok("壊れた hex は NG", !bls.verify(msg, kp.publicKey, sig.slice(0, -2) + "00"));

// 集約
const keys = [kp, kp2, bls.generateKeyPair()];
const msgs = ["msg-0", "msg-1", "msg-2"].map((s) => enc.encode(s));
const sigs = keys.map((k, i) => bls.sign(msgs[i], k.privateKey));
const agg = bls.aggregateSignatures(sigs);
ok("aggSig = noble", toHex(agg) === toHex(nb.aggregateSignatures(sigs)));
ok("aggregateVerify ok", t("aggregateVerify(3)", () => bls.aggregateVerify(msgs, keys.map((k) => k.publicKey), agg)));
ok("aggregateVerify 入れ替え NG", !bls.aggregateVerify([msgs[1], msgs[0], msgs[2]], keys.map((k) => k.publicKey), agg));
ok("aggregateVerify 同じメッセージ NG (NUL)", !bls.aggregateVerify([msgs[0], msgs[0]], [keys[0].publicKey, keys[1].publicKey], agg));
const same = keys.map((k) => bls.sign(msg, k.privateKey));
const aggSame = bls.aggregateSignatures(same);
ok("fastAggregateVerify ok", bls.fastAggregateVerify(msg, keys.map((k) => k.publicKey), aggSame));
ok("fastAggregateVerify 1人抜け NG", !bls.fastAggregateVerify(msg, keys.slice(0, 2).map((k) => k.publicKey), aggSame));
ok("aggPk = noble", toHex(bls.aggregatePublicKeys(keys.map((k) => k.publicKey))) ===
  toHex(nb.aggregatePublicKeys(keys.map((k) => fromHex(k.publicKey)))));

// ブラインド署名
{
  const signer = bls.generateKeyPair();
  const m = enc.encode("100円券 #0001");
  const { blinded, r } = t("blind", () => bls.blind(m));
  const blindSig = t("blindSign", () => bls.blindSign(blinded, signer.privateKey));
  const s = t("unblind", () => bls.unblind(blindSig, r));
  ok("目隠しを外した署名 = 普通の署名 (sk·H(m))", toHex(s) === toHex(bls.sign(m, signer.privateKey)));
  ok("目隠しを外した署名を verify で検証できる", bls.verify(m, signer.publicKey, s));
  ok("noble でも検証できる", nb.verify(s, m, fromHex(signer.publicKey)));
  ok("署名者が見た値は H(m) とも最終の署名とも違う", toHex(blinded) !== toHex(bls.hashToPoint(m)) && toHex(blindSig) !== toHex(s));
  const b2 = bls.blind(m);
  ok("同じメッセージでも毎回違う目隠しになる", toHex(b2.blinded) !== toHex(blinded));
  ok("別の r で外すと無効な署名になる", !bls.verify(m, signer.publicKey, bls.unblind(blindSig, b2.r)));
  ok("別のメッセージとしては通らない", !bls.verify(enc.encode("1000円券 #0001"), signer.publicKey, s));
}

// バッチ検証
{
  const ks = Array.from({ length: 5 }, () => bls.generateKeyPair());
  const ms = ks.map((_, i) => enc.encode("batch-" + i));
  const items = ks.map((k, i) => ({ msg: ms[i], pk: k.publicKey, sig: bls.sign(ms[i], k.privateKey) }));
  ok("verifyBatch 5件 ok", t("verifyBatch(5)", () => bls.verifyBatch(items)));
  const bad = items.map((x) => ({ ...x }));
  bad[2] = { ...bad[2], sig: items[3].sig };
  ok("verifyBatch 1件だけ不正なら NG", !bls.verifyBatch(bad));
  // σ1 + Δ, σ2 - Δ: 素朴に足すだけだと打ち消し合って通ってしまう組。ランダム係数で見抜く
  const D = E2.mul(G2, 42n);
  const s1 = I.g2ToBytes(E2.add(I.g2FromBytes(items[0].sig), D));
  const s2 = I.g2ToBytes(E2.add(I.g2FromBytes(items[1].sig), E2.neg(D)));
  const cancel = items.map((x) => ({ ...x }));
  cancel[0] = { ...cancel[0], sig: s1 };
  cancel[1] = { ...cancel[1], sig: s2 };
  const naiveSum = bls.aggregateSignatures(cancel.map((x) => x.sig));
  ok("打ち消し合う2件: 素朴な集約だと通ってしまう", bls.aggregateVerify(ms, ks.map((k) => k.publicKey), naiveSum));
  ok("打ち消し合う2件: verifyBatch は見抜く", !bls.verifyBatch(cancel));
  ok("verifyBatch 空は false", !bls.verifyBatch([]));
}

console.log(fail ? `\n${fail} 件失敗` : "\n全部 ok");
process.exit(fail ? 1 : 0);
