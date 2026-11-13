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
ok("r·G1 = O", E1.inSubgroup(G1));
ok("r·G2 = O", E2.inSubgroup(G2));

// ペアリングの双線形性
const e = t("pairing", () => I.pairing(G1, G2));
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

console.log(fail ? `\n${fail} 件失敗` : "\n全部 ok");
process.exit(fail ? 1 : 0);
