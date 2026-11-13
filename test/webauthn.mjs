// WebAuthn 検証のテスト: demo.yubico.com で実際に YubiKey が作った署名を使う
import { verifyAssertion, b64Decode, derSigToRaw } from "../dist/webauthn-verify.js";

let fail = 0;
const ok = (name, cond) => {
  console.log(`${cond ? "ok  " : "FAIL"} ${name}`);
  if (!cond) fail++;
};

const real = {
  publicKeyPem: `-----BEGIN PUBLIC KEY-----
MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEaHmNrZnNt3j/gD671Ce9sXBC3mM0
0hd7KyGDd1RpbroZWh/Gm6UsbHNHWQgtu+oAbZ8SB2NSgP6lsNYTNlYpyA==
-----END PUBLIC KEY-----`,
  authenticatorData: "xGzvgq0bVGR3WR0Aiwh1nsPm0uy085R0v+ppaZJdA7cBAAAACQ==",
  clientDataJSON:
    "eyJ0eXBlIjoid2ViYXV0aG4uZ2V0IiwiY2hhbGxlbmdlIjoiQmdnS294b3cxMWxYUGhGM3habkZobmRtdWpQcy1Fd0dHa2JubVpRUzNDZyIsIm9yaWdpbiI6Imh0dHBzOi8vZGVtby55dWJpY28uY29tIiwiY3Jvc3NPcmlnaW4iOmZhbHNlLCJvdGhlcl9rZXlzX2Nhbl9iZV9hZGRlZF9oZXJlIjoiZG8gbm90IGNvbXBhcmUgY2xpZW50RGF0YUpTT04gYWdhaW5zdCBhIHRlbXBsYXRlLiBTZWUgaHR0cHM6Ly9nb28uZ2wveWFiUGV4In0=",
  signature: "MEYCIQCyPeWspIQfRbrHLvHHpOGW4KA+Qjo5q29Jr6sECZP1WwIhAKCCbvgltU68fYkGaEBKwrX2i2jqk1vuItnDNwQ8X7zj",
};
const expect = {
  challenge: b64Decode("BggKoxow11lXPhF3xZnFhndmujPs+EwGGkbnmZQS3Cg="),
  origin: "https://demo.yubico.com",
  rpId: "demo.yubico.com",
};

const r = await verifyAssertion(real, expect);
ok("本物の YubiKey 署名 (demo.yubico.com) が通る", r.ok);
ok("signCount = 9", r.signCount === 9);

const r2 = await verifyAssertion(real, { ...expect, challenge: new Uint8Array(32) });
ok("チャレンジが違うと NG", !r2.ok && !r2.checks.find((c) => c.name === "チャレンジ").ok);
const r3 = await verifyAssertion(real, { ...expect, origin: "https://evil.example" });
ok("オリジンが違うと NG", !r3.ok);
const r4 = await verifyAssertion(real, { ...expect, rpId: "evil.example" });
ok("rpId が違うと NG", !r4.ok);
const ad = b64Decode(real.authenticatorData);
ad[36] ^= 1;
const r5 = await verifyAssertion({ ...real, authenticatorData: btoa(String.fromCharCode(...ad)) }, expect);
ok("カウンタを1ビット改ざんすると署名 NG", !r5.checks.find((c) => c.name === "署名").ok);

// DER → r||s (r が 33 バイト = 先頭 0x00 付き のケース)
const raw = derSigToRaw(b64Decode(real.signature));
ok("DER 署名 → 64 バイト", raw.length === 64 && raw[0] === 0xb2);

console.log(fail ? `\n${fail} 件失敗` : "\nWebAuthn 全部 ok");
process.exit(fail ? 1 : 0);
