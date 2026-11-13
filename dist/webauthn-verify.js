// WebAuthn (FIDO2) のログイン署名 (assertion) を検証する
//   ブラウザでも Node でも動く (WebCrypto だけ使う)
//   対応: ES256 (ECDSA P-256) / EdDSA (Ed25519)
const enc = new TextEncoder();
const dec = new TextDecoder();
// ─── base64 / base64url / PEM ─────────────────────────────────────────
export const b64urlEncode = (b) => {
    let s = "";
    for (const x of b)
        s += String.fromCharCode(x);
    return btoa(s).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
};
// base64 でも base64url でも読む
export const b64Decode = (s) => {
    s = s.trim().replace(/-/g, "+").replace(/_/g, "/");
    while (s.length % 4)
        s += "=";
    return Uint8Array.from(atob(s), (c) => c.charCodeAt(0));
};
export const derToPem = (der, label = "PUBLIC KEY") => {
    let s = "";
    for (const x of der)
        s += String.fromCharCode(x);
    const b64 = btoa(s).replace(/(.{64})/g, "$1\n").trim();
    return `-----BEGIN ${label}-----\n${b64}\n-----END ${label}-----`;
};
export const pemToDer = (pem) => b64Decode(pem.replace(/-----[^-]+-----/g, "").replace(/\s+/g, ""));
const eq = (a, b) => a.length === b.length && a.every((x, i) => x === b[i]);
const concat = (a, b) => {
    const out = new Uint8Array(a.length + b.length);
    out.set(a);
    out.set(b, a.length);
    return out;
};
// TS の BufferSource 型に合わせるため ArrayBuffer にコピー
const ab = (u) => u.slice().buffer;
const sha256 = async (b) => new Uint8Array(await crypto.subtle.digest("SHA-256", ab(b)));
// ECDSA の DER 署名 (SEQUENCE { INTEGER r, INTEGER s }) → r||s (各 32 バイト)
// WebAuthn は DER で返すが、WebCrypto は r||s しか受け付けない
export const derSigToRaw = (der, n = 32) => {
    let i = 0;
    if (der[i++] !== 0x30)
        throw new Error("署名が DER の SEQUENCE じゃない");
    if (der[i] & 0x80)
        i += (der[i] & 0x7f) + 1;
    else
        i++;
    const readInt = () => {
        if (der[i++] !== 0x02)
            throw new Error("署名が DER の INTEGER じゃない");
        const len = der[i++];
        let v = der.subarray(i, i + len);
        i += len;
        while (v.length > 0 && v[0] === 0)
            v = v.subarray(1); // 符号用の 0x00 を外す
        if (v.length > n)
            throw new Error("署名の整数が長すぎ");
        const out = new Uint8Array(n);
        out.set(v, n - v.length);
        return out;
    };
    const r = readInt();
    const s = readInt();
    return concat(r, s);
};
export const parseAuthData = (ad) => {
    if (ad.length < 37)
        throw new Error("authenticatorData が短すぎ");
    const f = ad[32];
    const flags = {
        UP: !!(f & 0x01),
        UV: !!(f & 0x04),
        BE: !!(f & 0x08),
        BS: !!(f & 0x10),
        AT: !!(f & 0x40),
        ED: !!(f & 0x80),
    };
    const signCount = new DataView(ad.buffer, ad.byteOffset + 33, 4).getUint32(0);
    let aaguid = null;
    if (flags.AT && ad.length >= 53) {
        const h = Array.from(ad.subarray(37, 53), (x) => x.toString(16).padStart(2, "0")).join("");
        aaguid = [h.slice(0, 8), h.slice(8, 12), h.slice(12, 16), h.slice(16, 20), h.slice(20)].join("-");
    }
    return { rpIdHash: ad.subarray(0, 32), flags, signCount, aaguid };
};
const importKey = async (spki) => {
    try {
        const key = await crypto.subtle.importKey("spki", ab(spki), { name: "ECDSA", namedCurve: "P-256" }, false, ["verify"]);
        return { key, alg: "ES256" };
    }
    catch {
        const key = await crypto.subtle.importKey("spki", ab(spki), { name: "Ed25519" }, false, [
            "verify",
        ]);
        return { key, alg: "EdDSA" };
    }
};
export async function verifyAssertion(a, expect) {
    const checks = [];
    const add = (name, ok, detail) => checks.push({ name, ok, detail });
    const ad = b64Decode(a.authenticatorData);
    const cdRaw = b64Decode(a.clientDataJSON);
    const cd = JSON.parse(dec.decode(cdRaw));
    const parsed = parseAuthData(ad);
    add("type", cd.type === "webauthn.get", `${cd.type} (ログインの署名なら webauthn.get)`);
    const gotChal = b64Decode(cd.challenge);
    add("チャレンジ", eq(gotChal, expect.challenge), `署名されたチャレンジ: "${dec.decode(gotChal)}"`);
    add("オリジン", cd.origin === expect.origin, `${cd.origin} (期待: ${expect.origin})`);
    if (cd.crossOrigin)
        add("crossOrigin", false, "iframe 経由の署名");
    const rpHash = await sha256(enc.encode(expect.rpId));
    add("rpIdHash", eq(parsed.rpIdHash, rpHash), `SHA-256("${expect.rpId}") と比較`);
    add("ユーザーが触れた (UP)", parsed.flags.UP, `flags=0x${ad[32].toString(16).padStart(2, "0")}`);
    // 署名対象: authenticatorData || SHA-256(clientDataJSON)
    const msg = concat(ad, await sha256(cdRaw));
    const sigBytes = b64Decode(a.signature);
    try {
        const { key, alg } = await importKey(pemToDer(a.publicKeyPem));
        const ok = alg === "ES256"
            ? await crypto.subtle.verify({ name: "ECDSA", hash: "SHA-256" }, key, ab(derSigToRaw(sigBytes)), ab(msg))
            : await crypto.subtle.verify({ name: "Ed25519" }, key, ab(sigBytes), ab(msg));
        add("署名", ok, `${alg} で authenticatorData || SHA-256(clientDataJSON) を検証`);
    }
    catch (e) {
        add("署名", false, "検証できない: " + e.message);
    }
    return {
        ok: checks.every((c) => c.ok),
        checks,
        flags: parsed.flags,
        signCount: parsed.signCount,
        clientData: cd,
    };
}
