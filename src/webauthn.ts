import {
  b64Decode,
  b64urlEncode,
  derToPem,
  parseAuthData,
  verifyAssertion,
} from "./webauthn-verify.js";

const $ = <T extends HTMLElement = HTMLTextAreaElement>(id: string) =>
  document.getElementById(id) as T;
const enc = new TextEncoder();
const rand = (n: number) => crypto.getRandomValues(new Uint8Array(n));
const randHex = (n: number) =>
  Array.from(rand(n), (x) => x.toString(16).padStart(2, "0")).join("");

const rpId = location.hostname;
$<HTMLElement>("rpid").textContent = rpId;
$<HTMLElement>("origin").textContent = location.origin;

// 前回登録した鍵を覚えておく (使えなくても動く)
const store = {
  get: (k: string) => {
    try {
      return localStorage.getItem(k) ?? "";
    } catch {
      return "";
    }
  },
  set: (k: string, v: string) => {
    try {
      localStorage.setItem(k, v);
    } catch {}
  },
};
$("sign-id").value = store.get("webauthn-cred-id");
$("sign-pem").value = store.get("webauthn-pem");
$<HTMLInputElement>("sign-chal").value = randHex(16);

const status = (id: string, s: string) => ($<HTMLElement>(id).textContent = s);

if (!window.PublicKeyCredential) {
  status("reg-status", "このブラウザは WebAuthn に対応してない (HTTPS か localhost で開く)");
}

// ─── 1. 登録 ─────────────────────────────────────────────────────────
$("reg").addEventListener("click", async () => {
  status("reg-status", "キーに触れて...");
  try {
    const name = $<HTMLInputElement>("reg-user").value || "me";
    const cred = (await navigator.credentials.create({
      publicKey: {
        challenge: rand(32),
        rp: { name: "BLS demo", id: rpId },
        user: { id: rand(16), name, displayName: name },
        pubKeyCredParams: [
          { type: "public-key", alg: -7 }, // ES256
          { type: "public-key", alg: -8 }, // EdDSA
        ],
        attestation: "direct",
        authenticatorSelection: { userVerification: "discouraged", residentKey: "discouraged" },
        timeout: 120000,
      },
    })) as PublicKeyCredential;
    const res = cred.response as AuthenticatorAttestationResponse;
    const spki = res.getPublicKey();
    if (!spki) throw new Error("公開鍵が取れない (未対応のアルゴリズム)");
    const pem = derToPem(new Uint8Array(spki));
    const alg = res.getPublicKeyAlgorithm();
    const { aaguid } = parseAuthData(new Uint8Array(res.getAuthenticatorData()));
    const id = b64urlEncode(new Uint8Array(cred.rawId));

    $("reg-id").value = id;
    $("reg-pem").value = pem;
    $("reg-att").value = b64urlEncode(new Uint8Array(res.attestationObject));
    $<HTMLElement>("reg-alg").textContent =
      alg === -7 ? "ES256 (ECDSA P-256)" : alg === -8 ? "EdDSA (Ed25519)" : String(alg);
    $<HTMLElement>("reg-aaguid").textContent = aaguid ?? "—";
    $("sign-id").value = id;
    $("sign-pem").value = pem;
    store.set("webauthn-cred-id", id);
    store.set("webauthn-pem", pem);
    status("reg-status", "登録できた");
  } catch (e) {
    status("reg-status", "エラー: " + (e as Error).message);
  }
});

// ─── 2. 署名 ─────────────────────────────────────────────────────────
$("sign").addEventListener("click", async () => {
  status("sign-status", "キーに触れて...");
  try {
    const challenge = $<HTMLInputElement>("sign-chal").value;
    if (!challenge) throw new Error("チャレンジが空");
    const id = $("sign-id").value.trim();
    if (!id) throw new Error("クレデンシャル ID が空 (先に登録する)");
    const cred = (await navigator.credentials.get({
      publicKey: {
        challenge: enc.encode(challenge),
        rpId,
        allowCredentials: [{ type: "public-key", id: b64Decode(id).slice().buffer as ArrayBuffer }],
        userVerification: "discouraged",
        timeout: 120000,
      },
    })) as PublicKeyCredential;
    const res = cred.response as AuthenticatorAssertionResponse;
    const out = {
      rpId,
      origin: location.origin,
      challenge,
      credentialId: b64urlEncode(new Uint8Array(cred.rawId)),
      publicKeyPem: $("sign-pem").value.trim(),
      authenticatorData: b64urlEncode(new Uint8Array(res.authenticatorData)),
      clientDataJSON: b64urlEncode(new Uint8Array(res.clientDataJSON)),
      signature: b64urlEncode(new Uint8Array(res.signature)),
    };
    $("sign-out").value = JSON.stringify(out, null, 2);
    // その場で自分でも検証しておく
    const r = await verifyAssertion(out, {
      challenge: enc.encode(challenge),
      origin: location.origin,
      rpId,
    });
    status("sign-status", r.ok ? "署名できた (自己検証 OK)" : "署名できたけど自己検証 NG");
  } catch (e) {
    status("sign-status", "エラー: " + (e as Error).message);
  }
});

// ─── 3. 検証 ─────────────────────────────────────────────────────────
$("ver").addEventListener("click", async () => {
  const out = $<HTMLElement>("ver-out");
  try {
    const j = JSON.parse($("ver-in").value);
    const chal = $<HTMLInputElement>("ver-chal").value;
    if (!chal) throw new Error("自分が出したチャレンジを入れて");
    const r = await verifyAssertion(j, {
      challenge: enc.encode(chal),
      origin: j.origin,
      rpId: j.rpId,
    });
    out.textContent =
      (r.ok ? "✓ 有効\n\n" : "✗ 無効\n\n") +
      r.checks.map((c) => `${c.ok ? "✓" : "✗"} ${c.name}: ${c.detail}`).join("\n") +
      `\n\nsignCount: ${r.signCount}\nflags: ${JSON.stringify(r.flags)}\n` +
      `\n※ オリジンと rpId は JSON に書いてある値で確かめている。相手のサイトが本当にそこか、公開鍵が本当に相手のものかは別に確認すること`;
  } catch (e) {
    out.textContent = "エラー: " + (e as Error).message;
  }
});
