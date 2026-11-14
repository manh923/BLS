// cryptos の Dilithium2 (src/dilithium/Dilithium2.ts) を改造して署名を小さくした版
//   y をガウス分布にして z をライス符号で詰める (BLS リポジトリの src/lattice.ts の V3 / V4 と同じ技)
//   ※ おもちゃ: ガウス分布は浮動小数点で、定数時間ではない
export class Dilithium2Small {
    N = 256;
    Q = 8380417n;
    D = 13;
    K = 4;
    L = 4;
    ETA = 2;
    GAMMA1 = 131072n; // 2^17
    GAMMA2 = 95232n; // (Q-1)/88
    OMEGA = 80;
    BETA = 78n; // TAU * ETA (コンストラクタで η に合わせて決める)
    TAU = 39;
    LAMBDA = 128;
    N_INV = 8347681n; // 256^{-1} mod Q
    ZETA = 1753n;
    ZETA_TABLE = [
        0n,
        4808194n,
        3765607n,
        3761513n,
        5178923n,
        5496691n,
        5234739n,
        5178987n,
        7778734n,
        3542485n,
        2682288n,
        2129892n,
        3764867n,
        7375178n,
        557458n,
        7159240n,
        5010068n,
        4317364n,
        2663378n,
        6705802n,
        4855975n,
        7946292n,
        676590n,
        7044481n,
        5152541n,
        1714295n,
        2453983n,
        1460718n,
        7737789n,
        4795319n,
        2815639n,
        2283733n,
        3602218n,
        3182878n,
        2740543n,
        4793971n,
        5269599n,
        2101410n,
        3704823n,
        1159875n,
        394148n,
        928749n,
        1095468n,
        4874037n,
        2071829n,
        4361428n,
        3241972n,
        2156050n,
        3415069n,
        1759347n,
        7562881n,
        4805951n,
        3756790n,
        6444618n,
        6663429n,
        4430364n,
        5483103n,
        3192354n,
        556856n,
        3870317n,
        2917338n,
        1853806n,
        3345963n,
        1858416n,
        3073009n,
        1277625n,
        5744944n,
        3852015n,
        4183372n,
        5157610n,
        5258977n,
        8106357n,
        2508980n,
        2028118n,
        1937570n,
        4564692n,
        2811291n,
        5396636n,
        7270901n,
        4158088n,
        1528066n,
        482649n,
        1148858n,
        5418153n,
        7814814n,
        169688n,
        2462444n,
        5046034n,
        4213992n,
        4892034n,
        1987814n,
        5183169n,
        1736313n,
        235407n,
        5130263n,
        3258457n,
        5801164n,
        1787943n,
        5989328n,
        6125690n,
        3482206n,
        4197502n,
        7080401n,
        6018354n,
        7062739n,
        2461387n,
        3035980n,
        621164n,
        3901472n,
        7153756n,
        2925816n,
        3374250n,
        1356448n,
        5604662n,
        2683270n,
        5601629n,
        4912752n,
        2312838n,
        7727142n,
        7921254n,
        348812n,
        8052569n,
        1011223n,
        6026202n,
        4561790n,
        6458164n,
        6143691n,
        1744507n,
        1753n,
        6444997n,
        5720892n,
        6924527n,
        2660408n,
        6600190n,
        8321269n,
        2772600n,
        1182243n,
        87208n,
        636927n,
        4415111n,
        4423672n,
        6084020n,
        5095502n,
        4663471n,
        8352605n,
        822541n,
        1009365n,
        5926272n,
        6400920n,
        1596822n,
        4423473n,
        4620952n,
        6695264n,
        4969849n,
        2678278n,
        4611469n,
        4829411n,
        635956n,
        8129971n,
        5925040n,
        4234153n,
        6607829n,
        2192938n,
        6653329n,
        2387513n,
        4768667n,
        8111961n,
        5199961n,
        3747250n,
        2296099n,
        1239911n,
        4541938n,
        3195676n,
        2642980n,
        1254190n,
        8368000n,
        2998219n,
        141835n,
        8291116n,
        2513018n,
        7025525n,
        613238n,
        7070156n,
        6161950n,
        7921677n,
        6458423n,
        4040196n,
        4908348n,
        2039144n,
        6500539n,
        7561656n,
        6201452n,
        6757063n,
        2105286n,
        6006015n,
        6346610n,
        586241n,
        7200804n,
        527981n,
        5637006n,
        6903432n,
        1994046n,
        2491325n,
        6987258n,
        507927n,
        7192532n,
        7655613n,
        6545891n,
        5346675n,
        8041997n,
        2647994n,
        3009748n,
        5767564n,
        4148469n,
        749577n,
        4357667n,
        3980599n,
        2569011n,
        6764887n,
        1723229n,
        1665318n,
        2028038n,
        1163598n,
        5011144n,
        3994671n,
        8368538n,
        7009900n,
        3020393n,
        3363542n,
        214880n,
        545376n,
        7609976n,
        3105558n,
        7277073n,
        508145n,
        7826699n,
        860144n,
        3430436n,
        140244n,
        6866265n,
        6195333n,
        3123762n,
        2358373n,
        6187330n,
        5365997n,
        6663603n,
        2926054n,
        7987710n,
        8077412n,
        3531229n,
        4405932n,
        4606686n,
        1900052n,
        7598542n,
        1054478n,
        7648983n,
    ];
    // ===== Keccak-f[1600] / SHAKE-128,256 =====
    KECCAK_ROUNDS = 24;
    RC = [
        0x0000000000000001n,
        0x0000000000008082n,
        0x800000000000808an,
        0x8000000080008000n,
        0x000000000000808bn,
        0x0000000080000001n,
        0x8000000080008081n,
        0x8000000000008009n,
        0x000000000000008an,
        0x0000000000000088n,
        0x0000000080008009n,
        0x000000008000000an,
        0x000000008000808bn,
        0x800000000000008bn,
        0x8000000000008089n,
        0x8000000000008003n,
        0x8000000000008002n,
        0x8000000000000080n,
        0x000000000000800an,
        0x800000008000000an,
        0x8000000080008081n,
        0x8000000000008080n,
        0x0000000080000001n,
        0x8000000080008008n,
    ];
    ROT_OFFSETS = [
        0, 1, 62, 28, 27, 36, 44, 6, 55, 20, 3, 10, 43, 25, 39, 41, 45, 15, 21, 8,
        18, 2, 61, 56, 14,
    ];
    PI_LANES = [
        0, 10, 20, 5, 15, 16, 1, 11, 21, 6, 7, 17, 2, 12, 22, 23, 8, 18, 3, 13, 14,
        24, 9, 19, 4,
    ];
    MASK64 = 0xffffffffffffffffn;
    rotl64(x, n) {
        return ((x << BigInt(n)) | (x >> BigInt(64 - n))) & this.MASK64;
    }
    keccakF1600(state) {
        const C = new Array(5);
        const D = new Array(5);
        const B = new Array(25);
        for (let round = 0; round < this.KECCAK_ROUNDS; round++) {
            // θ step
            for (let x = 0; x < 5; x++) {
                C[x] =
                    state[x] ^
                        state[x + 5] ^
                        state[x + 10] ^
                        state[x + 15] ^
                        state[x + 20];
            }
            for (let x = 0; x < 5; x++) {
                D[x] = C[(x + 4) % 5] ^ this.rotl64(C[(x + 1) % 5], 1);
                for (let y = 0; y < 25; y += 5) {
                    state[y + x] = (state[y + x] ^ D[x]) & this.MASK64;
                }
            }
            // ρ + π steps
            for (let i = 0; i < 25; i++) {
                B[this.PI_LANES[i]] = this.rotl64(state[i], this.ROT_OFFSETS[i]);
            }
            // χ step
            for (let y = 0; y < 25; y += 5) {
                for (let x = 0; x < 5; x++) {
                    state[y + x] =
                        (B[y + x] ^
                            (~B[y + ((x + 1) % 5)] & this.MASK64 & B[y + ((x + 2) % 5)])) &
                            this.MASK64;
                }
            }
            // ι step
            state[0] = (state[0] ^ this.RC[round]) & this.MASK64;
        }
    }
    keccakAbsorb(state, rateBytes, input, dsByte) {
        const rateLanes = rateBytes >> 3;
        let offset = 0;
        // Absorb full blocks
        while (offset + rateBytes <= input.length) {
            for (let i = 0; i < rateLanes; i++) {
                let lane = 0n;
                const base = offset + i * 8;
                for (let b = 0; b < 8; b++) {
                    lane |= BigInt(input[base + b]) << BigInt(b * 8);
                }
                state[i] = (state[i] ^ lane) & this.MASK64;
            }
            this.keccakF1600(state);
            offset += rateBytes;
        }
        // Padding
        const remaining = input.length - offset;
        const padded = new Uint8Array(rateBytes);
        padded.set(input.subarray(offset, offset + remaining));
        padded[remaining] = dsByte;
        padded[rateBytes - 1] |= 0x80;
        for (let i = 0; i < rateLanes; i++) {
            let lane = 0n;
            const base = i * 8;
            for (let b = 0; b < 8; b++) {
                lane |= BigInt(padded[base + b]) << BigInt(b * 8);
            }
            state[i] = (state[i] ^ lane) & this.MASK64;
        }
        this.keccakF1600(state);
    }
    keccakSqueeze(state, rateBytes, outLen) {
        const out = new Uint8Array(outLen);
        let offset = 0;
        const rateLanes = rateBytes >> 3;
        while (offset < outLen) {
            const blockLen = Math.min(rateBytes, outLen - offset);
            for (let i = 0; i < rateLanes && offset < outLen; i++) {
                const lane = state[i];
                for (let b = 0; b < 8 && offset < outLen; b++) {
                    out[offset++] = Number((lane >> BigInt(b * 8)) & 0xffn);
                }
            }
            if (offset < outLen) {
                this.keccakF1600(state);
            }
        }
        return out;
    }
    shake128(input, outLen) {
        const state = new Array(25).fill(0n);
        const rate = 168; // (1600 - 256) / 8
        this.keccakAbsorb(state, rate, input, 0x1f);
        return this.keccakSqueeze(state, rate, outLen);
    }
    shake256(input, outLen) {
        const state = new Array(25).fill(0n);
        const rate = 136; // (1600 - 512) / 8
        this.keccakAbsorb(state, rate, input, 0x1f);
        return this.keccakSqueeze(state, rate, outLen);
    }
    // ===== Modular / Montgomery Arithmetic =====
    mod(a, m) {
        const r = a % m;
        return r < 0n ? r + m : r;
    }
    // Montgomery: R = 2^32
    MONT_R2 = 2365951n; // R^2 mod Q
    MONT_QINV = 4236238847n; // -Q^{-1} mod 2^32
    montReduce(a) {
        const t = (a * this.MONT_QINV) & 0xffffffffn;
        let u = (a + t * this.Q) >> 32n;
        if (u >= this.Q)
            u -= this.Q;
        return u;
    }
    montMul(a, b) {
        return this.montReduce(a * b);
    }
    toMont(a) {
        return this.montMul(a, this.MONT_R2);
    }
    fromMont(a) {
        return this.montReduce(a);
    }
    // ===== Pre-computed Montgomery domain zetas =====
    ZETA_MONT = [];
    // ===== 小さくする改造 (BLS リポジトリで追加) =====
    //   y をガウス分布 (σ = α·T) にして、z をライス符号で詰める
    //   T は ‖c·s1‖₂ の上限 (超えたら作り直し)。η は 1 か 2
    ALPHA;
    TBOUND;
    HINT_GOLOMB;
    lastAttempts = 0;
    // hintGolomb: ヒントを ω+k バイト固定ではなく、1 の位置の差のゴロム符号で送る
    constructor(opts = {}) {
        this.HINT_GOLOMB = opts.hintGolomb ?? false;
        this.ETA = opts.eta ?? 2;
        this.BETA = BigInt(this.TAU * this.ETA);
        this.ALPHA = opts.alpha ?? 11;
        this.TBOUND = opts.T ?? (this.ETA === 2 ? 420 : 260);
        this.ZETA_MONT = new Array(256);
        this.ZETA_MONT[0] = 0n;
        for (let i = 1; i < 256; i++) {
            this.ZETA_MONT[i] = this.toMont(this.ZETA_TABLE[i]);
        }
    }
    // ===== NTT =====
    ntt(a) {
        const r = a.map((x) => this.toMont(x));
        let k = 0;
        for (let len = 128; len >= 1; len >>= 1) {
            for (let start = 0; start < this.N; start += 2 * len) {
                k++;
                const zeta = this.ZETA_MONT[k];
                for (let j = start; j < start + len; j++) {
                    const t = this.montMul(zeta, r[j + len]);
                    r[j + len] = r[j] - t;
                    if (r[j + len] < 0n)
                        r[j + len] += this.Q;
                    r[j] = r[j] + t;
                    if (r[j] >= this.Q)
                        r[j] -= this.Q;
                }
            }
        }
        return r; // Montgomery domain のまま返す
    }
    invNtt(a) {
        const r = a.slice();
        let k = 255;
        for (let len = 1; len <= 128; len <<= 1) {
            for (let start = 0; start < this.N; start += 2 * len) {
                const zeta = this.Q - this.ZETA_MONT[k];
                k--;
                for (let j = start; j < start + len; j++) {
                    const t = r[j];
                    r[j] = t + r[j + len];
                    if (r[j] >= this.Q)
                        r[j] -= this.Q;
                    r[j + len] = this.montMul(zeta, t - r[j + len] + this.Q);
                }
            }
        }
        const ninvMont = this.toMont(this.N_INV);
        for (let i = 0; i < this.N; i++) {
            r[i] = this.fromMont(this.montMul(ninvMont, r[i]));
        }
        return r; // 通常domain に戻す
    }
    // ===== Polynomial Operations (NTT domain) =====
    // NTT domain pointwise: 両方Mont domain前提
    polyPointwise(a, b) {
        const r = new Array(this.N);
        for (let i = 0; i < this.N; i++) {
            r[i] = this.montMul(a[i], b[i]);
        }
        return r;
    }
    // NTT済みベクトル同士の内積 (NTT domain)
    nttVecInner(a, b) {
        const r = new Array(this.N).fill(0n);
        for (let i = 0; i < a.length; i++) {
            const pw = this.polyPointwise(a[i], b[i]);
            for (let j = 0; j < this.N; j++) {
                r[j] = r[j] + pw[j];
                if (r[j] >= this.Q)
                    r[j] -= this.Q;
            }
        }
        return r;
    }
    // 多項式乗算: a * b in Z_Q[X]/(X^256+1)
    polyMul(a, b) {
        const aNtt = this.ntt(a);
        const bNtt = this.ntt(b);
        const cNtt = this.polyPointwise(aNtt, bNtt);
        return this.invNtt(cNtt);
    }
    polyAdd(a, b) {
        const r = new Array(this.N);
        for (let i = 0; i < this.N; i++) {
            r[i] = a[i] + b[i];
            if (r[i] >= this.Q)
                r[i] -= this.Q;
        }
        return r;
    }
    polySub(a, b) {
        const r = new Array(this.N);
        for (let i = 0; i < this.N; i++) {
            r[i] = a[i] - b[i];
            if (r[i] < 0n)
                r[i] += this.Q;
        }
        return r;
    }
    // ===== Vector Operations =====
    // 行列A (K×L, NTT domain) × ベクトルv (L, NTT domain) → (K, NTT domain)
    matVecNtt(A, v) {
        const r = [];
        for (let i = 0; i < this.K; i++) {
            r.push(this.nttVecInner(A[i], v));
        }
        return r;
    }
    vecAdd(a, b) {
        return a.map((_, i) => this.polyAdd(a[i], b[i]));
    }
    vecSub(a, b) {
        return a.map((_, i) => this.polySub(a[i], b[i]));
    }
    vecNtt(v) {
        return v.map((p) => this.ntt(p));
    }
    vecInvNtt(v) {
        return v.map((p) => this.invNtt(p));
    }
    // ===== Sampling =====
    // SHAKE-128 の XOF ストリーム版（ExpandA用）
    xofInit(seed, i, j) {
        const input = new Uint8Array(seed.length + 2);
        input.set(seed);
        input[seed.length] = j; // 列が先（FIPS 204仕様通り）
        input[seed.length + 1] = i;
        const state = new Array(25).fill(0n);
        this.keccakAbsorb(state, 168, input, 0x1f);
        return { state, rate: 168 };
    }
    xofSqueeze(ctx, outLen) {
        return this.keccakSqueeze(ctx.state, ctx.rate, outLen);
    }
    // Rejection sampling: 係数を [0, Q) から一様にサンプリング
    rejUniformPoly(seed, i, j) {
        const poly = new Array(this.N);
        const ctx = this.xofInit(seed, i, j);
        let coeff = 0;
        while (coeff < this.N) {
            const buf = this.xofSqueeze(ctx, 168);
            for (let pos = 0; pos + 2 < buf.length && coeff < this.N; pos += 3) {
                const val = BigInt(buf[pos] | (buf[pos + 1] << 8) | (buf[pos + 2] << 16)) &
                    0x7fffffn;
                if (val < this.Q)
                    poly[coeff++] = val;
            }
        }
        return poly;
    }
    // ExpandA: ρ → A ∈ R_Q^{K×L} (NTT domain)
    expandA(rho) {
        const A = [];
        for (let i = 0; i < this.K; i++) {
            A[i] = [];
            for (let j = 0; j < this.L; j++) {
                A[i][j] = this.ntt(this.rejUniformPoly(rho, i, j));
            }
        }
        return A;
    }
    // ===== CBD / Eta Sampling =====
    // SHAKE-256 の PRF: seed || nonce → output
    prf(seed, nonce, outLen) {
        const input = new Uint8Array(seed.length + 2);
        input.set(seed);
        input[seed.length] = nonce & 0xff;
        input[seed.length + 1] = (nonce >> 8) & 0xff;
        return this.shake256(input, outLen);
    }
    // η=2 用: rejection sampling from [0,15) → {-2,-1,0,1,2}
    sampleEtaPoly(seed, nonce) {
        const poly = new Array(this.N);
        const buf = this.prf(seed, nonce, 136); // ETA=2: 136バイトで十分
        let coeff = 0;
        let pos = 0;
        while (coeff < this.N) {
            const b = buf[pos++];
            // 各バイトから2係数 (4bit each)
            const lo = b & 0x0f;
            const hi = b >> 4;
            if (lo < 15 && coeff < this.N) {
                // FIPS 204 CoeffFromHalfByte: η=2, b mod 5 → [0,4], η - result → [-2,2]
                // 0..14 を 5 で割ると各値が3回ずつ → bias なし
                poly[coeff++] = BigInt(this.ETA - (lo % (2 * this.ETA + 1)));
            }
            if (hi < 15 && coeff < this.N) {
                poly[coeff++] = BigInt(this.ETA - (hi % (2 * this.ETA + 1)));
            }
        }
        return poly;
    }
    // ExpandS: ρ' → (s1 ∈ R^L, s2 ∈ R^K) with coefficients in [-η, η]
    expandS(rhoPrime) {
        const s1 = [];
        const s2 = [];
        let nonce = 0;
        for (let i = 0; i < this.L; i++) {
            s1.push(this.sampleEtaPoly(rhoPrime, nonce++));
        }
        for (let i = 0; i < this.K; i++) {
            s2.push(this.sampleEtaPoly(rhoPrime, nonce++));
        }
        return { s1, s2 };
    }
    // ===== Power2Round =====
    power2Round(r) {
        const pow2d = 1n << BigInt(this.D); // 8192
        const half = pow2d >> 1n; // 4096
        let r0 = r % pow2d;
        if (r0 > half)
            r0 -= pow2d;
        const r1 = (r - r0) >> BigInt(this.D);
        return [r1, r0];
    }
    polyPower2Round(p) {
        const high = new Array(this.N);
        const low = new Array(this.N);
        for (let i = 0; i < this.N; i++) {
            [high[i], low[i]] = this.power2Round(p[i]);
        }
        return { high, low };
    }
    vecPower2Round(v) {
        const t1 = [];
        const t0 = [];
        for (let i = 0; i < v.length; i++) {
            const { high, low } = this.polyPower2Round(v[i]);
            t1.push(high);
            t0.push(low);
        }
        return { t1, t0 };
    }
    // ===== Byte Utils =====
    concat(...arrays) {
        const total = arrays.reduce((s, a) => s + a.length, 0);
        const r = new Uint8Array(total);
        let offset = 0;
        for (const a of arrays) {
            r.set(a, offset);
            offset += a.length;
        }
        return r;
    }
    // t1: 各係数10bit, K=8多項式 → 2560 bytes
    packT1(t1) {
        const out = new Uint8Array(this.K * 320);
        let off = 0;
        for (let i = 0; i < this.K; i++) {
            for (let j = 0; j < this.N; j += 4) {
                const a = Number(t1[i][j]), b = Number(t1[i][j + 1]);
                const c = Number(t1[i][j + 2]), d = Number(t1[i][j + 3]);
                out[off++] = a & 0xff;
                out[off++] = ((a >> 8) | (b << 2)) & 0xff;
                out[off++] = ((b >> 6) | (c << 4)) & 0xff;
                out[off++] = ((c >> 4) | (d << 6)) & 0xff;
                out[off++] = d >> 2;
            }
        }
        return out;
    }
    unpackT1(buf) {
        const t1 = [];
        let off = 0;
        for (let i = 0; i < this.K; i++) {
            const p = new Array(this.N);
            for (let j = 0; j < this.N; j += 4) {
                p[j] = BigInt(((buf[off + 1] & 0x03) << 8) | buf[off]);
                p[j + 1] = BigInt(((buf[off + 2] & 0x0f) << 6) | (buf[off + 1] >> 2));
                p[j + 2] = BigInt(((buf[off + 3] & 0x3f) << 4) | (buf[off + 2] >> 4));
                p[j + 3] = BigInt((buf[off + 4] << 2) | (buf[off + 3] >> 6));
                off += 5;
            }
            t1.push(p);
        }
        return t1;
    }
    // t0: 各係数13bit (signed → unsigned化), K=8 → 3328 bytes
    packT0(t0) {
        const out = new Uint8Array(this.K * 416);
        let off = 0;
        const pow2d1 = 1n << BigInt(this.D - 1); // 4096
        for (let i = 0; i < this.K; i++) {
            for (let j = 0; j < this.N; j += 8) {
                const vals = [];
                for (let k = 0; k < 8; k++) {
                    // signed → unsigned: t0 ∈ (-2^12, 2^12] → [0, 2^13)
                    vals.push(Number(pow2d1 - t0[i][j + k]));
                }
                // 8 × 13bit = 104bit = 13 bytes
                out[off++] = vals[0] & 0xff;
                out[off++] = ((vals[0] >> 8) | (vals[1] << 5)) & 0xff;
                out[off++] = (vals[1] >> 3) & 0xff;
                out[off++] = ((vals[1] >> 11) | (vals[2] << 2)) & 0xff;
                out[off++] = ((vals[2] >> 6) | (vals[3] << 7)) & 0xff;
                out[off++] = (vals[3] >> 1) & 0xff;
                out[off++] = ((vals[3] >> 9) | (vals[4] << 4)) & 0xff;
                out[off++] = (vals[4] >> 4) & 0xff;
                out[off++] = ((vals[4] >> 12) | (vals[5] << 1)) & 0xff;
                out[off++] = ((vals[5] >> 7) | (vals[6] << 6)) & 0xff;
                out[off++] = (vals[6] >> 2) & 0xff;
                out[off++] = ((vals[6] >> 10) | (vals[7] << 3)) & 0xff;
                out[off++] = (vals[7] >> 5) & 0xff;
            }
        }
        return out;
    }
    unpackT0(buf) {
        const t0 = [];
        let off = 0;
        const pow2d1 = 1n << BigInt(this.D - 1);
        for (let i = 0; i < this.K; i++) {
            const p = new Array(this.N);
            for (let j = 0; j < this.N; j += 8) {
                const v0 = buf[off] | ((buf[off + 1] & 0x1f) << 8);
                const v1 = (buf[off + 1] >> 5) |
                    (buf[off + 2] << 3) |
                    ((buf[off + 3] & 0x03) << 11);
                const v2 = (buf[off + 3] >> 2) | ((buf[off + 4] & 0x7f) << 6);
                const v3 = (buf[off + 4] >> 7) |
                    (buf[off + 5] << 1) |
                    ((buf[off + 6] & 0x0f) << 9);
                const v4 = (buf[off + 6] >> 4) |
                    (buf[off + 7] << 4) |
                    ((buf[off + 8] & 0x01) << 12);
                const v5 = (buf[off + 8] >> 1) | ((buf[off + 9] & 0x3f) << 7);
                const v6 = (buf[off + 9] >> 6) |
                    (buf[off + 10] << 2) |
                    ((buf[off + 11] & 0x07) << 10);
                const v7 = (buf[off + 11] >> 3) | (buf[off + 12] << 5);
                p[j] = pow2d1 - BigInt(v0 & 0x1fff);
                p[j + 1] = pow2d1 - BigInt(v1 & 0x1fff);
                p[j + 2] = pow2d1 - BigInt(v2 & 0x1fff);
                p[j + 3] = pow2d1 - BigInt(v3 & 0x1fff);
                p[j + 4] = pow2d1 - BigInt(v4 & 0x1fff);
                p[j + 5] = pow2d1 - BigInt(v5 & 0x1fff);
                p[j + 6] = pow2d1 - BigInt(v6 & 0x1fff);
                p[j + 7] = pow2d1 - BigInt(v7 & 0x1fff);
                off += 13;
            }
            t0.push(p);
        }
        return t0;
    }
    // η=2: 各係数3bit, 256係数 → 96 bytes (halfbyte packing)
    packEta(p) {
        const out = new Uint8Array(96);
        let off = 0;
        for (let j = 0; j < this.N; j += 8) {
            // η=2: 各係数を [0,4] にマップ: η - coeff
            const vals = [];
            for (let k = 0; k < 8; k++) {
                let v = Number(this.ETA - Number(p[j + k]));
                if (v < 0)
                    v += 5; // should not happen if coeffs in [-2,2]
                vals.push(v);
            }
            // 8 × 3bit = 24bit = 3 bytes
            out[off++] = (vals[0] | (vals[1] << 3) | (vals[2] << 6)) & 0xff;
            out[off++] =
                ((vals[2] >> 2) | (vals[3] << 1) | (vals[4] << 4) | (vals[5] << 7)) &
                    0xff;
            out[off++] = ((vals[5] >> 1) | (vals[6] << 2) | (vals[7] << 5)) & 0xff;
        }
        return out;
    }
    unpackEta(buf) {
        const p = new Array(this.N);
        let off = 0;
        for (let j = 0; j < this.N; j += 8) {
            const b0 = buf[off], b1 = buf[off + 1], b2 = buf[off + 2];
            const v = [
                b0 & 7,
                (b0 >> 3) & 7,
                ((b0 >> 6) | (b1 << 2)) & 7,
                (b1 >> 1) & 7,
                (b1 >> 4) & 7,
                ((b1 >> 7) | (b2 << 1)) & 7,
                (b2 >> 2) & 7,
                (b2 >> 5) & 7,
            ];
            for (let k = 0; k < 8; k++) {
                p[j + k] = BigInt(this.ETA - v[k]);
            }
            off += 3;
        }
        return p;
    }
    // ===== Key Serialization =====
    // pk = ρ (32) || t1_packed (1280) = 1312 bytes
    encodePk(pk) {
        return this.concat(pk.rho, this.packT1(pk.t1));
    }
    decodePk(buf) {
        return {
            rho: buf.slice(0, 32),
            t1: this.unpackT1(buf.slice(32)),
        };
    }
    // sk = ρ(32) || K(32) || tr(64) || s1(L*96=384) || s2(K*96=384) || t0(K*416=1664) = 2560 bytes
    encodeSk(sk) {
        const parts = [sk.rho, sk.K, sk.tr];
        for (let i = 0; i < this.L; i++)
            parts.push(this.packEta(sk.s1[i]));
        for (let i = 0; i < this.K; i++)
            parts.push(this.packEta(sk.s2[i]));
        parts.push(this.packT0(sk.t0));
        return this.concat(...parts);
    }
    decodeSk(buf) {
        let off = 0;
        const rho = buf.slice(off, (off += 32));
        const K = buf.slice(off, (off += 32));
        const tr = buf.slice(off, (off += 64));
        const s1 = [];
        for (let i = 0; i < this.L; i++)
            s1.push(this.unpackEta(buf.slice(off, (off += 96))));
        const s2 = [];
        for (let i = 0; i < this.K; i++)
            s2.push(this.unpackEta(buf.slice(off, (off += 96))));
        const t0 = this.unpackT0(buf.slice(off));
        return { rho, K, tr, s1, s2, t0 };
    }
    // ===== KeyGen (修正版) =====
    keyGen(seed) {
        if (!seed) {
            seed = new Uint8Array(32);
            crypto.getRandomValues(seed);
        }
        const expanded = this.shake256(this.concat(seed, new Uint8Array([this.K, this.L])), 128);
        const rho = expanded.slice(0, 32);
        const rhoPrime = expanded.slice(32, 96);
        const K = expanded.slice(96, 128);
        const A = this.expandA(rho);
        const { s1, s2 } = this.expandS(rhoPrime);
        const s1Ntt = this.vecNtt(s1);
        const t = this.vecAdd(this.vecInvNtt(this.matVecNtt(A, s1Ntt)), s2);
        const { t1, t0 } = this.vecPower2Round(t);
        const pkObj = { rho, t1 };
        const pk = this.encodePk(pkObj);
        const tr = this.shake256(pk, 64);
        const sk = this.encodeSk({ rho, K, tr, s1, s2, t0 });
        return { pk, sk };
    }
    // ===== Decompose / HighBits / LowBits =====
    // r → (r1, r0) where r = r1*α + r0, |r0| ≤ α/2
    // ML-DSA-87: α = 2*GAMMA2 = 523776, m = (Q-1)/α = 16
    decompose(r) {
        const alpha = 2n * this.GAMMA2; // 523776
        const halfAlpha = alpha >> 1n; // 261888
        // FIPS 204 Algorithm 36
        let r0 = ((r % alpha) + alpha) % alpha; // r mod α in [0, α)
        if (r0 > halfAlpha)
            r0 -= alpha; // 中心リフト
        // 特殊ケース: r - r0 == Q - 1
        if (r - r0 === this.Q - 1n) {
            return [0n, r0 - 1n];
        }
        const r1 = (r - r0) / alpha;
        return [r1, r0];
    }
    highBits(r) {
        return this.decompose(r)[0];
    }
    lowBits(r) {
        return this.decompose(r)[1];
    }
    polyHighBits(p) {
        return p.map((c) => this.highBits(c));
    }
    polyLowBits(p) {
        return p.map((c) => this.lowBits(c));
    }
    vecHighBits(v) {
        return v.map((p) => this.polyHighBits(p));
    }
    vecLowBits(v) {
        return v.map((p) => this.polyLowBits(p));
    }
    // ===== MakeHint / UseHint =====
    // HighBits(r) ≠ HighBits(r+z) のときヒントが1
    makeHint(z, r) {
        const r1 = this.highBits(r);
        const rz = this.mod(r + z, this.Q);
        const v1 = this.highBits(rz);
        return r1 !== v1 ? 1 : 0;
    }
    // ヒントを使って正しい上位ビットを復元
    useHint(hint, r) {
        const [r1, r0] = this.decompose(r);
        const m = (this.Q - 1n) / (2n * this.GAMMA2); // 44
        if (hint === 0)
            return r1;
        if (r0 > 0n) {
            return (r1 + 1n) % m;
        }
        else {
            return (r1 - 1n + m) % m;
        }
    }
    polyMakeHint(z, r) {
        const hint = new Array(this.N);
        let count = 0;
        for (let i = 0; i < this.N; i++) {
            hint[i] = this.makeHint(z[i], r[i]);
            count += hint[i];
        }
        return { hint, count };
    }
    polyUseHint(hint, r) {
        const out = new Array(this.N);
        for (let i = 0; i < this.N; i++) {
            out[i] = this.useHint(hint[i], r[i]);
        }
        return out;
    }
    vecMakeHint(z, r) {
        const hints = [];
        let count = 0;
        for (let i = 0; i < z.length; i++) {
            const h = this.polyMakeHint(z[i], r[i]);
            hints.push(h.hint);
            count += h.count;
        }
        return { hints, count };
    }
    vecUseHint(hints, r) {
        return hints.map((h, i) => this.polyUseHint(h, r[i]));
    }
    // ===== SampleInBall =====
    // チャレンジ c: 256係数中 TAU=60個が ±1、残りは 0
    sampleInBall(seed) {
        const c = new Array(this.N).fill(0n);
        const state = new Array(25).fill(0n);
        this.keccakAbsorb(state, 136, seed, 0x1f);
        // 最初のsqueezeブロックから sign bits (8 bytes) とサンプル用バイトを取得
        let buf = this.keccakSqueeze(state, 136, 136);
        let bufPos = 0;
        let signs = 0n;
        for (let i = 0; i < 8; i++) {
            signs |= BigInt(buf[bufPos++]) << BigInt(i * 8);
        }
        let signIdx = 0;
        for (let i = this.N - this.TAU; i < this.N; i++) {
            let j;
            do {
                if (bufPos >= buf.length) {
                    buf = this.keccakSqueeze(state, 136, 136);
                    bufPos = 0;
                }
                j = buf[bufPos++];
            } while (j > i);
            c[i] = c[j];
            c[j] = 1n - 2n * ((signs >> BigInt(signIdx)) & 1n); // ±1
            signIdx++;
        }
        return c;
    }
    // ===== ExpandMask =====
    // γ1=2^19: 各係数20bit, 256係数 → 640 bytes per poly
    expandMask(rhoPrime, kappa) {
        const y = [];
        for (let i = 0; i < this.L; i++) {
            const input = this.concat(rhoPrime, new Uint8Array([(kappa + i) & 0xff, ((kappa + i) >> 8) & 0xff]));
            const buf = this.shake256(input, this.Z_POLY_BYTES); // 576 bytes
            const p = new Array(this.N);
            const mask = 0x3ffff; // 18bit
            // 4係数 = 72bit = 9 bytes
            for (let j = 0; j < this.N; j += 4) {
                const base = (j >> 2) * 9;
                const v0 = (buf[base] | (buf[base + 1] << 8) | (buf[base + 2] << 16)) & mask;
                const v1 = ((buf[base + 2] >> 2) |
                    (buf[base + 3] << 6) |
                    (buf[base + 4] << 14)) &
                    mask;
                const v2 = ((buf[base + 4] >> 4) |
                    (buf[base + 5] << 4) |
                    (buf[base + 6] << 12)) &
                    mask;
                const v3 = ((buf[base + 6] >> 6) |
                    (buf[base + 7] << 2) |
                    (buf[base + 8] << 10)) &
                    mask;
                p[j] = this.mod(this.GAMMA1 - BigInt(v0), this.Q);
                p[j + 1] = this.mod(this.GAMMA1 - BigInt(v1), this.Q);
                p[j + 2] = this.mod(this.GAMMA1 - BigInt(v2), this.Q);
                p[j + 3] = this.mod(this.GAMMA1 - BigInt(v3), this.Q);
            }
            y.push(p);
        }
        return y;
    }
    // ===== Signature Packing =====
    // z: γ1=2^17 → 各係数18bit unsigned化, 4係数=72bit=9bytes
    // L=4 → 256*18/8 * 4 = 576 * 4 = 2304 bytes... いや
    // 256 * 18bit = 4608bit = 576 bytes per poly, L=4 → 2304 bytes
    Z_POLY_BYTES = 576; // N * 18 / 8
    packZ(z) {
        const out = new Uint8Array(this.L * this.Z_POLY_BYTES);
        let off = 0;
        const halfQ = this.Q >> 1n;
        const bits = 18; // log2(2 * GAMMA1) = log2(2^18) = 18
        const mask = (1 << bits) - 1;
        for (let i = 0; i < this.L; i++) {
            for (let j = 0; j < this.N; j += 4) {
                const vals = [];
                for (let k = 0; k < 4; k++) {
                    let zs = z[i][j + k];
                    if (zs > halfQ)
                        zs -= this.Q;
                    vals.push(Number(this.GAMMA1 - zs) & mask);
                }
                // 4 * 18bit = 72bit = 9 bytes
                out[off++] = vals[0] & 0xff;
                out[off++] = (vals[0] >> 8) & 0xff;
                out[off++] = ((vals[0] >> 16) | (vals[1] << 2)) & 0xff;
                out[off++] = (vals[1] >> 6) & 0xff;
                out[off++] = ((vals[1] >> 14) | (vals[2] << 4)) & 0xff;
                out[off++] = (vals[2] >> 4) & 0xff;
                out[off++] = ((vals[2] >> 12) | (vals[3] << 6)) & 0xff;
                out[off++] = (vals[3] >> 2) & 0xff;
                out[off++] = (vals[3] >> 10) & 0xff;
            }
        }
        return out;
    }
    // hint: ω=75個以下の1の位置を格納
    packHint(hints) {
        const out = new Uint8Array(this.OMEGA + this.K); // 75 + 8 = 83
        let idx = 0;
        for (let i = 0; i < this.K; i++) {
            for (let j = 0; j < this.N; j++) {
                if (hints[i][j] === 1) {
                    out[idx++] = j;
                }
            }
            out[this.OMEGA + i] = idx;
        }
        return out;
    }
    // w1: 各係数6bit (m=44→上位は0..43), 192 bytes per poly, K=4 → 768
    packW1(w1) {
        const out = new Uint8Array(this.K * 192); // 256 * 6 / 8 = 192
        let off = 0;
        for (let i = 0; i < this.K; i++) {
            for (let j = 0; j < this.N; j += 4) {
                const a = Number(w1[i][j]), b = Number(w1[i][j + 1]);
                const c = Number(w1[i][j + 2]), d = Number(w1[i][j + 3]);
                // 4 * 6bit = 24bit = 3 bytes
                out[off++] = (a | (b << 6)) & 0xff;
                out[off++] = ((b >> 2) | (c << 4)) & 0xff;
                out[off++] = ((c >> 4) | (d << 2)) & 0xff;
            }
        }
        return out;
    }
    // ===== Infinity Norm Check =====
    polyChkNorm(p, bound) {
        for (let i = 0; i < this.N; i++) {
            let v = p[i];
            // 中心リフト
            if (v > this.Q >> 1n)
                v = this.Q - v;
            if (v >= bound)
                return false;
        }
        return true;
    }
    vecChkNorm(v, bound) {
        return v.every((p) => this.polyChkNorm(p, bound));
    }
    // ===== 改造用の補助 =====
    get SIGMA() {
        return this.ALPHA * this.TBOUND;
    }
    get RICE_L() {
        return Math.floor(Math.log2(this.SIGMA));
    }
    get L2_BOUND() {
        return 1.2 * this.SIGMA * Math.sqrt(this.L * this.N);
    }
    centeredNum(x) {
        let v = x % this.Q;
        if (v < 0n)
            v += this.Q;
        if (v > this.Q >> 1n)
            v -= this.Q;
        return Number(v);
    }
    l2sq(v) {
        let s = 0;
        for (const p of v)
            for (const x of p)
                s += this.centeredNum(x) ** 2;
        return s;
    }
    // y をガウス分布から (ρ' と κ から決定的に作る。Box–Muller。おもちゃ)
    expandMaskGauss(rhoPrime, kappa) {
        const y = [];
        for (let i = 0; i < this.L; i++) {
            const buf = this.shake256(this.concat(rhoPrime, new Uint8Array([(kappa + i) & 0xff, ((kappa + i) >> 8) & 0xff, 0x47])), this.N * 4);
            const dv = new DataView(buf.buffer, buf.byteOffset, buf.byteLength);
            const p = new Array(this.N);
            for (let j = 0; j < this.N; j += 2) {
                const u1 = (dv.getUint32(j * 4, true) + 1) / 4294967297;
                const u2 = dv.getUint32(j * 4 + 4, true) / 4294967296;
                const r = Math.sqrt(-2 * Math.log(u1));
                p[j] = this.mod(BigInt(Math.round(this.SIGMA * r * Math.cos(2 * Math.PI * u2))), this.Q);
                p[j + 1] = this.mod(BigInt(Math.round(this.SIGMA * r * Math.sin(2 * Math.PI * u2))), this.Q);
            }
            y.push(p);
        }
        return y;
    }
    // 棄却サンプリング用の [0, 1) の乱数 (これも決定的)
    uniform01(rhoPrime, kappa) {
        const b = this.shake256(this.concat(rhoPrime, new Uint8Array([kappa & 0xff, (kappa >> 8) & 0xff, 0x55])), 8);
        const dv = new DataView(b.buffer, b.byteOffset, 8);
        return (dv.getUint32(0, true) * 2097152 + (dv.getUint32(4, true) >>> 11)) / 9007199254740992;
    }
    // z をライス符号で: 符号 1bit + 下位 L bit + 上位を 1 の連続 (0 で終わり)
    packZRice(z) {
        const L = this.RICE_L;
        const out = [];
        let acc = 0, n = 0;
        const put = (bit) => {
            acc |= bit << n;
            if (++n === 8) {
                out.push(acc);
                acc = 0;
                n = 0;
            }
        };
        for (const p of z)
            for (const x of p) {
                const c = this.centeredNum(x);
                const a = Math.abs(c);
                put(c < 0 ? 1 : 0);
                for (let i = 0; i < L; i++)
                    put((a >> i) & 1);
                for (let i = 0; i < a >> L; i++)
                    put(1);
                put(0);
            }
        if (n)
            out.push(acc);
        return Uint8Array.from(out);
    }
    unpackZRice(buf) {
        const L = this.RICE_L;
        let pos = 0;
        const get = () => {
            const byte = buf[pos >> 3];
            if (byte === undefined)
                throw new Error("短い");
            const b = (byte >> (pos & 7)) & 1;
            pos++;
            return b;
        };
        try {
            const z = [];
            for (let i = 0; i < this.L; i++) {
                const p = new Array(this.N);
                for (let j = 0; j < this.N; j++) {
                    const s = get();
                    let a = 0;
                    for (let k = 0; k < L; k++)
                        a |= get() << k;
                    let hi = 0;
                    while (get())
                        if (++hi > 64)
                            return null;
                    a += hi << L;
                    if (s && a === 0)
                        return null; // -0 は認めない (署名を一意に)
                    p[j] = this.mod(BigInt(s ? -a : a), this.Q);
                }
                z.push(p);
            }
            if (Math.ceil(pos / 8) !== buf.length)
                return null; // 余分なバイトなし
            if (pos & 7 && buf[buf.length - 1] >> (pos & 7))
                return null; // 余りのビットは 0
            return z;
        }
        catch {
            return null;
        }
    }
    // ヒント (ゴロム符号) と z (ライス符号) を 1 本のビット列に
    //   ヒント: 1 の個数 7bit + 位置の差 (下位 4bit + 上位を 1 の連続)。位置は K 本をつなげて数える
    packHintAndZ(hints, z) {
        const out = [];
        let acc = 0, n = 0;
        const put = (v, bits) => {
            for (let i = 0; i < bits; i++) {
                acc |= ((v >> i) & 1) << n;
                if (++n === 8) {
                    out.push(acc);
                    acc = 0;
                    n = 0;
                }
            }
        };
        const pos = [];
        hints.forEach((h, i) => h.forEach((x, j) => x && pos.push(i * this.N + j)));
        put(pos.length, 7);
        let prev = -1;
        for (const q of pos) {
            const g = q - prev - 1;
            put(g & 15, 4);
            for (let i = 0; i < g >> 4; i++)
                put(1, 1);
            put(0, 1);
            prev = q;
        }
        const L = this.RICE_L;
        for (const p of z)
            for (const x of p) {
                const c = this.centeredNum(x);
                const a = Math.abs(c);
                put(c < 0 ? 1 : 0, 1);
                put(a & ((1 << L) - 1), L);
                for (let i = 0; i < a >> L; i++)
                    put(1, 1);
                put(0, 1);
            }
        if (n)
            out.push(acc);
        return Uint8Array.from(out);
    }
    unpackHintAndZ(buf) {
        let pos = 0;
        const get = (bits) => {
            let v = 0;
            for (let i = 0; i < bits; i++) {
                const byte = buf[pos >> 3];
                if (byte === undefined)
                    throw new Error("短い");
                v |= ((byte >> (pos & 7)) & 1) << i;
                pos++;
            }
            return v;
        };
        try {
            const hints = Array.from({ length: this.K }, () => new Array(this.N).fill(0));
            const cnt = get(7);
            if (cnt > this.OMEGA)
                return null;
            let prev = -1;
            for (let i = 0; i < cnt; i++) {
                let g = get(4);
                let hi = 0;
                while (get(1))
                    if (++hi > this.K * 16)
                        return null;
                g += hi << 4;
                const q = prev + 1 + g;
                if (q >= this.K * this.N)
                    return null;
                hints[Math.floor(q / this.N)][q % this.N] = 1;
                prev = q;
            }
            const L = this.RICE_L;
            const z = [];
            for (let i = 0; i < this.L; i++) {
                const p = new Array(this.N);
                for (let j = 0; j < this.N; j++) {
                    const s = get(1);
                    let a = get(L);
                    let hi = 0;
                    while (get(1))
                        if (++hi > 64)
                            return null;
                    a += hi << L;
                    if (s && a === 0)
                        return null;
                    p[j] = this.mod(BigInt(s ? -a : a), this.Q);
                }
                z.push(p);
            }
            if (Math.ceil(pos / 8) !== buf.length)
                return null;
            if (pos & 7 && buf[buf.length - 1] >> (pos & 7))
                return null;
            return { hints, z };
        }
        catch {
            return null;
        }
    }
    // FIPS 204 どおりの厳しいヒントの読み出し (位置は昇順、使わない所は 0)
    unpackHintStrict(buf) {
        const hints = [];
        let idx = 0;
        for (let i = 0; i < this.K; i++) {
            const h = new Array(this.N).fill(0);
            const limit = buf[this.OMEGA + i];
            if (limit < idx || limit > this.OMEGA)
                return null;
            const first = idx;
            while (idx < limit) {
                if (idx > first && buf[idx - 1] >= buf[idx])
                    return null;
                h[buf[idx]] = 1;
                idx++;
            }
            hints.push(h);
        }
        for (let i = idx; i < this.OMEGA; i++)
            if (buf[i] !== 0)
                return null;
        return hints;
    }
    // ===== Sign (改造: y をガウス分布、z をライス符号) =====
    sign(skBytes, msg) {
        const sk = this.decodeSk(skBytes);
        const A = this.expandA(sk.rho);
        const s1Ntt = this.vecNtt(sk.s1);
        const s2Ntt = this.vecNtt(sk.s2);
        const t0Ntt = this.vecNtt(sk.t0);
        const mu = this.shake256(this.concat(sk.tr, msg), 64);
        const rhoPrime = this.shake256(this.concat(sk.K, mu), 64);
        const a = this.ALPHA;
        const M = Math.exp(12 / a + 1 / (2 * a * a));
        const sigma2 = this.SIGMA ** 2;
        let kappa = 0;
        for (let attempt = 1; attempt <= 10000; attempt++) {
            const y = this.expandMaskGauss(rhoPrime, kappa);
            const u = this.uniform01(rhoPrime, kappa);
            kappa += this.L;
            const w = this.vecInvNtt(this.matVecNtt(A, this.vecNtt(y)));
            const w1 = this.vecHighBits(w);
            const cTilde = this.shake256(this.concat(mu, this.packW1(w1)), 32);
            const cNtt = this.ntt(this.sampleInBall(cTilde));
            const cs1 = this.vecInvNtt(s1Ntt.map((p) => this.polyPointwise(cNtt.slice(), p)));
            const z = this.vecAdd(y, cs1);
            // ガウス分布の棄却サンプリング: z が c·s1 を含まないように見せる
            const v2 = this.l2sq(cs1);
            if (Math.sqrt(v2) > this.TBOUND)
                continue;
            let dot = 0;
            for (let i = 0; i < this.L; i++)
                for (let j = 0; j < this.N; j++)
                    dot += this.centeredNum(z[i][j]) * this.centeredNum(cs1[i][j]);
            if (u >= Math.exp((-2 * dot + v2) / (2 * sigma2)) / M)
                continue;
            if (Math.sqrt(this.l2sq(z)) > this.L2_BOUND)
                continue;
            // ここから下は元の Dilithium2 と同じ (Bai–Galbraith とヒント)
            const cs2 = this.vecInvNtt(s2Ntt.map((p) => this.polyPointwise(cNtt.slice(), p)));
            const wMinusCs2 = this.vecSub(w, cs2);
            const r0 = this.vecLowBits(wMinusCs2);
            if (!this.vecChkNorm(r0.map((p) => p.map((c) => this.mod(c, this.Q))), this.GAMMA2 - this.BETA))
                continue;
            const ct0 = this.vecInvNtt(t0Ntt.map((p) => this.polyPointwise(cNtt.slice(), p)));
            // FIPS 204 では ‖c·t0‖∞ < γ2 も確認する (元のコードにはなかった)
            if (!this.vecChkNorm(ct0, this.GAMMA2))
                continue;
            const { hints, count } = this.vecMakeHint(ct0, wMinusCs2);
            if (count > this.OMEGA)
                continue;
            this.lastAttempts = attempt;
            if (this.HINT_GOLOMB)
                return this.concat(cTilde, this.packHintAndZ(hints, z));
            return this.concat(cTilde, this.packZRice(z), this.packHint(hints));
        }
        return null;
    }
    // ===== Verify (改造: z はライス符号、ノルムは ℓ2 で確認) =====
    verify(pkBytes, msg, sig) {
        try {
            const hintLen = this.OMEGA + this.K;
            if (sig.length < 32 + (this.HINT_GOLOMB ? 1 : hintLen))
                return false;
            const pk = this.decodePk(pkBytes);
            const A = this.expandA(pk.rho);
            const cTilde = sig.slice(0, 32);
            let z, hints;
            if (this.HINT_GOLOMB) {
                const r = this.unpackHintAndZ(sig.slice(32));
                if (!r)
                    return false;
                ({ z, hints } = r);
            }
            else {
                z = this.unpackZRice(sig.slice(32, sig.length - hintLen));
                hints = this.unpackHintStrict(sig.slice(sig.length - hintLen));
            }
            if (!z || !hints)
                return false;
            if (Math.sqrt(this.l2sq(z)) > this.L2_BOUND)
                return false;
            const cNtt = this.ntt(this.sampleInBall(cTilde));
            const tr = this.shake256(pkBytes, 64);
            const mu = this.shake256(this.concat(tr, msg), 64);
            const Az = this.vecInvNtt(this.matVecNtt(A, this.vecNtt(z)));
            const t1Ntt = this.vecNtt(pk.t1.map((p) => p.map((c) => this.mod(c * (1n << BigInt(this.D)), this.Q))));
            const ct1 = this.vecInvNtt(t1Ntt.map((p) => this.polyPointwise(cNtt.slice(), p)));
            const w1Prime = this.vecUseHint(hints, this.vecSub(Az, ct1));
            const cTildeCheck = this.shake256(this.concat(mu, this.packW1(w1Prime)), 32);
            for (let i = 0; i < 32; i++)
                if (cTilde[i] !== cTildeCheck[i])
                    return false;
            return true;
        }
        catch {
            return false;
        }
    }
    // ===== Unpack helpers for verify =====
    unpackZ(buf) {
        const z = [];
        let off = 0;
        const mask = 0x3ffff; // 18bit
        for (let i = 0; i < this.L; i++) {
            const p = new Array(this.N);
            for (let j = 0; j < this.N; j += 4) {
                const b = buf.slice(off, off + 9);
                off += 9;
                const v0 = (b[0] | (b[1] << 8) | (b[2] << 16)) & mask;
                const v1 = ((b[2] >> 2) | (b[3] << 6) | (b[4] << 14)) & mask;
                const v2 = ((b[4] >> 4) | (b[5] << 4) | (b[6] << 12)) & mask;
                const v3 = ((b[6] >> 6) | (b[7] << 2) | (b[8] << 10)) & mask;
                p[j] = this.mod(this.GAMMA1 - BigInt(v0), this.Q);
                p[j + 1] = this.mod(this.GAMMA1 - BigInt(v1), this.Q);
                p[j + 2] = this.mod(this.GAMMA1 - BigInt(v2), this.Q);
                p[j + 3] = this.mod(this.GAMMA1 - BigInt(v3), this.Q);
            }
            z.push(p);
        }
        return z;
    }
    unpackHint(buf) {
        const hints = [];
        let idx = 0;
        for (let i = 0; i < this.K; i++) {
            const h = new Array(this.N).fill(0);
            const limit = buf[this.OMEGA + i];
            if (limit < idx || limit > this.OMEGA)
                return null;
            while (idx < limit) {
                if (buf[idx] >= this.N)
                    return null;
                h[buf[idx]] = 1;
                idx++;
            }
            hints.push(h);
        }
        return hints;
    }
    toBase64(arr) {
        let bin = "";
        for (let i = 0; i < arr.length; i++) {
            bin += String.fromCharCode(arr[i]);
        }
        return btoa(bin);
    }
    fromBase64(b64) {
        const bin = atob(b64);
        const arr = new Uint8Array(bin.length);
        for (let i = 0; i < bin.length; i++) {
            arr[i] = bin.charCodeAt(i);
        }
        return arr;
    }
    pkFromSk(sk) {
        const { rho, s1, s2 } = this.decodeSk(sk);
        const A = this.expandA(rho);
        const s1Ntt = this.vecNtt(s1);
        const t = this.vecAdd(this.vecInvNtt(this.matVecNtt(A, s1Ntt)), s2);
        const { t1 } = this.vecPower2Round(t);
        return this.encodePk({ rho, t1 });
    }
}
