/** 13.52 libkernel bootstrap — low PLT imports, no high IAT (+0x3cb8cc8). */
import { int64 } from "./int64.mjs";

const SCE_MAGIC = 0x1d3d154f;
const SCE_ELF_OFF = 0x160;
const POOPS_SCAN_LO = 0x10000;
const POOPS_OOM_LO = 0x2f000;
const POOPS_OOM_HI = 0x34000;

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
