# polpNO — PS4 13.52-only build

This is a firmware-locked refactor of the supplied `polpNO-use` project.

## Changes

- Only accepts a PS4 user-agent reporting **13.52**.
- Removes firmware selection/fallback logic from the entry point.
- Uses a dedicated `ps4_13.52.mjs` configuration module.
- Uses a dedicated `chain_13.52.mjs` entry point.
- Pins the patch source to:
  `https://github.com/OptiTronOffical/polpNO-use/blob/aec207b31694bb182e032033a1bfab0863c171dd/patches/1352.bin`
- The service worker fetches `/patches/1352.bin` from that exact commit when requested.
- Older patch blobs are not included.
- The Lapse page is retained only as a non-chain informational page; the 13.52 entry point launches the Poops chain.

## Important verification note

The GitHub file is confirmed to be **712 bytes**, but the binary contents could not be retrieved by the build environment. The project therefore does not fabricate a local 712-byte file. The exact GitHub raw endpoint is used at runtime instead.

Also, the supplied 13.52 kernel-offset list has been incorporated into `ps4_13.52.mjs`, but the original project contains unresolved WebKit values (`0xDEAD....`). Those are deliberately preserved as explicit unresolved values rather than being invented. Consequently this archive is a complete 13.52-specific source refactor, **not a claim that the supplied exploit chain has been independently validated on 13.52 hardware**.
