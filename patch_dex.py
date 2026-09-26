"""
Patch the DEX files in base.apk with three fixes (each patch is searched in
every classesN.dex, since R8 moves classes between dex files per release):

1. validateIsUhdSupportedDevice() – bypass TiledMedia UHD device whitelist:
     if-nez v1, :cond_3  →  goto/16 :cond_3
   (always returns 'supported')

2. getDrmHeaderOverride() in DiagnosticsPreferenceManagerImpl – two sub-patches:
   a. Change const-string v1, "" default to const-string v1, "HDR_UHD_CMAFWV"
      (getString(key, default) now returns "HDR_UHD_CMAFWV" when pref not set)
   b. Nop out if-eqz v0, :cond_1  (bypass isDiagnosticsEnabled() guard)

3. getOverrideVideoDRM() in Headers$BuilderImpl:
   a. Nop out if-eqz v1, :cond_0  (bypass isDiagnosticsEnabled() guard)

Result: x-f1-override-video-drm: HDR_UHD_CMAFWV is always sent in CONTENT_PLAY
requests, telling the F1TV backend to serve the 4K UHD stream.

Dalvik instruction sizes:
  if-eqz/if-nez/if-lez  vAA, +CCCC  =>  4 bytes (op + reg + 16-bit offset)
  goto/16 +AAAA                      =>  4 bytes (op 0x29, 00, 16-bit offset)
  const-string vAA, string@BBBB      =>  4 bytes (op 0x1a + reg + 16-bit idx)
  nop                                =>  2 bytes (00 00)  – two nops replace 4-byte branch
"""

import zipfile, shutil, os, struct, hashlib, zlib, sys

# Usage: python patch_dex.py [base.apk] [output.apk]
APK_IN  = sys.argv[1] if len(sys.argv) > 1 else "unknown/base.apk"
APK_OUT = sys.argv[2] if len(sys.argv) > 2 else "f1tv_patched_unsigned.apk"

# ──────────────────────────────────────────────────────────────────────────────
# PATCH 1  –  validateIsUhdSupportedDevice (TiledMedia UHD whitelist bypass)
# ──────────────────────────────────────────────────────────────────────────────
# Unique context:
#   move-result-object v0  (0c 00)   ← BEFORE
#   move-result v1         (0a 01)
#   const/4 v2, #1         (12 12)
#   if-nez v1, :cond_3     (39 01 XX XX)  ← patch: → goto/16 :cond_3 (29 00 XX XX)
#   move-object v1, v0     (07 01)   ← AFTER (2 bytes past the instruction)
SEARCH_UHD   = bytes([0x0a, 0x01, 0x12, 0x12, 0x39, 0x01])
BEFORE_UHD   = bytes([0x0c, 0x00])
AFTER_UHD    = bytes([0x07, 0x01])

# ──────────────────────────────────────────────────────────────────────────────
# PATCH 2  –  getDrmHeaderOverride() in DiagnosticsPreferenceManagerImpl
# ──────────────────────────────────────────────────────────────────────────────
# Method has .locals 3  →  p0 = register 3
# Unique 18-byte fingerprint (p = start of move-result v0):
#   [p+0..1]  0a 00           move-result v0         (isDiagnosticsEnabled result)
#   [p+2..3]  1a 01           const-string v1 opcode+reg
#   [p+4..5]  XX XX           string index for ""    ← change to "HDR_UHD_CMAFWV"
#   [p+6..7]  38 00           if-eqz v0 opcode+reg   ← nop
#   [p+8..9]  XX XX           branch offset           ← nop
#   [p+10..11] 54 30          iget-object v0, p0     (0x54=iget-object, reg3 → byte=0x30)
#   [p+12..13] XX XX          field index
#   [p+14..15] 1a 02          const-string v2 opcode+reg
#   [p+16..17] KEY_LO KEY_HI  string index for "key.diagnostics.streamHeaderOverride"
# Before p: invoke-interface {v0}, isDiagnosticsEnabled() ends with 00 00 (v0 register byte + pad)
SEARCH_DRM = bytes([0x0a, 0x00, 0x1a, 0x01])  # move-result v0, const-string v1 opcode+reg

# ──────────────────────────────────────────────────────────────────────────────
# PATCH 3  –  getOverrideVideoDRM() in Headers$BuilderImpl
# ──────────────────────────────────────────────────────────────────────────────
# Method has .locals 2  →  p0 = register 2
# Fingerprint (p = start of move-result v1):
#   [p-6..-5]  72 10          invoke-interface, 1 arg    ← BEFORE (isDiagnosticsEnabled)
#   [p-2..-1]  01 00          register byte (v1) + pad
#   [p+0..1]   0a 01          move-result v1
#   [p+2..3]   38 01          if-eqz v1 opcode+reg       ← nop
#   [p+4..5]   XX XX          branch offset               ← nop
#   [p+6..7]   07 01          move-object v1, v0         ← AFTER
SEARCH_OVERR  = bytes([0x0a, 0x01, 0x38, 0x01])  # move-result v1, if-eqz v1 opcode+reg
BEFORE_OVERR  = bytes([0x01, 0x00])               # end of invoke-interface {v1}
AFTER_OVERR   = bytes([0x07, 0x01])               # move-object v1, v0


def find_string_index(data: bytes, target: str) -> int:
    """Return the DEX string pool index of `target`, or -1 if not found."""
    string_ids_size = struct.unpack_from('<I', data, 0x38)[0]
    string_ids_off  = struct.unpack_from('<I', data, 0x3C)[0]
    target_bytes = target.encode('utf-8')
    for i in range(string_ids_size):
        off = struct.unpack_from('<I', data, string_ids_off + i * 4)[0]
        # Decode ULEB128 UTF-16 character length (we only need byte length = len(target))
        idx = off
        b = data[idx]; idx += 1
        length = b & 0x7F
        while b & 0x80:
            b = data[idx]; idx += 1
            length = (length | ((b & 0x7F) << 7))  # simplified; assumes ≤ 2 ULEB bytes
        # Read MUTF-8 content until null terminator
        end = data.index(0, idx)
        if data[idx:end] == target_bytes:
            return i
    return -1


def patch_dex(data: bytes) -> tuple[bytes, set]:
    """Apply whichever patches match in this dex. Returns (dex, applied patch numbers)."""
    patched = bytearray(data)
    applied = set()

    # Patches 2 and 3 live next to the diagnostics key; only look in the dex that has it
    uhd_str_idx = find_string_index(data, "HDR_UHD_CMAFWV")
    drm_key_idx = find_string_index(data, "key.diagnostics.streamHeaderOverride")
    has_drm = uhd_str_idx != -1 and drm_key_idx != -1
    if has_drm:
        print(f"  String 'HDR_UHD_CMAFWV' index: {uhd_str_idx} (0x{uhd_str_idx:04x})")
        print(f"  String 'key.diagnostics.streamHeaderOverride' index: {drm_key_idx} (0x{drm_key_idx:04x})")
        uhd_lo = uhd_str_idx & 0xFF
        uhd_hi = (uhd_str_idx >> 8) & 0xFF
        key_lo = drm_key_idx & 0xFF
        key_hi = (drm_key_idx >> 8) & 0xFF

    # ── Patch 1: validateIsUhdSupportedDevice ─────────────────────────────────
    pos = 0
    found_uhd = []
    while True:
        p = data.find(SEARCH_UHD, pos)
        if p == -1:
            break
        # BEFORE_UHD (0c 00) is 8 bytes before SEARCH_UHD start (2 bytes + 6-byte invoke-interface)
        before_ok = (p >= 8 and data[p-8:p-6] == BEFORE_UHD)
        after_ok  = (data[p+8:p+10] == AFTER_UHD)
        if after_ok:   # before_ok is extra validation; after_ok alone is sufficient (matches original)
            found_uhd.append(p)
        pos = p + 1
    if len(found_uhd) > 1:
        raise ValueError(f"Patch 1 (UHD whitelist): meerdere matches: {[hex(x) for x in found_uhd]}")
    if found_uhd:
        p = found_uhd[0]
        print(f"Patch 1 (UHD whitelist):        match op 0x{p:08x}")
        print(f"  Voor: {bytes(patched[p:p+10]).hex()}")
        patched[p + 4] = 0x29   # goto/16 opcode
        patched[p + 5] = 0x00   # padding (was register v1)
        # offset bytes at p+6, p+7 stay the same
        print(f"  Na:   {bytes(patched[p:p+10]).hex()}")
        applied.add(1)

    if not has_drm:
        return finish(patched, applied)

    # ── Patch 2: getDrmHeaderOverride() ──────────────────────────────────────
    # Full fingerprint search: match SEARCH_DRM + structural checks + DRM key index
    pos = 0
    found_drm = []
    while True:
        p = data.find(SEARCH_DRM, pos)
        if p == -1:
            break
        # Check structural bytes
        if data[p+6:p+8] != bytes([0x38, 0x00]):       # if-eqz v0
            pos = p + 1; continue
        if data[p+10:p+12] != bytes([0x54, 0x30]):     # iget-object v0, p0 (reg3, 0x54=iget-object)
            pos = p + 1; continue
        if data[p+14:p+16] != bytes([0x1a, 0x02]):     # const-string v2
            pos = p + 1; continue
        if data[p+16] != key_lo or data[p+17] != key_hi:  # DRM key index
            pos = p + 1; continue
        # Check before: invoke-interface {v0} ends with 00 00
        if p < 2 or data[p-2:p] != bytes([0x00, 0x00]):
            pos = p + 1; continue
        found_drm.append(p)
        pos = p + 1

    if len(found_drm) == 0:
        raise ValueError("Patch 2 (getDrmHeaderOverride): geen match gevonden!")
    if len(found_drm) > 1:
        raise ValueError(f"Patch 2 (getDrmHeaderOverride): meerdere matches: {[hex(x) for x in found_drm]}")
    p = found_drm[0]
    print(f"Patch 2 (getDrmHeaderOverride): match op 0x{p:08x}")
    print(f"  Voor: {bytes(patched[p:p+18]).hex()}")
    # 2a: change const-string v1, "" → const-string v1, "HDR_UHD_CMAFWV"
    patched[p+4] = uhd_lo
    patched[p+5] = uhd_hi
    # 2b: nop out if-eqz v0, :cond_1
    patched[p+6] = 0x00
    patched[p+7] = 0x00
    patched[p+8] = 0x00
    patched[p+9] = 0x00
    print(f"  Na:   {bytes(patched[p:p+18]).hex()}")
    applied.add(2)

    # ── Patch 3: getOverrideVideoDRM() ───────────────────────────────────────
    pos = 0
    found_overr = []
    while True:
        p = data.find(SEARCH_OVERR, pos)
        if p == -1:
            break
        before_ok = (p >= 2 and data[p-2:p] == BEFORE_OVERR)
        after_ok  = (data[p+6:p+8] == AFTER_OVERR)
        if before_ok and after_ok:
            found_overr.append(p)
        pos = p + 1

    if len(found_overr) == 0:
        raise ValueError("Patch 3 (getOverrideVideoDRM): geen match gevonden!")
    if len(found_overr) > 1:
        raise ValueError(f"Patch 3 (getOverrideVideoDRM): meerdere matches: {[hex(x) for x in found_overr]}")
    p = found_overr[0]
    print(f"Patch 3 (getOverrideVideoDRM):  match op 0x{p:08x}")
    print(f"  Voor: {bytes(patched[p:p+8]).hex()}")
    # Nop out if-eqz v1, :cond_0
    patched[p+2] = 0x00
    patched[p+3] = 0x00
    patched[p+4] = 0x00
    patched[p+5] = 0x00
    print(f"  Na:   {bytes(patched[p:p+8]).hex()}")
    applied.add(3)

    return finish(patched, applied)


def finish(patched: bytearray, applied: set) -> tuple[bytes, set]:
    if not applied:
        return bytes(patched), applied
    # ── Update DEX checksums ──────────────────────────────────────────────────
    sha1 = hashlib.sha1(bytes(patched[32:])).digest()
    patched[12:32] = sha1
    print(f"  SHA-1:    {sha1.hex()}")

    adler = zlib.adler32(bytes(patched[12:])) & 0xFFFFFFFF
    patched[8:12] = adler.to_bytes(4, 'little')
    print(f"  Adler-32: {adler:#010x}")

    return bytes(patched), applied


# ── Patch every dex in the APK ───────────────────────────────────────────────
patched_dexes = {}
applied_all = []
with zipfile.ZipFile(APK_IN, 'r') as zin:
    for name in zin.namelist():
        if not (name.startswith('classes') and name.endswith('.dex')):
            continue
        dex_data = zin.read(name)
        print(f"{name}: {len(dex_data)} bytes")
        new_dex, applied = patch_dex(dex_data)
        if applied:
            patched_dexes[name] = new_dex
            applied_all += sorted(applied)

for n in (1, 2, 3):
    c = applied_all.count(n)
    if c != 1:
        raise ValueError(f"Patch {n}: {c} matches over alle dex-bestanden (verwacht 1)!")

# Repack: copy all entries, replace patched dex files
tmp_out = APK_OUT + ".tmp"
with zipfile.ZipFile(APK_IN, 'r') as zin:
    with zipfile.ZipFile(tmp_out, 'w', compression=zipfile.ZIP_STORED) as zout:
        for item in zin.infolist():
            if item.filename in patched_dexes:
                zout.writestr(item, patched_dexes[item.filename])
                print(f"  {item.filename} vervangen")
            else:
                zout.writestr(item, zin.read(item.filename))

os.replace(tmp_out, APK_OUT)
print(f"\nKlaar! Patched APK: {APK_OUT}")
