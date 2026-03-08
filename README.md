# F1TV 4K UHD patch — Sony Bravia (Android TV)

Patch the F1TV app (`com.formulaone.production`) to stream in 4K UHD on a Sony
Bravia TV. By default the app only offers HD, even with a 4K Pro subscription.

> **Personal use only.** You need a valid F1TV subscription. Do not distribute
> patched APKs.

---

## How it works

F1TV gates 4K by only sending the `x-f1-override-video-drm` header in
`CONTENT_PLAY` requests when an internal diagnostics flag is enabled (which it
never is in release builds). This patch removes those two guards and hardcodes
the header value `HDR_UHD_CMAFWV`, so every stream request asks the backend for
the 4K HDR Widevine stream.

Three binary patches are applied directly to `classes4.dex`:

| # | Location | What changes |
|---|----------|--------------|
| 1 | `DeviceSupportImpl.validateIsUhdSupportedDevice()` | UHD device-whitelist always passes |
| 2 | `DiagnosticsPreferenceManagerImpl.getDrmHeaderOverride()` | Bypasses `isDiagnosticsEnabled()` guard, hardcodes `"HDR_UHD_CMAFWV"` as default |
| 3 | `Headers$BuilderImpl.getOverrideVideoDRM()` | Bypasses second `isDiagnosticsEnabled()` guard |

---

## Requirements

- Python 3.x
- Java (JRE 8+)
- [uber-apk-signer](https://github.com/patrickfav/uber-apk-signer/releases) — download `uber-apk-signer.jar`
- [Android platform-tools](https://developer.android.com/tools/releases/platform-tools) — for `adb`
- F1TV APKM file — download from [APKMirror](https://www.apkmirror.com/apk/formula-one-digital-media-limited/f1-tv/) (choose the APKM)
- Sony Bravia TV with **ADB over WiFi** enabled

### Enable ADB on Sony Bravia
1. Settings → Device Preferences → About → Build number (tap 7×)
2. Settings → Device Preferences → Developer options → USB debugging **on**
3. Settings → Device Preferences → Developer options → ADB over network **on**
4. Note the IP address shown (e.g. `192.168.1.120`)

---

## Step-by-step

### 1. Extract the APKM

An APKM file is a ZIP. Rename it to `.zip` and extract, or use 7-Zip/unzip:

```bash
mkdir unknown
unzip F1TV_x.x.x.x.apkm -d unknown/
```

You will see `base.apk` and several `split_config.*.apk` files.

### 2. Run the patch script

Edit the paths at the top of `patch_dex.py` if needed:

```python
APK_IN  = "unknown/base.apk"
APK_OUT = "f1tv_patched_unsigned.apk"
```

Then run:

```bash
python patch_dex.py
```

Expected output:
```
classes4.dex: 10112704 bytes
  String 'HDR_UHD_CMAFWV' index: 14556 (0x38dc)
  String 'key.diagnostics.drmHeaderOverride' index: 55152 (0xd770)
Patch 1 (UHD whitelist):        match op 0x003fe6de
Patch 2 (getDrmHeaderOverride): match op 0x003773be
Patch 3 (getOverrideVideoDRM):  match op 0x0034bdba
  SHA-1:    ...
  Adler-32: ...
Klaar! Patched APK: f1tv_patched_unsigned.apk
```

If a patch reports "geen match gevonden", the app structure changed in this
version — see [Updating for a new version](#updating-for-a-new-version).

### 3. Create a signing keystore

You only need to do this once. The keystore is yours — keep it safe for future
re-installs.

```bash
keytool -genkeypair \
  -keystore f1tv.keystore \
  -alias f1tv \
  -keyalg RSA -keysize 2048 -validity 10000 \
  -storepass android -keypass android \
  -dname "CN=F1TV,O=Patch,C=NL"
```

### 4. Sign the APKs

Sign the patched base APK:

```bash
java -jar uber-apk-signer.jar \
  --apks f1tv_patched_unsigned.apk \
  --ks f1tv.keystore --ksAlias f1tv \
  --ksPass android --ksKeyPass android \
  --out .
```

Sign the architecture split (Sony Bravia uses `armeabi-v7a`):

```bash
java -jar uber-apk-signer.jar \
  --apks unknown/split_config.armeabi_v7a.apk \
  --ks f1tv.keystore --ksAlias f1tv \
  --ksPass android --ksKeyPass android \
  --allowResign --out .
```

This produces:
- `f1tv_patched_unsigned-aligned-signed.apk`
- `split_config.armeabi_v7a-aligned-signed.apk`

### 5. Connect ADB to the TV

```bash
adb connect 192.168.1.120:5555   # use your TV's IP
adb devices                       # should show the TV as "device"
```

### 6. Uninstall the existing F1TV app

```bash
adb uninstall com.formulaone.production
```

### 7. Install the patched app

```bash
adb install-multiple \
  f1tv_patched_unsigned-aligned-signed.apk \
  split_config.armeabi_v7a-aligned-signed.apk
```

### 8. Verify 4K is active

Start playing any content, then run:

```bash
adb logcat -d | grep "4k layer"
```

You should see:
```
hwcomposer: buffer is 2k but exist 4k layer
```

This confirms the TV is rendering a 4K video layer. UHD will also appear in the
in-app quality settings.

---

## Updating for a new version

1. Download the new APKM and extract to `unknown/`
2. Run `python patch_dex.py` — it will report an error for any pattern that
   changed
3. If a patch fails, inspect the updated smali to find the new byte pattern:
   - Patch 2: search for `key.diagnostics.drmHeaderOverride` in
     `DiagnosticsPreferenceManagerImpl.smali`
   - Patch 3: search for `isDiagnosticsEnabled` call followed by `if-eqz`
     followed by `move-object v1, v0` in `Headers$BuilderImpl.smali`
4. Re-sign with your **existing** keystore (no need to uninstall if same cert)
5. Install with `adb install-multiple` (add `-r` flag to replace without
   uninstalling if signature matches)

### Decompiling smali for inspection

```bash
java -jar apktool.jar d unknown/base.apk -o unknown/base -f
# smali files in: unknown/base/smali_classes*/
```

---

## Technical notes

### Why not apktool rebuild?

The app uses resource IDs that cause `aapt2` to fail during rebuild. Binary DEX
patching is the only reliable approach without a full AOSP build environment.

### Dalvik opcodes used

| Mnemonic | Opcode |
|----------|--------|
| `iget-object` | `0x54` (not 0x52 — that is plain `iget`) |
| `if-eqz` | `0x38` |
| `if-nez` | `0x39` |
| `goto/16` | `0x29` |
| `const-string` | `0x1a` |
| nop | `0x00 0x00` |

Register encoding for `iget-object vA, vB`: byte = `(vB << 4) | vA`.
With `.locals 3`, p0 = register 3, so byte = `0x30` for vA=0.

After patching, SHA-1 (over bytes 32..end) and Adler-32 (over bytes 12..end)
in the DEX header must be recalculated — `patch_dex.py` does this automatically.

---

## Tested on

| App version | TV model | Date | Result |
|-------------|----------|------|--------|
| 3.0.47.1 | Sony Bravia 4K VH2 | 2026-03-08 | ✅ 4K UHD working |
