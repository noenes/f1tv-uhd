"""
Smali-level patch for ComposerUseCaseImpl (the CONTENT_PLAY request).
Run this BEFORE patch_dex.py.

  python patch_smali.py <base.apk> <out.apk> [apktool.jar]

What it changes in preparePlaybackInternal():
  - videoType REPLAY / LIVE: first request with the forced UHD header
    (x-f1-override-video-stream); if that request fails (e.g. ER1005 for
    HD-only content) it automatically retries without that header (HD).
  - any other videoType: request without the forced header, so the server
    chooses the stream itself (HD, or a clear UHD stream when it has one).
  - a Widevine stream without license URL is treated as an error (-> fallback).
  - logs "F1UHD" lines (videoType, streamType, laUrl) for adb logcat.

Only the dex that contains ComposerUseCaseImpl is decompiled and rebuilt; the
resources are copied raw (apktool -r), so aapt2 is never involved.
"""

import os, shutil, subprocess, sys, tempfile, zipfile

APK_IN  = sys.argv[1] if len(sys.argv) > 1 else "unknown/base.apk"
APK_OUT = sys.argv[2] if len(sys.argv) > 2 else "base_smali.apk"
APKTOOL = sys.argv[3] if len(sys.argv) > 3 else "apktool.jar"

CLS     = "Lcom/avs/f1/interactors/composer/ComposerUseCaseImpl;"
SMALI   = "com/avs/f1/interactors/composer/ComposerUseCaseImpl.smali"
RESP    = "Lcom/avs/f1/net/model/play/ContentPlayResponse;"
SIG     = "(Ljava/lang/String;Ljava/util/Map;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)Lio/reactivex/Flowable;"

WRAPPER = f"""
.method private preparePlaybackInternal{SIG}
    .locals 3

    new-instance v0, Ljava/lang/StringBuilder;

    invoke-direct {{v0}}, Ljava/lang/StringBuilder;-><init>()V

    const-string v1, "videoType="

    invoke-virtual {{v0, v1}}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    invoke-virtual {{v0, p5}}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    invoke-virtual {{v0}}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    move-result-object v0

    const-string v1, "F1UHD"

    invoke-static {{v1, v0}}, Landroid/util/Log;->i(Ljava/lang/String;Ljava/lang/String;)I

    if-eqz p5, :uhd_try

    const-string v0, "REPLAY"

    invoke-virtual {{p5, v0}}, Ljava/lang/String;->equalsIgnoreCase(Ljava/lang/String;)Z

    move-result v0

    if-nez v0, :uhd_try

    const-string v0, "LIVE"

    invoke-virtual {{p5, v0}}, Ljava/lang/String;->equalsIgnoreCase(Ljava/lang/String;)Z

    move-result v0

    if-nez v0, :uhd_try

    const/4 v2, 0x1

    sput-boolean v2, {CLS}->uhdFallback:Z

    invoke-direct/range {{p0 .. p5}}, {CLS}->preparePlaybackInternalOrig{SIG}

    move-result-object v0

    const/4 v2, 0x0

    sput-boolean v2, {CLS}->uhdFallback:Z

    return-object v0

    :uhd_try
    const/4 v2, 0x0

    sput-boolean v2, {CLS}->uhdFallback:Z

    invoke-direct/range {{p0 .. p5}}, {CLS}->preparePlaybackInternalOrig{SIG}

    move-result-object v0

    const/4 v2, 0x1

    sput-boolean v2, {CLS}->uhdFallback:Z

    invoke-direct/range {{p0 .. p5}}, {CLS}->preparePlaybackInternalOrig{SIG}

    move-result-object v1

    const/4 v2, 0x0

    sput-boolean v2, {CLS}->uhdFallback:Z

    invoke-virtual {{v0, v1}}, Lio/reactivex/Flowable;->onErrorResumeNext(Lorg/reactivestreams/Publisher;)Lio/reactivex/Flowable;

    move-result-object v0

    return-object v0
.end method

"""

# Inserted right after the headers map is built in the original method
STRIP_HEADER = f"""
    sget-boolean v1, {CLS}->uhdFallback:Z

    if-eqz v1, :uhd_keep

    new-instance v1, Ljava/util/HashMap;

    invoke-direct {{v1, v0}}, Ljava/util/HashMap;-><init>(Ljava/util/Map;)V

    move-object v0, v1

    const-string v1, "x-f1-override-video-stream"

    invoke-interface {{v0, v1}}, Ljava/util/Map;->remove(Ljava/lang/Object;)Ljava/lang/Object;

    :uhd_keep
"""

# Inserted at the start of handleContentPlayResponse()
CHECK_RESPONSE = f"""
    invoke-virtual {{p1}}, {RESP}->getStreamType()Ljava/lang/String;

    move-result-object v0

    invoke-virtual {{p1}}, {RESP}->getLaUrl()Ljava/lang/String;

    move-result-object v1

    new-instance v2, Ljava/lang/StringBuilder;

    invoke-direct {{v2}}, Ljava/lang/StringBuilder;-><init>()V

    const-string v3, "streamType="

    invoke-virtual {{v2, v3}}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    invoke-virtual {{v2, v0}}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    const-string v3, " laUrl="

    invoke-virtual {{v2, v3}}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    invoke-virtual {{v2, v1}}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    invoke-virtual {{v2}}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    move-result-object v2

    const-string v3, "F1UHD"

    invoke-static {{v3, v2}}, Landroid/util/Log;->i(Ljava/lang/String;Ljava/lang/String;)I

    if-eqz v0, :uhd_resp_ok

    const-string v2, "WV"

    invoke-virtual {{v0, v2}}, Ljava/lang/String;->contains(Ljava/lang/CharSequence;)Z

    move-result v2

    if-eqz v2, :uhd_resp_ok

    if-nez v1, :uhd_resp_ok

    new-instance v2, Ljava/lang/IllegalStateException;

    const-string v3, "Widevine stream without laUrl"

    invoke-direct {{v2, v3}}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    invoke-static {{v2}}, Lio/reactivex/Flowable;->error(Ljava/lang/Throwable;)Lio/reactivex/Flowable;

    move-result-object v2

    return-object v2

    :uhd_resp_ok
"""


def patch_smali(s: str) -> str:
    old_def = f".method private preparePlaybackInternal{SIG}"
    if s.count(old_def) != 1:
        raise ValueError("preparePlaybackInternal() niet (uniek) gevonden!")

    # 1. rename the original method and put the wrapper in front of it
    s = s.replace(old_def, WRAPPER.lstrip("\n") + f".method private preparePlaybackInternalOrig{SIG}")

    # 2. strip the override header when uhdFallback is set
    i = s.index(".method private preparePlaybackInternalOrig")
    anchor = ("Lcom/avs/f1/net/api/Headers$Builder;->buildFor(Lcom/avs/f1/net/api/Api;)Ljava/util/Map;\n\n"
              "    move-result-object v0\n")
    j = s.find(anchor, i)
    if j == -1 or j > s.index(".end method", i):
        raise ValueError("headersBuilder.buildFor() niet gevonden in preparePlaybackInternal()!")
    j += len(anchor)
    s = s[:j] + STRIP_HEADER + s[j:]

    # 3. reject a Widevine stream without license URL
    i = s.index(".method private handleContentPlayResponse(")
    if ".locals 9" not in s[i:i + 200]:
        raise ValueError("handleContentPlayResponse() heeft onverwachte .locals")
    j = s.index(".end annotation\n", i) + len(".end annotation\n")
    s = s[:j] + CHECK_RESPONSE + s[j:]

    # 4. static flag
    k = s.index("# static fields")
    k = s.index("\n", k) + 1
    return s[:k] + ".field private static uhdFallback:Z\n\n" + s[k:]


def main():
    needle = CLS.encode()
    with zipfile.ZipFile(APK_IN) as z:
        dex_name = next(n for n in z.namelist()
                        if n.startswith("classes") and n.endswith(".dex") and needle in z.read(n))
        print(f"ComposerUseCaseImpl zit in {dex_name}")
        work = tempfile.mkdtemp(prefix="f1tv_smali_")
        mini = os.path.join(work, "mini.apk")
        with zipfile.ZipFile(mini, "w") as zm:
            for n in ("AndroidManifest.xml", "resources.arsc"):
                zm.writestr(n, z.read(n))
            zm.writestr("classes.dex", z.read(dex_name))

    src = os.path.join(work, "src")
    subprocess.run(["java", "-jar", APKTOOL, "d", "-r", "-f", mini, "-o", src], check=True)
    path = os.path.join(src, "smali", *SMALI.split("/"))
    with open(path, encoding="utf-8") as f:
        s = f.read()
    with open(path, "w", encoding="utf-8") as f:
        f.write(patch_smali(s))
    print("Smali gepatcht, opnieuw bouwen...")

    built = os.path.join(work, "built.apk")
    subprocess.run(["java", "-jar", APKTOOL, "b", src, "-o", built], check=True)
    with zipfile.ZipFile(built) as zb:
        new_dex = zb.read("classes.dex")

    with zipfile.ZipFile(APK_IN) as zin, zipfile.ZipFile(APK_OUT, "w", zipfile.ZIP_STORED) as zout:
        for item in zin.infolist():
            zout.writestr(item, new_dex if item.filename == dex_name else zin.read(item.filename))
    shutil.rmtree(work, ignore_errors=True)
    print(f"\nKlaar! {dex_name} vervangen: {APK_OUT}")


if __name__ == "__main__":
    main()
