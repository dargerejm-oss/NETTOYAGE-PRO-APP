# -*- coding: utf-8 -*-
"""
NETTOYAGE ANDROID PRO  -  JM.DARGERE
Nettoyage en profondeur du stockage d'un telephone Android (Termux + Flask + page web).

Lancement : bash start.sh   puis ouvrir  http://localhost:8877  dans le navigateur du telephone.

Principes de securite :
  - rien en dehors du stockage partage (/storage/emulated/0) ;
  - par defaut, "A la corbeille" : les fichiers sont deplaces dans _CORBEILLE_NETTOYAGE et restaurables ;
  - suppression definitive seulement apres une confirmation explicite ;
  - les photos floues / captures ne sont JAMAIS cochees d'avance.
"""
import os
import re
import io
import sys
import json
import time
import shutil
import hashlib
import threading
import subprocess
from datetime import datetime

from flask import Flask, jsonify, request, send_file, send_from_directory, abort

try:
    from PIL import Image, ImageFilter, ImageStat, ImageOps
    HAVE_PIL = True
except Exception:
    HAVE_PIL = False

HERE = os.environ.get("NAP_HERE") or os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.realpath(os.environ.get("NAP_ROOT", "/storage/emulated/0"))
PORT = int(os.environ.get("NAP_PORT", "8877"))
TRASH_NAME = "_CORBEILLE_NETTOYAGE"
TRASH = os.path.join(ROOT, TRASH_NAME)
IMG_EXT = (".jpg", ".jpeg", ".png", ".webp", ".heic", ".gif", ".bmp")
VID_EXT = (".mp4", ".mkv", ".mov", ".avi", ".3gp", ".webm")
PROTECTED_TOP = {"DCIM", "Pictures", "Music", "Movies", "Download", "Documents", "Android", "Alarms", "Notifications",
                 "Ringtones", "Podcasts", "Recordings", "Audiobooks", "Fonts"}

app = Flask(__name__, static_folder=None)

# ---------------------------------------------------------------- utilitaires
def inside_root(p):
    try:
        rp = os.path.realpath(p)
    except Exception:
        return False
    return rp != ROOT and rp.startswith(ROOT + os.sep)


def in_trash(p):
    rp = os.path.realpath(p)
    return rp == TRASH or rp.startswith(TRASH + os.sep)


def item(path, st=None):
    try:
        st = st or os.stat(path)
        return {"p": path, "n": os.path.basename(path), "s": st.st_size, "m": int(st.st_mtime),
                "d": os.path.relpath(os.path.dirname(path), ROOT)}
    except Exception:
        return None


def walk_files(base, skip=None, stop=None):
    """Parcourt les fichiers (sans suivre les liens) ; skip(path_dir)->True pour ignorer un dossier."""
    stack = [base]
    while stack:
        if stop is not None and stop.is_set():
            return
        d = stack.pop()
        try:
            it = os.scandir(d)
        except Exception:
            continue
        with it:
            for e in it:
                try:
                    if e.is_symlink():
                        continue
                    if e.is_dir(follow_symlinks=False):
                        if e.path == TRASH or (skip and skip(e.path)):
                            continue
                        stack.append(e.path)
                    elif e.is_file(follow_symlinks=False):
                        yield e
                except Exception:
                    continue


def dir_size(d, stop=None):
    tot = 0
    for e in walk_files(d, stop=stop):
        try:
            tot += e.stat(follow_symlinks=False).st_size
        except Exception:
            pass
    return tot


def is_android_private(p):
    rel = os.path.relpath(p, ROOT).replace("\\", "/")
    return rel == "Android" or rel.startswith("Android/")


# ---------------------------------------------------------------- tache de fond
JOB = {"running": False, "kind": "", "pct": 0.0, "msg": "", "t0": 0.0, "t1": 0.0, "result": None, "error": "", "id": 0}
STOP = threading.Event()
LOCK = threading.Lock()


def set_prog(pct=None, msg=None):
    if pct is not None:
        JOB["pct"] = max(0.0, min(100.0, pct))
    if msg is not None:
        JOB["msg"] = msg


def run_job(kind, fn, *args):
    with LOCK:
        if JOB["running"]:
            return False
        STOP.clear()
        JOB.update(running=True, kind=kind, pct=0.0, msg="", t0=time.time(), t1=0.0, result=None, error="", id=JOB["id"] + 1)

    def work():
        try:
            JOB["result"] = fn(*args)
        except Exception as e:                       # jamais de plantage silencieux
            JOB["error"] = "%s" % e
        finally:
            JOB["t1"] = time.time()
            JOB["pct"] = 100.0
            JOB["running"] = False
    threading.Thread(target=work, daemon=True).start()
    return True


# ---------------------------------------------------------------- analyses
def scan_overview(path=None):
    base = os.path.realpath(path) if path else ROOT
    if not (base == ROOT or inside_root(base)):
        raise ValueError("chemin refuse")
    entries = []
    try:
        names = sorted(os.listdir(base))
    except Exception as e:
        raise ValueError("lecture impossible : %s" % e)
    n = max(1, len(names))
    for i, name in enumerate(names):
        if STOP.is_set():
            break
        p = os.path.join(base, name)
        set_prog(100.0 * i / n, name)
        try:
            if os.path.islink(p):
                continue
            if os.path.isdir(p):
                if p == TRASH:
                    continue
                entries.append({"p": p, "n": name, "s": dir_size(p, STOP), "dir": True,
                                "m": int(os.stat(p).st_mtime), "d": os.path.relpath(base, ROOT)})
            else:
                it = item(p)
                if it:
                    it["dir"] = False
                    entries.append(it)
        except Exception:
            continue
    entries.sort(key=lambda x: -x["s"])
    total = sum(e["s"] for e in entries)
    return {"type": "folder", "base": base, "root": ROOT, "total": total, "items": entries, "stopped": STOP.is_set()}


def scan_big(min_mb=50):
    minb = int(min_mb) * 1024 * 1024
    found = []
    cnt = 0
    for e in walk_files(ROOT, stop=STOP):
        cnt += 1
        if cnt % 400 == 0:
            set_prog(min(95, cnt / 800.0), os.path.relpath(os.path.dirname(e.path), ROOT))
        try:
            st = e.stat(follow_symlinks=False)
        except Exception:
            continue
        if st.st_size >= minb:
            it = item(e.path, st)
            if it:
                found.append(it)
    found.sort(key=lambda x: -x["s"])
    return {"type": "list", "groups": [{"k": "g_big", "x": "%d Mo" % int(min_mb), "items": found[:400], "sel": False}],
            "stopped": STOP.is_set()}


def quick_hash(path, size):
    h = hashlib.sha1()
    h.update(str(size).encode())
    with open(path, "rb") as f:
        h.update(f.read(65536))
        if size > 131072:
            f.seek(size - 65536)
            h.update(f.read(65536))
    return h.hexdigest()


def full_hash(path):
    h = hashlib.sha1()
    with open(path, "rb") as f:
        while True:
            b = f.read(1 << 20)
            if not b:
                break
            h.update(b)
    return h.hexdigest()


def scan_dups(min_kb=50):
    minb = int(min_kb) * 1024
    by_size = {}
    cnt = 0
    for e in walk_files(ROOT, skip=lambda d: is_android_private(d) or os.path.basename(d) == ".thumbnails", stop=STOP):
        cnt += 1
        if cnt % 400 == 0:
            set_prog(min(35, cnt / 1500.0), "")
        try:
            st = e.stat(follow_symlinks=False)
        except Exception:
            continue
        if st.st_size >= minb:
            by_size.setdefault(st.st_size, []).append((e.path, st))
    cand = [(s, v) for s, v in by_size.items() if len(v) > 1]
    todo = sum(len(v) for s, v in cand) or 1
    done = 0
    groups = []
    for size, files in cand:
        if STOP.is_set():
            break
        quick = {}
        for p, st in files:
            done += 1
            set_prog(35 + 60.0 * done / todo, os.path.basename(p))
            try:
                quick.setdefault(quick_hash(p, size), []).append((p, st))
            except Exception:
                continue
        for qs in quick.values():
            if len(qs) < 2:
                continue
            full = {}
            for p, st in qs:
                try:
                    full.setdefault(full_hash(p), []).append((p, st))
                except Exception:
                    continue
            for fs in full.values():
                if len(fs) > 1:
                    fs.sort(key=lambda x: (x[1].st_mtime, len(x[0])))
                    its = [item(p, st) for p, st in fs]
                    its = [i for i in its if i]
                    if len(its) > 1:
                        its[0]["keep"] = True        # le plus ancien est gardé
                        groups.append(its)
    groups.sort(key=lambda g: -g[0]["s"] * (len(g) - 1))
    saving = sum(g[0]["s"] * (len(g) - 1) for g in groups)
    return {"type": "dups", "groups": groups[:600], "saving": saving, "stopped": STOP.is_set()}


SOCIAL = [
    ("WhatsApp", ["WhatsApp/Media", "Android/media/com.whatsapp/WhatsApp/Media", "Android/media/com.whatsapp.w4b/WhatsApp Business/Media"]),
    ("Telegram", ["Telegram", "Android/media/org.telegram.messenger/Telegram"]),
    ("Line", ["Android/media/jp.naver.line.android", "LINE", "Pictures/LINE", "Download/LINE"]),
    ("Messenger", ["Pictures/Messenger", "Android/media/com.facebook.orca"]),
    ("Instagram", ["Pictures/Instagram", "Android/media/com.instagram.android"]),
    ("Facebook", ["Pictures/Facebook", "Android/media/com.facebook.katana"]),
    ("Viber", ["Viber", "Android/media/com.viber.voip"]),
    ("Signal", ["Pictures/Signal", "Android/media/org.thoughtcrime.securesms"]),
    ("Snapchat", ["Snapchat", "Pictures/Snapchat"]),
    ("TikTok", ["Movies/TikTok", "Pictures/TikTok"]),
]


def scan_social(age_days=60, with_sent=False):
    cutoff = time.time() - int(age_days) * 86400
    groups = []
    seen_roots = set()
    n = len(SOCIAL)
    for i, (app_name, rels) in enumerate(SOCIAL):
        if STOP.is_set():
            break
        set_prog(100.0 * i / n, app_name)
        its = []
        for rel in rels:
            base = os.path.join(ROOT, rel)
            if not os.path.isdir(base) or base in seen_roots:
                continue
            seen_roots.add(base)
            for e in walk_files(base, stop=STOP):
                try:
                    st = e.stat(follow_symlinks=False)
                except Exception:
                    continue
                if e.name.startswith(".") or e.name.lower() == ".nomedia":
                    continue
                if not with_sent and re.search(r"[/\\](Sent|Envoy)", e.path):
                    continue
                if st.st_mtime <= cutoff:
                    it = item(e.path, st)
                    if it:
                        its.append(it)
        if its:
            its.sort(key=lambda x: -x["s"])
            groups.append({"k": "g_app", "x": app_name, "items": its[:500], "sel": False,
                           "total": sum(x["s"] for x in its), "count": len(its)})
    return {"type": "list", "groups": groups, "stopped": STOP.is_set()}


def blur_score(path):
    im = Image.open(path)
    im.draft("L", (640, 640))
    im = ImageOps.exif_transpose(im).convert("L")
    im.thumbnail((640, 640))
    lap = im.filter(ImageFilter.Kernel((3, 3), [0, 1, 0, 1, -4, 1, 0, 1, 0], scale=1, offset=128))
    return ImageStat.Stat(lap).var[0]


def scan_photos(blur_thr=45.0, small_mp=0.3):
    shots, blurry, small = [], [], []
    files = []
    for e in walk_files(ROOT, skip=lambda d: is_android_private(d) or os.path.basename(d) == ".thumbnails", stop=STOP):
        if e.name.lower().endswith(IMG_EXT):
            files.append(e.path)
    n = max(1, len(files))
    for i, p in enumerate(files):
        if STOP.is_set():
            break
        if i % 20 == 0:
            set_prog(100.0 * i / n, os.path.basename(p))
        low = p.lower()
        it = item(p)
        if not it:
            continue
        rel = os.path.relpath(p, ROOT).replace("\\", "/")
        if re.search(r"screenshot|capture d.cran|screen_?shot", low) and "/screenshots/" in low.replace("\\", "/") + "/" \
                or os.path.basename(low).startswith(("screenshot_", "screenshot-", "capture_d")):
            shots.append(it)
            continue
        if not HAVE_PIL or low.endswith((".heic", ".gif")):
            continue
        try:
            with Image.open(p) as im:
                w, h = im.size
            if w * h < small_mp * 1e6 and it["s"] > 0:
                it["x"] = "%dx%d" % (w, h)
                small.append(it)
                continue
            if rel.upper().startswith(("DCIM/", "PICTURES/")) and it["s"] > 40 * 1024:
                sc = blur_score(p)
                if sc < blur_thr:
                    it["x"] = "%.0f" % sc
                    blurry.append(it)
        except Exception:
            continue
    blurry.sort(key=lambda x: float(x.get("x", 0)))
    return {"type": "list", "groups": [
        {"k": "g_shots", "items": sorted(shots, key=lambda x: -x["s"])[:800], "sel": False, "thumbs": True},
        {"k": "g_blur", "items": blurry[:600], "sel": False, "thumbs": True},
        {"k": "g_small", "items": sorted(small, key=lambda x: -x["s"])[:600], "sel": False, "thumbs": True},
    ], "pil": HAVE_PIL, "stopped": STOP.is_set()}


# ---------------------------------------------------------------- CLE USB (photos et videos)
USB_BASE = os.environ.get("NAP_USB_BASE", "/storage")
USB_DIR = "SAUVEGARDE_TELEPHONE"


USB_DIAG = []


def sm_volumes():
    """Volumes vus par Android lui-meme (StorageManager), si l'appli tourne sous Chaquopy."""
    out = []
    try:
        from java import jclass
        app_ctx = jclass("com.chaquo.python.Python").getPlatform().getApplication()
        sm = app_ctx.getSystemService("storage")
        vols = sm.getStorageVolumes()
        for i in range(vols.size()):
            v = vols.get(i)
            try:
                d = v.getDirectory()
                path = d.getAbsolutePath() if d is not None else ""
            except Exception:
                path = ""
            out.append({"path": path, "state": str(v.getState()), "removable": bool(v.isRemovable()),
                        "primary": bool(v.isPrimary()), "uuid": str(v.getUuid()), "desc": str(v.getDescription(app_ctx))})
    except Exception as e:
        USB_DIAG.append("StorageManager indisponible : %s" % str(e)[:80])
    return out


def usb_volumes():
    """Cles / cartes branchees : /storage/<UUID> (hors stockage interne) + volumes vus par Android."""
    del USB_DIAG[:]
    out = []
    fstypes = {}
    try:
        with open("/proc/mounts") as f:
            for ln in f:
                a = ln.split()
                if len(a) > 2:
                    fstypes[a[1]] = a[2]
    except Exception:
        USB_DIAG.append("Liste des montages illisible")
    paths = []
    try:
        names = sorted(os.listdir(USB_BASE))
        USB_DIAG.append("/storage contient : " + ", ".join(names))
    except Exception as e:
        names = []
        USB_DIAG.append("/storage illisible : %s" % str(e)[:60])
    for n in names:
        if n in ("emulated", "self") or n.startswith("."):
            continue
        paths.append(os.path.join(USB_BASE, n))
    for sv in sm_volumes():
        USB_DIAG.append("Android voit : %s | %s | état %s | %s" % (sv["desc"], sv["path"] or "(pas de chemin)", sv["state"],
                                                                 "amovible" if sv["removable"] else "interne"))
        if sv["primary"] or not sv["removable"] or not sv["path"]:
            continue
        if sv["state"] != "mounted":
            USB_DIAG.append("→ la clé est vue mais pas « montée » (état : %s) : format non pris en charge (NTFS ?) ou clé à retirer et rebrancher." % sv["state"])
            continue
        if sv["path"] not in paths:
            paths.append(sv["path"])
    for p in paths:
        if not os.path.isdir(p):
            continue
        v = {"p": p, "n": os.path.basename(p), "fs": "", "free": 0, "total": 0, "w": False}
        for k, ft in fstypes.items():
            if k.endswith("/" + v["n"]):
                v["fs"] = ft
        try:
            st = os.statvfs(p)
            v["free"] = st.f_bavail * st.f_frsize
            v["total"] = st.f_blocks * st.f_frsize
        except Exception:
            pass
        try:                                         # test d'ecriture reel
            tp = os.path.join(p, ".nap_test")
            with open(tp, "w") as f:
                f.write("ok")
            os.remove(tp)
            v["w"] = True
        except Exception as e:
            v["w"] = False
            USB_DIAG.append("Écriture refusée sur %s : %s" % (p, str(e)[:60]))
        out.append(v)
    return out


DOC_EXT = (".pdf", ".doc", ".docx", ".xls", ".xlsx", ".ppt", ".pptx", ".odt", ".ods", ".txt", ".rtf", ".epub", ".csv")
MAIL_EXT = (".eml", ".msg", ".mbox", ".pst", ".vcf", ".ics")
MAIL_WORDS = ("mail", "courrier", "outlook", "thunderbird", "k9", "pieces jointes", "pièces jointes", "attachment")
CAT_TITLE = {"v": "🎞 Vidéos", "p": "🖼 Photos", "d": "📄 Documents", "m": "✉ Courrier et pièces jointes"}


def media_cat(path_lower):
    n = path_lower
    if n.endswith(MAIL_EXT):
        return "m"
    if n.endswith(DOC_EXT):
        return "m" if any(w in n for w in MAIL_WORDS) else "d"
    if n.endswith(IMG_EXT):
        return "p"
    if n.endswith(VID_EXT):
        return "v"
    return None


def scan_media(cats=("p", "v"), min_mb=0, age_days=0):
    now = time.time()
    cats = set(cats or ("p", "v"))
    by = {"v": [], "p": [], "d": [], "m": []}
    n = 0
    for e in walk_files(ROOT, skip=lambda d: is_android_private(d) or os.path.basename(d) == ".thumbnails", stop=STOP):
        c = media_cat(e.path.lower())
        if c is None or c not in cats:
            continue
        try:
            st = e.stat()
        except Exception:
            continue
        if st.st_size <= 0:
            continue
        if age_days and now - st.st_mtime < age_days * 86400:
            continue
        if min_mb and st.st_size < min_mb * 1048576:
            continue
        it = item(e.path, st)
        if it:
            by[c].append(it)
            n += 1
            if n % 500 == 0:
                set_prog(None, "%d fichiers" % n)
            if n >= 80000:
                break
    groups = []
    for c in ("v", "p", "d", "m"):
        if c in cats:
            its = sorted(by[c], key=lambda x: -x["m"])
            groups.append({"k": CAT_TITLE[c], "items": its, "sel": False, "thumbs": True,
                           "count": len(its), "total": sum(i["s"] for i in its)})
    return {"type": "list", "groups": groups, "usb": True, "stopped": STOP.is_set()}


# ---------------------------------------------------------------- NETTOYAGE AUTOMATIQUE SUR (technique uniquement)
def auto_clean():
    """Efface sans question ce qui est purement technique et se reconstruit seul :
    miniatures de galerie, dossiers cache/temp, vrais fichiers temporaires (> 1 jour), dossiers vides.
    Jamais : photos, videos, documents, .bak, .apk, restes d'applis."""
    res = scan_junk()
    now = time.time()
    safe_tmp = re.compile(r"\.(tmp|temp|crdownload|cache|dmp|log)$", re.I)
    freed, done, errs = 0, 0, 0
    todo, empty = [], []
    for g in res["groups"]:
        if g["k"] in ("g_thumb", "g_cache"):
            todo += g["items"]
        elif g["k"] == "g_tmp":
            todo += [i for i in g["items"] if safe_tmp.search(i["n"]) and now - i["m"] > 86400]
        elif g["k"] == "g_trashed":
            todo += [i for i in g["items"] if now - i["m"] > 30 * 86400]
        elif g["k"] == "g_empty":
            empty += g["items"]
    n = max(1, len(todo))
    for i, it in enumerate(todo):
        if STOP.is_set():
            break
        if i % 50 == 0:
            set_prog(100.0 * i / n, it["n"])
        p = it["p"]
        if not inside_root(p) or in_trash(p) or not os.path.isfile(p):
            continue
        try:
            sz = os.path.getsize(p)
            os.remove(p)
            freed += sz
            done += 1
        except Exception:
            errs += 1
    for it in sorted(empty, key=lambda x: -len(x["p"])):
        try:
            if inside_root(it["p"]) and os.path.isdir(it["p"]) and not os.listdir(it["p"]):
                os.rmdir(it["p"])
                done += 1
        except Exception:
            errs += 1
    return {"type": "autodone", "freed": freed, "done": done, "nerr": errs, "stopped": STOP.is_set()}


def _same(a, b):
    """Verification : meme taille + debut et fin identiques."""
    sa, sb = os.path.getsize(a), os.path.getsize(b)
    if sa != sb:
        return False
    with open(a, "rb") as fa, open(b, "rb") as fb:
        if fa.read(262144) != fb.read(262144):
            return False
        if sa > 524288:
            fa.seek(sa - 262144)
            fb.seek(sa - 262144)
            if fa.read(262144) != fb.read(262144):
                return False
    return True


def usb_copy(paths, volpath):
    vols = {v["p"]: v for v in usb_volumes()}
    v = vols.get(volpath)
    if not v or not v["w"]:
        raise RuntimeError("Clé USB introuvable ou non accessible en écriture.")
    dest_root = os.path.join(volpath, USB_DIR)
    fat = v["fs"].lower() in ("vfat", "msdos", "fat32", "fat")
    todo, total = [], 0
    for p in paths:
        rp = os.path.realpath(p)
        if inside_root(rp) and not in_trash(rp) and os.path.isfile(rp):
            todo.append(rp)
            total += os.path.getsize(rp)
    # place necessaire = ce qui n'est pas deja sur la cle
    need = 0
    for rp in todo:
        dst = os.path.join(dest_root, os.path.relpath(rp, ROOT))
        if not (os.path.isfile(dst) and os.path.getsize(dst) == os.path.getsize(rp)):
            need += os.path.getsize(rp)
    if need > v["free"] - 50 * 1048576:
        raise RuntimeError("Pas assez de place sur la clé : il faut %.1f Go, il reste %.1f Go." % (need / 1e9, v["free"] / 1e9))
    done_b, copied, skipped, failed, verified = 0, 0, 0, [], []
    for i, rp in enumerate(todo):
        if STOP.is_set():
            break
        size = os.path.getsize(rp)
        set_prog(100.0 * done_b / max(1, total), "%d/%d  %s" % (i + 1, len(todo), os.path.basename(rp)))
        dst = os.path.join(dest_root, os.path.relpath(rp, ROOT))
        try:
            if fat and size >= 4 * 1024 ** 3 - 1:
                failed.append([rp, "trop gros pour une clé FAT32 (4 Go max)"])
                done_b += size
                continue
            if os.path.isfile(dst) and _same(rp, dst):
                skipped += 1
                verified.append(rp)
                done_b += size
                continue
            os.makedirs(os.path.dirname(dst), exist_ok=True)
            tmp = dst + ".part"
            with open(rp, "rb") as fi, open(tmp, "wb") as fo:
                while True:
                    if STOP.is_set():
                        raise InterruptedError("arrêt")
                    buf = fi.read(4 * 1048576)
                    if not buf:
                        break
                    fo.write(buf)
                    done_b += len(buf)
                    set_prog(100.0 * done_b / max(1, total))
                fo.flush()
                try:
                    os.fsync(fo.fileno())
                except Exception:
                    pass
            os.replace(tmp, dst)
            try:
                os.utime(dst, (os.path.getatime(rp), os.path.getmtime(rp)))
            except Exception:
                pass
            if _same(rp, dst):
                copied += 1
                verified.append(rp)
            else:
                failed.append([rp, "copie différente de l'original"])
        except InterruptedError:
            try:
                os.remove(dst + ".part")
            except Exception:
                pass
            break
        except Exception as e:
            failed.append([rp, str(e)])
            try:
                os.remove(dst + ".part")
            except Exception:
                pass
    vsize = 0
    for rp in verified:
        try:
            vsize += os.path.getsize(rp)
        except Exception:
            pass
    if verified:
        state_set(last_usb=int(time.time()))
    return {"type": "usbdone", "copied": copied, "skipped": skipped, "failed": failed[:30], "nfailed": len(failed),
            "verified": verified, "vsize": vsize, "dest": dest_root, "stopped": STOP.is_set(), "total": len(todo)}


# ---------------------------------------------------------------- RAFALES / PHOTOS SIMILAIRES
def dhash(path):
    im = Image.open(path)
    im.draft("L", (160, 160))
    im = ImageOps.exif_transpose(im).convert("L").resize((9, 8))
    px = list(im.getdata())
    bits = 0
    for r in range(8):
        for c in range(8):
            bits = (bits << 1) | (1 if px[r * 9 + c] > px[r * 9 + c + 1] else 0)
    return bits


def scan_similar(gap_s=30, maxdist=8):
    if not HAVE_PIL:
        return {"type": "list", "groups": [], "pil": False}
    files = []
    for e in walk_files(ROOT, skip=lambda d: is_android_private(d) or os.path.basename(d) == ".thumbnails", stop=STOP):
        if e.name.lower().endswith((".jpg", ".jpeg", ".png", ".webp")):
            try:
                st = e.stat()
                if st.st_size > 30 * 1024:
                    files.append((st.st_mtime, e.path, st))
            except Exception:
                pass
    files.sort()
    files = files[-12000:]
    n = max(1, len(files))
    groups, cur = [], []
    prev_t = 0
    for i, (mt, p, st) in enumerate(files):
        if STOP.is_set():
            break
        if i % 25 == 0:
            set_prog(100.0 * i / n, os.path.basename(p))
        try:
            h = dhash(p)
        except Exception:
            continue
        if cur and mt - prev_t <= gap_s and bin(cur[0][0] ^ h).count("1") <= maxdist:
            cur.append((h, p, st))
        else:
            if len(cur) >= 2:
                groups.append(cur)
            cur = [(h, p, st)]
        prev_t = mt
    if len(cur) >= 2:
        groups.append(cur)
    out = []
    for g in groups[-400:][::-1]:
        its, best, bs = [], None, -1
        for h, p, st in g:
            it = item(p, st)
            if not it:
                continue
            try:
                sc = blur_score(p)
            except Exception:
                sc = 0
            it["_sc"] = sc
            if sc > bs:
                bs, best = sc, it
            its.append(it)
        if len(its) < 2:
            continue
        best["x"] = "⭐ meilleure"
        for it in its:
            it.pop("_sc", None)
        when = time.strftime("%d/%m/%Y %H:%M", time.localtime(its[0]["m"]))
        out.append({"k": "📸 %s — %d photos" % (when, len(its)), "items": its, "sel": False, "thumbs": True,
                    "best": best["p"], "count": len(its), "total": sum(i["s"] for i in its)})
    return {"type": "list", "groups": out, "pil": True, "stopped": STOP.is_set()}


# ---------------------------------------------------------------- ALLEGER (re-compression JPEG, original en corbeille)
def scan_heavy(min_mb=3):
    items = []
    for e in walk_files(ROOT, skip=lambda d: is_android_private(d) or os.path.basename(d) == ".thumbnails", stop=STOP):
        if e.name.lower().endswith((".jpg", ".jpeg")):
            try:
                st = e.stat()
            except Exception:
                continue
            if st.st_size >= min_mb * 1048576:
                it = item(e.path, st)
                if it:
                    items.append(it)
    items.sort(key=lambda x: -x["s"])
    items = items[:5000]
    return {"type": "list", "groups": [{"k": "📷 Photos lourdes (JPEG)", "items": items, "sel": False, "thumbs": True,
                                        "count": len(items), "total": sum(i["s"] for i in items)}], "stopped": STOP.is_set()}


def shrink_images(paths, quality=85, maxside=0):
    if not HAVE_PIL:
        raise RuntimeError("Pillow absent")
    batch = datetime.now().strftime("%Y%m%d_%H%M%S")
    bdir = os.path.join(TRASH, batch)
    manifest, saved, done, errs = [], 0, 0, []
    todo = [os.path.realpath(p) for p in paths]
    todo = [p for p in todo if inside_root(p) and not in_trash(p) and p.lower().endswith((".jpg", ".jpeg")) and os.path.isfile(p)]
    for i, p in enumerate(todo):
        if STOP.is_set():
            break
        set_prog(100.0 * i / max(1, len(todo)), os.path.basename(p))
        tmp = p + ".nap_tmp"
        try:
            old = os.path.getsize(p)
            stt = os.stat(p)
            with Image.open(p) as im:
                exif = im.info.get("exif")
                icc = im.info.get("icc_profile")
                im2 = im
                if maxside and max(im.size) > maxside:
                    im2 = im.copy()
                    im2.thumbnail((maxside, maxside))
                kw = {"quality": quality, "optimize": True}
                if exif:
                    kw["exif"] = exif
                if icc:
                    kw["icc_profile"] = icc
                im2.convert("RGB").save(tmp, "JPEG", **kw)
            new = os.path.getsize(tmp)
            if new > old * 0.85:                     # gain trop faible : on laisse l'original
                os.remove(tmp)
                continue
            dst = os.path.join(bdir, os.path.relpath(p, ROOT))
            os.makedirs(os.path.dirname(dst), exist_ok=True)
            shutil.move(p, dst)
            os.replace(tmp, p)
            os.utime(p, (stt.st_atime, stt.st_mtime))
            manifest.append({"src": p, "dst": dst})
            saved += old - new
            done += 1
        except Exception as e:
            errs.append([p, str(e)])
            try:
                os.remove(tmp)
            except Exception:
                pass
    if manifest:
        try:
            with open(os.path.join(bdir, "_manifest.json"), "w", encoding="utf-8") as f:
                json.dump(manifest, f)
        except Exception:
            pass
    return {"type": "shrinkdone", "done": done, "saved": saved, "errors": errs[:20], "nerr": len(errs), "total": len(todo)}


# ---------------------------------------------------------------- ENVOYER VERS LE PC (Wi-Fi)
import socket
import secrets
import zipfile
from html import escape
from urllib.parse import quote
from werkzeug.serving import make_server

SHARE = {"srv": None, "token": "", "url": "", "t0": 0.0}
share_app = Flask("share", static_folder=None)
MEDIA_EXT = IMG_EXT + VID_EXT


def local_ip():
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("10.255.255.255", 1))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except Exception:
        return ""


def _share_ok(token):
    if not SHARE["srv"] or token != SHARE["token"] or time.time() - SHARE["t0"] > 3600:
        abort(404)


def _share_dirs():
    dirs = {}
    for e in walk_files(ROOT, skip=lambda d: is_android_private(d) or os.path.basename(d) == ".thumbnails"):
        if e.name.lower().endswith(MEDIA_EXT):
            d = os.path.dirname(e.path)
            try:
                dirs.setdefault(d, [0, 0])
                dirs[d][0] += 1
                dirs[d][1] += e.stat().st_size
            except Exception:
                pass
    return dirs


def _page(title, body):
    return ("<!doctype html><meta charset=utf-8><meta name=viewport content='width=device-width,initial-scale=1'>"
            "<title>%s</title><style>body{font:16px system-ui;max-width:900px;margin:20px auto;padding:0 12px}"
            "a{color:#1565C0}li{margin:6px 0}.b{display:inline-block;background:#2E7D32;color:#fff;padding:8px 14px;"
            "border-radius:8px;text-decoration:none;font-weight:700}</style><h1>%s</h1>%s" % (escape(title), escape(title), body))


@share_app.route("/<token>/")
def share_home(token):
    _share_ok(token)
    dirs = _share_dirs()
    li = "".join("<li><a href='/%s/d?p=%s'>%s</a> — %d fichiers, %.1f Go</li>" % (
        token, quote(os.path.relpath(d, ROOT)), escape(os.path.relpath(d, ROOT)), v[0], v[1] / 1e9)
        for d, v in sorted(dirs.items(), key=lambda x: -x[1][1]))
    return _page("Photos et vidéos du téléphone", "<p>Choisis un dossier, puis télécharge-le en ZIP ou fichier par fichier.</p><ul>%s</ul>" % li)


def _safe_dir(rel):
    d = os.path.realpath(os.path.join(ROOT, rel))
    if not (inside_root(d) and os.path.isdir(d)) or in_trash(d) or is_android_private(d):
        abort(404)
    return d


@share_app.route("/<token>/d")
def share_dir(token):
    _share_ok(token)
    rel = request.args.get("p", "")
    d = _safe_dir(rel)
    fl = sorted(f for f in os.listdir(d) if f.lower().endswith(MEDIA_EXT) and os.path.isfile(os.path.join(d, f)))
    li = "".join("<li><a href='/%s/f?p=%s'>%s</a> (%.1f Mo)</li>" % (
        token, quote(os.path.join(rel, f)), escape(f), os.path.getsize(os.path.join(d, f)) / 1048576) for f in fl)
    return _page(rel or "/", "<p><a class=b href='/%s/z?p=%s'>⬇ TOUT EN ZIP (%d fichiers)</a></p><p><a href='/%s/'>← dossiers</a></p><ul>%s</ul>" % (
        token, quote(rel), len(fl), token, li))


@share_app.route("/<token>/f")
def share_file(token):
    _share_ok(token)
    p = os.path.realpath(os.path.join(ROOT, request.args.get("p", "")))
    if not (inside_root(p) and os.path.isfile(p) and p.lower().endswith(MEDIA_EXT)) or in_trash(p) or is_android_private(os.path.dirname(p)):
        abort(404)
    return send_file(p, as_attachment=True)


class _Pipe:
    def __init__(self):
        self.buf = []
        self.pos = 0

    def write(self, b):
        self.buf.append(bytes(b))
        self.pos += len(b)
        return len(b)

    def tell(self):
        return self.pos

    def flush(self):
        pass


@share_app.route("/<token>/z")
def share_zip(token):
    _share_ok(token)
    d = _safe_dir(request.args.get("p", ""))
    fl = sorted(f for f in os.listdir(d) if f.lower().endswith(MEDIA_EXT) and os.path.isfile(os.path.join(d, f)))

    def gen():
        pipe = _Pipe()
        z = zipfile.ZipFile(pipe, "w", zipfile.ZIP_STORED, allowZip64=True)
        for f in fl:
            with z.open(zipfile.ZipInfo.from_file(os.path.join(d, f), f), "w", force_zip64=True) as zf, open(os.path.join(d, f), "rb") as fi:
                while True:
                    b = fi.read(1048576)
                    if not b:
                        break
                    zf.write(b)
                    for x in pipe.buf:
                        yield x
                    pipe.buf = []
        z.close()
        for x in pipe.buf:
            yield x
    name = (os.path.basename(d) or "photos") + ".zip"
    from flask import Response
    return Response(gen(), mimetype="application/zip", headers={"Content-Disposition": "attachment; filename*=UTF-8''" + quote(name)})


def share_start():
    share_stop()
    token = secrets.token_urlsafe(6)
    port = 8878
    srv = make_server("0.0.0.0", port, share_app, threaded=True)
    SHARE.update(srv=srv, token=token, t0=time.time())
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    ip = local_ip()
    SHARE["url"] = "http://%s:%d/%s/" % (ip or "ADRESSE-DU-TELEPHONE", port, token)
    return SHARE["url"]


def share_stop():
    s = SHARE.get("srv")
    if s:
        try:
            threading.Thread(target=s.shutdown, daemon=True).start()
        except Exception:
            pass
    SHARE.update(srv=None, token="", url="")


# ---------------------------------------------------------------- memoire de la derniere copie sur cle
STATE_FILE = os.path.join(HERE, "nap_state.json")


def state_get():
    try:
        with open(STATE_FILE, encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return {}


def state_set(**kw):
    s = state_get()
    s.update(kw)
    try:
        with open(STATE_FILE, "w", encoding="utf-8") as f:
            json.dump(s, f)
    except Exception:
        pass


def installed_packages():
    for cmd in (["pm", "list", "packages"], ["cmd", "package", "list", "packages"]):
        try:
            out = subprocess.run(cmd, capture_output=True, text=True, timeout=12).stdout
            pk = set(re.findall(r"package:([\w.]+)", out))
            if len(pk) > 20:
                return pk
        except Exception:
            continue
    return None


def scan_junk():
    g_thumb, g_cache, g_tmp, g_apk, g_empty, g_trashed, g_resid = [], [], [], [], [], [], []
    tmp_re = re.compile(r"\.(tmp|temp|crdownload|part|partial|download|log|bak|cache|dmp)$", re.I)
    cnt = 0

    def skip(d):
        b = os.path.basename(d)
        return b in (".thumbnails",) or (is_android_private(d) and b not in ("cache",))

    # dossiers miniatures / cache
    stack = [ROOT]
    while stack and not STOP.is_set():
        d = stack.pop()
        try:
            names = os.listdir(d)
        except Exception:
            continue
        cnt += 1
        if cnt % 60 == 0:
            set_prog(min(40, cnt / 80.0), os.path.relpath(d, ROOT))
        for name in names:
            p = os.path.join(d, name)
            try:
                if os.path.islink(p) or not os.path.isdir(p) or p == TRASH:
                    continue
            except Exception:
                continue
            low = name.lower()
            if low == ".thumbnails" or low == "thumbnails" and "dcim" in d.lower():
                for e in walk_files(p, stop=STOP):
                    it = item(e.path)
                    if it:
                        g_thumb.append(it)
            elif low in ("cache", ".cache", "caches", "tmp", ".tmp", "temp", ".temp") and not is_android_private(p) or \
                    (low == "cache" and re.match(r"Android/data/[^/]+$", os.path.relpath(d, ROOT).replace("\\", "/"))):
                for e in walk_files(p, stop=STOP):
                    it = item(e.path)
                    if it:
                        g_cache.append(it)
            elif not is_android_private(p) or os.path.relpath(p, ROOT).replace("\\", "/").count("/") < 3:
                stack.append(p)

    # fichiers temporaires, APK, corbeille Android
    cnt = 0
    for e in walk_files(ROOT, skip=lambda d: os.path.basename(d) == ".thumbnails", stop=STOP):
        cnt += 1
        if cnt % 500 == 0:
            set_prog(40 + min(30, cnt / 1500.0), "")
        n = e.name
        if is_android_private(e.path) and not n.startswith(".trashed"):
            continue
        try:
            if n.startswith((".trashed-", ".pending-")):
                it = item(e.path)
                it and g_trashed.append(it)
            elif tmp_re.search(n):
                it = item(e.path)
                it and g_tmp.append(it)
            elif n.lower().endswith(".apk"):
                it = item(e.path)
                it and g_apk.append(it)
        except Exception:
            continue

    # dossiers vides
    set_prog(75, "")
    for d, dirs, files in os.walk(ROOT):
        if STOP.is_set():
            break
        if d == TRASH or d.startswith(TRASH + os.sep) or is_android_private(d) and d != ROOT:
            dirs[:] = []
            continue
        if d == ROOT:
            continue
        rel = os.path.relpath(d, ROOT)
        if rel in PROTECTED_TOP or os.path.exists(os.path.join(d, ".nomedia")):
            continue
        try:
            if not os.listdir(d):
                g_empty.append({"p": d, "n": os.path.basename(d), "s": 0, "m": int(os.stat(d).st_mtime), "d": os.path.dirname(rel), "dir": True})
        except Exception:
            pass

    # restes d'applications desinstallees
    set_prog(90, "")
    pk = installed_packages()
    resid_note = ""
    if pk:
        for sub in ("Android/data", "Android/media", "Android/obb"):
            base = os.path.join(ROOT, sub)
            try:
                names = os.listdir(base)
            except Exception:
                continue
            for name in names:
                if re.match(r"^[a-z][\w]*(\.[\w]+)+$", name) and name not in pk and not name.startswith("com.android"):
                    p = os.path.join(base, name)
                    sz = dir_size(p, STOP)
                    if sz > 0:
                        g_resid.append({"p": p, "n": name, "s": sz, "m": int(os.stat(p).st_mtime), "d": sub, "dir": True})
    else:
        resid_note = "nopm"

    def srt(l):
        return sorted(l, key=lambda x: -x["s"])
    return {"type": "list", "note": resid_note, "groups": [
        {"k": "g_thumb", "items": srt(g_thumb)[:3000], "sel": True, "total": sum(x["s"] for x in g_thumb), "count": len(g_thumb)},
        {"k": "g_cache", "items": srt(g_cache)[:3000], "sel": True, "total": sum(x["s"] for x in g_cache), "count": len(g_cache)},
        {"k": "g_tmp", "items": srt(g_tmp)[:3000], "sel": True, "total": sum(x["s"] for x in g_tmp), "count": len(g_tmp)},
        {"k": "g_trashed", "items": srt(g_trashed)[:3000], "sel": True, "total": sum(x["s"] for x in g_trashed), "count": len(g_trashed)},
        {"k": "g_apk", "items": srt(g_apk)[:500], "sel": False, "total": sum(x["s"] for x in g_apk), "count": len(g_apk)},
        {"k": "g_resid", "items": srt(g_resid)[:500], "sel": False, "total": sum(x["s"] for x in g_resid), "count": len(g_resid)},
        {"k": "g_empty", "items": g_empty[:1500], "sel": True, "total": 0, "count": len(g_empty)},
    ], "stopped": STOP.is_set()}


# ---------------------------------------------------------------- suppression / corbeille
def remove_paths(paths, mode):
    freed, done, errs = 0, 0, []
    batch = datetime.now().strftime("%Y%m%d_%H%M%S")
    bdir = os.path.join(TRASH, batch)
    manifest = []
    uniq = []
    seen = set()
    for p in paths:                                  # on enleve les doublons de chemins et les sous-chemins deja couverts
        rp = os.path.realpath(p)
        if rp not in seen:
            seen.add(rp)
            uniq.append(rp)
    uniq.sort(key=len)
    keep = []
    for rp in uniq:
        if not any(rp.startswith(k + os.sep) for k in keep):
            keep.append(rp)
    for rp in keep:
        if not inside_root(rp) or (mode == "trash" and in_trash(rp)):
            errs.append([rp, "refuse"])
            continue
        if not os.path.lexists(rp):
            continue
        try:
            size = os.path.getsize(rp) if os.path.isfile(rp) else dir_size(rp)
            if mode == "permanent" or in_trash(rp):
                if os.path.isdir(rp) and not os.path.islink(rp):
                    shutil.rmtree(rp)
                else:
                    os.remove(rp)
            else:
                rel = os.path.relpath(rp, ROOT)
                dst = os.path.join(bdir, rel)
                os.makedirs(os.path.dirname(dst), exist_ok=True)
                shutil.move(rp, dst)
                manifest.append({"src": rp, "dst": dst})
            freed += size
            done += 1
        except Exception as e:
            errs.append([rp, str(e)])
    if manifest:
        try:
            with open(os.path.join(bdir, "_manifest.json"), "w", encoding="utf-8") as f:
                json.dump(manifest, f)
        except Exception:
            pass
    return {"done": done, "freed": freed, "errors": errs[:30], "nerr": len(errs), "mode": mode}


def trash_batches():
    out = []
    if os.path.isdir(TRASH):
        for name in sorted(os.listdir(TRASH), reverse=True):
            p = os.path.join(TRASH, name)
            if os.path.isdir(p):
                cnt = sum(1 for e in walk_files(p) if e.name != "_manifest.json")
                out.append({"b": name, "s": dir_size(p), "n": cnt})
    return out


# ---------------------------------------------------------------- routes
@app.route("/")
def index():
    return send_from_directory(HERE, "index.html")


@app.route("/api/storage")
def api_storage():
    try:
        st = os.statvfs(ROOT)
        total, free = st.f_blocks * st.f_frsize, st.f_bavail * st.f_frsize
    except Exception:
        total = free = 0
    tb = trash_batches()
    return jsonify({"total": total, "free": free, "used": total - free, "root": ROOT, "pil": HAVE_PIL,
                    "trash": sum(b["s"] for b in tb)})


@app.route("/api/scan", methods=["POST"])
def api_scan():
    d = request.get_json(silent=True) or {}
    kind = d.get("kind")
    fn = {"folder": lambda: run_job("folder", scan_overview, d.get("path")),
          "big": lambda: run_job("big", scan_big, d.get("min_mb", 50)),
          "dups": lambda: run_job("dups", scan_dups, d.get("min_kb", 50)),
          "social": lambda: run_job("social", scan_social, d.get("age", 60), bool(d.get("sent"))),
          "photos": lambda: run_job("photos", scan_photos, float(d.get("blur", 45))),
          "junk": lambda: run_job("junk", scan_junk),
          "similar": lambda: run_job("similar", scan_similar),
          "heavy": lambda: run_job("heavy", scan_heavy, float(d.get("min_mb", 3))),
          "media": lambda: run_job("media", scan_media, d.get("cats") or ["p", "v"], float(d.get("min_mb", 0)), int(d.get("age", 0))),
          "auto": lambda: run_job("auto", auto_clean)}.get(kind)
    if not fn:
        return jsonify({"ok": False, "err": "kind"}), 400
    return jsonify({"ok": bool(fn())})


@app.route("/api/usb/status")
def api_usb_status():
    vols = usb_volumes()
    return jsonify({"vols": vols, "dir": USB_DIR, "diag": list(USB_DIAG)})


@app.route("/api/usb/copy", methods=["POST"])
def api_usb_copy():
    d = request.get_json(silent=True) or {}
    paths = [p for p in d.get("paths", []) if isinstance(p, str)]
    vol = d.get("vol", "")
    if not paths or len(paths) > 100000 or vol not in [v["p"] for v in usb_volumes()]:
        return jsonify({"ok": False}), 400
    return jsonify({"ok": bool(run_job("usb", usb_copy, paths, vol))})


@app.route("/api/share/start", methods=["POST"])
def api_share_start():
    try:
        return jsonify({"ok": True, "url": share_start(), "ip": bool(local_ip())})
    except Exception as e:
        return jsonify({"ok": False, "err": str(e)})


@app.route("/api/share/stop", methods=["POST"])
def api_share_stop():
    share_stop()
    return jsonify({"ok": True})


@app.route("/api/share/status")
def api_share_status():
    on = bool(SHARE["srv"]) and time.time() - SHARE["t0"] <= 3600
    return jsonify({"on": on, "url": SHARE["url"] if on else ""})


@app.route("/api/state")
def api_state():
    s = state_get()
    try:
        st = os.statvfs(ROOT)
        pc = 100.0 * (1 - st.f_bavail / max(1, st.f_blocks))
    except Exception:
        pc = 0
    return jsonify({"last_usb": s.get("last_usb", 0), "used_pct": pc})


@app.route("/api/shrink", methods=["POST"])
def api_shrink():
    d = request.get_json(silent=True) or {}
    paths = [p for p in d.get("paths", []) if isinstance(p, str)]
    if not paths or len(paths) > 20000:
        return jsonify({"ok": False}), 400
    q = max(60, min(95, int(d.get("q", 85))))
    ms = int(d.get("maxside", 0))
    return jsonify({"ok": bool(run_job("shrink", shrink_images, paths, q, ms))})


@app.route("/api/job")
def api_job():
    j = dict(JOB)
    j.pop("result", None)
    j["elapsed"] = (j["t1"] or time.time()) - j["t0"] if j["t0"] else 0
    return jsonify(j)


@app.route("/api/result")
def api_result():
    return jsonify({"id": JOB["id"], "kind": JOB["kind"], "error": JOB["error"], "result": JOB["result"]})


@app.route("/api/stop", methods=["POST"])
def api_stop():
    STOP.set()
    return jsonify({"ok": True})


@app.route("/api/delete", methods=["POST"])
def api_delete():
    d = request.get_json(silent=True) or {}
    paths = [p for p in d.get("paths", []) if isinstance(p, str)]
    mode = "permanent" if d.get("mode") == "permanent" else "trash"
    if not paths or len(paths) > 20000:
        return jsonify({"ok": False}), 400
    return jsonify({"ok": True, **remove_paths(paths, mode)})


@app.route("/api/trash")
def api_trash():
    return jsonify({"batches": trash_batches()})


@app.route("/api/trash/restore", methods=["POST"])
def api_restore():
    b = (request.get_json(silent=True) or {}).get("b", "")
    if not re.match(r"^[\w\-]+$", b):
        abort(400)
    bdir = os.path.join(TRASH, b)
    ok, bad = 0, 0
    try:
        with open(os.path.join(bdir, "_manifest.json"), encoding="utf-8") as f:
            mf = json.load(f)
    except Exception:
        return jsonify({"ok": False, "restored": 0, "failed": 0})
    for m in mf:
        try:
            if os.path.exists(m["dst"]) and inside_root(m["src"]) and not os.path.exists(m["src"]):
                os.makedirs(os.path.dirname(m["src"]), exist_ok=True)
                shutil.move(m["dst"], m["src"])
                ok += 1
            else:
                bad += 1
        except Exception:
            bad += 1
    try:
        if not any(e.name != "_manifest.json" for e in walk_files(bdir)):
            shutil.rmtree(bdir, ignore_errors=True)
    except Exception:
        pass
    return jsonify({"ok": True, "restored": ok, "failed": bad})


@app.route("/api/trash/empty", methods=["POST"])
def api_empty():
    b = (request.get_json(silent=True) or {}).get("b", "all")
    freed = 0
    try:
        if b == "all":
            freed = dir_size(TRASH)
            shutil.rmtree(TRASH, ignore_errors=True)
        elif re.match(r"^[\w\-]+$", b):
            p = os.path.join(TRASH, b)
            freed = dir_size(p)
            shutil.rmtree(p, ignore_errors=True)
    except Exception:
        pass
    return jsonify({"ok": True, "freed": freed})


@app.route("/api/thumb")
def api_thumb():
    p = request.args.get("p", "")
    if not HAVE_PIL or not os.path.isfile(p) or not (inside_root(p) or in_trash(p)):
        abort(404)
    try:
        im = Image.open(p)
        im.draft("RGB", (240, 240))
        im = ImageOps.exif_transpose(im).convert("RGB")
        im.thumbnail((200, 200))
        buf = io.BytesIO()
        im.save(buf, "JPEG", quality=70)
        buf.seek(0)
        r = send_file(buf, mimetype="image/jpeg")
        r.headers["Cache-Control"] = "max-age=3600"
        return r
    except Exception:
        abort(404)


# ---------------------------------------------------------------- SYSTEME (via adb, "debogage sans fil")
ADB = os.environ.get("NAP_ADB", "adb")


def adb(*args, timeout=40):
    try:
        r = subprocess.run([ADB] + list(args), capture_output=True, text=True, timeout=timeout)
        return r.returncode, (r.stdout or "") + (r.stderr or "")
    except FileNotFoundError:
        return -1, "adb-absent"
    except Exception as e:
        return -1, str(e)


def adb_status():
    rc, out = adb("devices", timeout=15)
    if out.strip() == "adb-absent":
        return {"adb": False, "connected": False, "devices": []}
    devs = [l.split()[0] for l in out.splitlines()[1:] if l.strip().endswith("device")]
    return {"adb": True, "connected": bool(devs), "devices": devs}


def parse_list(txt, key, num=True):
    m = re.search(r"^" + re.escape(key) + r":\s*\[(.*?)\]\s*$", txt, re.M)
    if not m:
        return []
    items = [x.strip().strip('"') for x in m.group(1).split(",") if x.strip()]
    if num:
        out = []
        for x in items:
            try:
                out.append(int(x))
            except Exception:
                out.append(0)
        return out
    return items


def parse_diskstats(txt):
    parts = {}
    for k in ("App Size", "App Data Size", "App Cache Size", "Photos Size", "Videos Size", "Audio Size",
              "Downloads Size", "System Size", "Other Size"):
        m = re.search(r"^" + re.escape(k) + r":\s*(\d+)", txt, re.M)
        if m:
            parts[k] = int(m.group(1))
    names = parse_list(txt, "Package Names", num=False)
    sizes = parse_list(txt, "App Sizes")
    datas = parse_list(txt, "App Data Sizes")
    caches = parse_list(txt, "Cache Sizes")
    apps = []
    for i, n in enumerate(names):
        a = sizes[i] if i < len(sizes) else 0
        d = datas[i] if i < len(datas) else 0
        c = caches[i] if i < len(caches) else 0
        apps.append({"pkg": n, "app": a, "data": d, "cache": c, "total": a + d + c})
    apps.sort(key=lambda x: -x["total"])
    m = re.search(r"Data-Free:\s*(\d+)K\s*/\s*(\d+)K", txt)
    free = {"free": int(m.group(1)) * 1024, "total": int(m.group(2)) * 1024} if m else None
    return {"parts": parts, "apps": apps, "free": free}


def third_party():
    rc, out = adb("shell", "pm", "list", "packages", "-3", timeout=30)
    return set(re.findall(r"package:([\w.]+)", out))


def scan_system():
    set_prog(10, "adb")
    st = adb_status()
    if not st["connected"]:
        return {"type": "system", "error": "adb", "adb": st}
    set_prog(30, "dumpsys diskstats")
    rc, out = adb("shell", "dumpsys", "diskstats", timeout=90)
    data = parse_diskstats(out)
    set_prog(80, "pm list packages")
    tp = third_party()
    names = {a["pkg"] for a in data["apps"]}
    for a in data["apps"]:
        a["third"] = a["pkg"] in tp
        a["label"] = a["pkg"]
    data["apps"] = [a for a in data["apps"] if a["total"] > 0][:200]
    data["type"] = "system"
    data["error"] = "" if data["parts"] else "vide"
    return data


def trim_caches():
    st = adb_status()
    if not st["connected"]:
        return {"type": "trim", "error": "adb"}
    set_prog(10, "dumpsys diskstats")
    before = parse_diskstats(adb("shell", "dumpsys", "diskstats", timeout=90)[1])["parts"].get("App Cache Size", 0)
    set_prog(40, "pm trim-caches")
    rc, out = adb("shell", "pm", "trim-caches", "999999999999", timeout=180)
    set_prog(80, "dumpsys diskstats")
    after = parse_diskstats(adb("shell", "dumpsys", "diskstats", timeout=90)[1])["parts"].get("App Cache Size", 0)
    return {"type": "trim", "error": "" if rc == 0 else out.strip()[:200], "before": before, "after": after, "freed": max(0, before - after)}


def uninstall_pkgs(pkgs):
    tp = third_party()
    res = []
    for i, p in enumerate(pkgs):
        set_prog(100.0 * i / max(1, len(pkgs)), p)
        if not re.match(r"^[a-z][\w]*(\.[\w]+)+$", p) or p not in tp:
            res.append({"pkg": p, "ok": False, "msg": "refuse"})
            continue
        rc, out = adb("uninstall", p, timeout=90)
        res.append({"pkg": p, "ok": "Success" in out, "msg": out.strip()[:120]})
    return {"type": "uninstall", "results": res}


@app.route("/api/sys/status")
def api_sys_status():
    return jsonify(adb_status())


@app.route("/api/sys/pair", methods=["POST"])
def api_sys_pair():
    d = request.get_json(silent=True) or {}
    hp, code = str(d.get("hp", "")).strip(), str(d.get("code", "")).strip()
    if not re.match(r"^[\w.\-]+:\d{2,5}$", hp) or not re.match(r"^\d{4,8}$", code):
        return jsonify({"ok": False, "msg": "format"})
    rc, out = adb("pair", hp, code, timeout=30)
    return jsonify({"ok": "Successfully" in out, "msg": out.strip()[:200]})


@app.route("/api/sys/connect", methods=["POST"])
def api_sys_connect():
    hp = str((request.get_json(silent=True) or {}).get("hp", "")).strip()
    if not re.match(r"^[\w.\-]+:\d{2,5}$", hp):
        return jsonify({"ok": False, "msg": "format"})
    rc, out = adb("connect", hp, timeout=30)
    return jsonify({"ok": "connected" in out.lower() and "cannot" not in out.lower() and "failed" not in out.lower(), "msg": out.strip()[:200]})


@app.route("/api/sys/run", methods=["POST"])
def api_sys_run():
    d = request.get_json(silent=True) or {}
    k = d.get("kind")
    if k == "scan":
        ok = run_job("system", scan_system)
    elif k == "trim":
        ok = run_job("trim", trim_caches)
    elif k == "uninstall":
        ok = run_job("uninstall", uninstall_pkgs, [p for p in d.get("pkgs", []) if isinstance(p, str)][:50])
    else:
        return jsonify({"ok": False}), 400
    return jsonify({"ok": bool(ok)})


if __name__ == "__main__":
    if not os.path.isdir(ROOT):
        print("Dossier introuvable : %s\nLance d'abord : termux-setup-storage" % ROOT)
        sys.exit(1)
    print("NETTOYAGE ANDROID PRO  ->  http://localhost:%d   (stockage : %s)" % (PORT, ROOT))
    app.run(host="127.0.0.1", port=PORT, threaded=True)
