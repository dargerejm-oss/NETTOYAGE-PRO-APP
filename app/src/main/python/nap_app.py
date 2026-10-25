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
          "junk": lambda: run_job("junk", scan_junk)}.get(kind)
    if not fn:
        return jsonify({"ok": False, "err": "kind"}), 400
    return jsonify({"ok": bool(fn())})


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
