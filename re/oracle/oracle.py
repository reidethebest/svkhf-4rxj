"""Run the original NTFS Log Tracker v1.71 headlessly on one $LogFile and record its SQL stream (runtime oracle).

  python oracle.py --logfile C:\\samples\\01\\$LogFile --out C:\\...\\runs\\01 --utc 0 [--dst] [--mft PATH] [--pid PID]

Without --pid the original is spawned under Frida (python bindings) with hook.js loaded.
With --pid the process was spawned by another Frida client (e.g. REA's start_frida_session) that already loaded a
hook.js generated with --emit-hook-only; this script then only drives the GUI.

Outputs in --out: sql.jsonl (ordered SQL/file/msgbox events), the original's .db, NLT_LogFile_*.csv, log.txt copy, run.json.
"""
import argparse
import ctypes
import json
import os
import shutil
import sys
import time
from ctypes import wintypes
from pathlib import Path

import win32con
import win32gui
import win32process

HERE = Path(__file__).resolve().parent
EXE = HERE.parent.parent / "Journal Alternative" / "NTFS Log Tracker v1.71.exe"
user32 = ctypes.WinDLL("user32", use_last_error=True)
user32.SendMessageW.argtypes = [wintypes.HWND, wintypes.UINT, wintypes.WPARAM, wintypes.LPARAM]
user32.SendMessageW.restype = ctypes.c_ssize_t

MAIN_TITLE = "NTFS Log Tracker v1.71"
DEAD = []  # set by the Frida 'detached' handler when the original terminates or crashes


class ProcessDied(RuntimeError):
    pass


def check_alive():
    if DEAD:
        raise ProcessDied(f"original terminated: {DEAD[0]}")
ID_LOGFILE_EDIT, ID_MFT_EDIT, ID_PARSE, ID_CSV_EXPORT = 1006, 1005, 1001, 1010
ID_LOGFILE_BROWSE, ID_MFT_BROWSE = 1004, 1002
ID_DBNAME, ID_DBPATH_BROWSE, ID_TZ_COMBO, ID_DST, ID_SUSPICIOUS = 1016, 1001, 1037, 1038, 1039


def windows_of(pid, title=None):
    found = []

    def cb(h, _):
        if win32gui.IsWindowVisible(h) and win32process.GetWindowThreadProcessId(h)[1] == pid:
            if title is None or win32gui.GetWindowText(h) == title:
                found.append(h)
        return True

    win32gui.EnumWindows(cb, None)
    return found


def wait_window(pid, title, timeout=60):
    end = time.time() + timeout
    while time.time() < end:
        w = windows_of(pid, title)
        if w:
            return w[0]
        time.sleep(0.2)
    raise TimeoutError(f"window {title!r} did not appear")


def wait_gone(pid, title, timeout):
    end = time.time() + timeout
    while time.time() < end:
        check_alive()
        if not windows_of(pid, title):
            check_alive()
            return
        time.sleep(0.5)
    raise TimeoutError(f"window {title!r} still open")


def set_text(dlg, cid, text):
    h = win32gui.GetDlgItem(dlg, cid)
    buf = ctypes.create_unicode_buffer(text)
    user32.SendMessageW(h, win32con.WM_SETTEXT, 0, ctypes.addressof(buf))


def click_async(dlg, cid):
    h = win32gui.GetDlgItem(dlg, cid)
    win32gui.PostMessage(dlg, win32con.WM_COMMAND, (win32con.BN_CLICKED << 16) | cid, h)


def get_text(h):
    n = user32.SendMessageW(h, win32con.WM_GETTEXTLENGTH, 0, 0)
    buf = ctypes.create_unicode_buffer(n + 1)
    user32.SendMessageW(h, win32con.WM_GETTEXT, n + 1, ctypes.addressof(buf))
    return buf.value


def descendants(h):
    out = []
    win32gui.EnumChildWindows(h, lambda c, _: out.append(c) or True, None)
    return out


def pick_file(pid, main_dlg, button_id, edit_id, path, attempts=3):
    """pick_file_once with retries: under load the dialog can take the OK click before it accepts the typed name."""
    for i in range(attempts):
        try:
            return pick_file_once(pid, main_dlg, button_id, edit_id, path)
        except (RuntimeError, TimeoutError):
            if i == attempts - 1:
                raise
            for h in windows_of(pid):  # close a dialog left open by the failed attempt
                if h != main_dlg and win32gui.GetClassName(h) == "#32770":
                    win32gui.PostMessage(h, win32con.WM_CLOSE, 0, 0)
            time.sleep(2)


def pick_file_once(pid, main_dlg, button_id, edit_id, path):
    """Answer the original's file-open dialog (opened by button_id) with path, via the dialog's file-name box."""
    before = set(windows_of(pid))
    click_async(main_dlg, button_id)
    end = time.time() + 30
    dlg = None
    while time.time() < end and dlg is None:
        for h in windows_of(pid):
            if h not in before and win32gui.GetClassName(h) == "#32770":
                dlg = h
        time.sleep(0.2)
    if dlg is None:
        raise TimeoutError("file dialog did not appear")
    time.sleep(2.0)  # let the (Vista-style) dialog finish populating (slower with parallel instances)
    edit = None
    for c in descendants(dlg):
        if win32gui.GetDlgCtrlID(c) == 1148:  # cmb13 / edt1: file name box
            inner = [d for d in descendants(c) if win32gui.GetClassName(d) == "Edit"]
            edit = inner[0] if inner else c
            break
    if edit is None:
        raise RuntimeError("file name box not found in file dialog")
    buf = ctypes.create_unicode_buffer(path)
    user32.SendMessageW(edit, win32con.WM_SETTEXT, 0, ctypes.addressof(buf))
    ok = win32gui.GetDlgItem(dlg, win32con.IDOK)
    win32gui.PostMessage(ok, win32con.BM_CLICK, 0, 0)
    end = time.time() + 30
    while time.time() < end and win32gui.IsWindow(dlg) and win32gui.IsWindowVisible(dlg):
        time.sleep(0.2)
    end = time.time() + 15
    got = ""
    while time.time() < end:  # the edit is filled after DoModal returns
        got = get_text(win32gui.GetDlgItem(main_dlg, edit_id))
        if got and Path(got).resolve() == Path(path).resolve():
            return
        time.sleep(0.3)
    if not got or Path(got).resolve() != Path(path).resolve():
        raise RuntimeError(f"path not accepted by the original: edit shows {got!r}")


def combo_items(combo):
    items = []
    for i in range(user32.SendMessageW(combo, win32con.CB_GETCOUNT, 0, 0)):
        n = user32.SendMessageW(combo, win32con.CB_GETLBTEXTLEN, i, 0)
        buf = ctypes.create_unicode_buffer(n + 1)
        user32.SendMessageW(combo, win32con.CB_GETLBTEXT, i, ctypes.addressof(buf))
        items.append(buf.value)
    return items


def tz_label(utc):
    # Labels observed in the binary: 'UTC%0.2d:00' (negative), 'UTC %0.2d:00' (zero), 'UTC+%0.2d:00' (positive).
    if utc < 0:
        return "UTC%03d:00" % utc
    if utc == 0:
        return "UTC 00:00"
    return "UTC+%02d:00" % utc


def events(path):
    if not path.exists():
        return []
    out = []
    for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
        try:
            out.append(json.loads(line))
        except json.JSONDecodeError:
            pass
    return out


def wait_event(path, pred, timeout, quiet=3.0):
    end = time.time() + timeout
    while time.time() < end:
        check_alive()
        evs = events(path)
        hit = [e for e in evs if pred(e)]
        if hit:
            last = len(evs)
            time.sleep(quiet)
            if len(events(path)) == last:
                return hit[-1]
        time.sleep(0.5)
    raise TimeoutError("expected oracle event did not occur")


def make_hook(out_dir):
    src = (HERE / "hook.js").read_text(encoding="utf-8")
    src = src.replace("__OUT__", str(out_dir / "sql.jsonl").replace("\\", "\\\\"))
    src = src.replace("__BROWSE_DIR__", str(out_dir).replace("\\", "\\\\"))
    path = out_dir / "hook.run.js"
    path.write_text(src, encoding="utf-8")
    return path


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--logfile", required=True)
    ap.add_argument("--mft")
    ap.add_argument("--out", required=True)
    ap.add_argument("--utc", type=int, default=0)
    ap.add_argument("--dst", action="store_true")
    ap.add_argument("--pid", type=int)
    ap.add_argument("--emit-hook-only", action="store_true")
    ap.add_argument("--timeout", type=int, default=3600)
    ap.add_argument("--cwd", help="working directory of the original (its log.txt goes there); default: its folder")
    a = ap.parse_args()

    out = Path(a.out).resolve()
    out.mkdir(parents=True, exist_ok=True)
    hook = make_hook(out)
    if a.emit_hook_only:
        print(hook)
        return
    jsonl = out / "sql.jsonl"

    session = None
    pid = a.pid
    if pid is None:
        import frida

        jsonl.unlink(missing_ok=True)
        pid = frida.spawn([str(EXE)], stdio="pipe", cwd=str(Path(a.cwd).resolve() if a.cwd else EXE.parent))
        (out / "pid.txt").write_text(str(pid))
        session = frida.attach(pid)
        session.on("detached", lambda reason, crash: DEAD.append(f"{reason} {crash.summary if crash else ''}".strip()))
        script = session.create_script(hook.read_text(encoding="utf-8"))
        script.on("message", lambda m, d: m.get("type") == "error" and print("frida:", m, file=sys.stderr))
        script.load()
        frida.resume(pid)
    wait_event(jsonl, lambda e: e["ev"] == "ready", 60, quiet=0)

    main_dlg = wait_window(pid, MAIN_TITLE, 180)
    pick_file(pid, main_dlg, ID_LOGFILE_BROWSE, ID_LOGFILE_EDIT, str(Path(a.logfile).resolve()))
    if a.mft:
        pick_file(pid, main_dlg, ID_MFT_BROWSE, ID_MFT_EDIT, str(Path(a.mft).resolve()))
    click_async(main_dlg, ID_PARSE)

    setting = wait_window(pid, "Parse Setting")
    set_text(setting, ID_DBNAME, "oracle")
    click_async(setting, ID_DBPATH_BROWSE)  # answered by the hooked SHBrowseForFolderW with --out
    wait_event(jsonl, lambda e: e["ev"] == "browse_folder", 30, quiet=0.5)
    combo = win32gui.GetDlgItem(setting, ID_TZ_COMBO)
    items = combo_items(combo)
    want = tz_label(a.utc)
    if want not in items:
        raise SystemExit(f"timezone {want!r} not in combo items {items}")
    user32.SendMessageW(combo, win32con.CB_SETCURSEL, items.index(want), 0)
    win32gui.PostMessage(setting, win32con.WM_COMMAND, (win32con.CBN_SELCHANGE << 16) | ID_TZ_COMBO, combo)
    # Checkboxes must be toggled with a real click: the dialog tracks them through BN_CLICKED handlers.
    for cid, want_checked in ((ID_DST, a.dst), (ID_SUSPICIOUS, False)):
        box = win32gui.GetDlgItem(setting, cid)
        if bool(user32.SendMessageW(box, win32con.BM_GETCHECK, 0, 0)) != want_checked:
            user32.SendMessageW(box, win32con.BM_CLICK, 0, 0)
        if bool(user32.SendMessageW(box, win32con.BM_GETCHECK, 0, 0)) != want_checked:
            raise RuntimeError(f"checkbox {cid} did not reach state {want_checked}")
    time.sleep(0.3)
    t0 = time.time()
    click_async(setting, win32con.IDOK)

    # Parsing ends when the original writes log.txt and the status dialog closes.
    wait_event(jsonl, lambda e: e["ev"] == "createfile" and e["path"].lower().endswith("log.txt"), a.timeout)
    wait_gone(pid, "Process Status", a.timeout)
    parse_secs = time.time() - t0

    mark = len(events(jsonl))
    click_async(main_dlg, ID_CSV_EXPORT)
    csv_box = wait_event(jsonl, lambda e: e["ev"] == "msgbox" and e["seq"] >= mark, a.timeout)

    dbs = [e["path"] for e in events(jsonl) if e["ev"] == "open16"]
    logtxt = (Path(a.cwd).resolve() if a.cwd else EXE.parent) / "log.txt"
    if logtxt.exists():
        shutil.copy2(logtxt, out / "log.txt")
    (out / "run.json").write_text(json.dumps({
        "logfile": str(Path(a.logfile).resolve()), "mft": a.mft, "utc": a.utc, "dst": a.dst,
        "tz_label": want, "tz_items": items, "db_paths": dbs, "parse_seconds": round(parse_secs, 1),
        "msgboxes": [e.get("text") for e in events(jsonl) if e["ev"] == "msgbox"], "csv_msgbox": csv_box.get("text"),
    }, indent=1), encoding="utf-8")

    win32gui.PostMessage(main_dlg, win32con.WM_CLOSE, 0, 0)
    if session is not None:
        end = time.time() + 10  # wait for the original to exit; kill it if it does not
        while not DEAD and time.time() < end:
            time.sleep(0.2)
        if not DEAD:
            import frida
            try:
                frida.kill(pid)
            except Exception:
                pass
    print(json.dumps({"out": str(out), "parse_seconds": round(parse_secs, 1), "events": len(events(jsonl))}), flush=True)
    sys.stderr.flush()
    os._exit(0)  # skip interpreter teardown with live Frida threads (it can crash and change the exit code)


if __name__ == "__main__":
    try:
        main()
    except BaseException:
        # Do not leave a spawned original behind (it holds our std handles and its log.txt).
        import frida
        for p in Path(sys.argv[sys.argv.index("--out") + 1]).resolve().glob("pid.txt"):
            try:
                frida.kill(int(p.read_text()))
            except Exception:
                pass
        raise
