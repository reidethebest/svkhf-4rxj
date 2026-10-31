// Frida oracle for NTFS Log Tracker v1.71: records every SQL statement the original executes, in order,
// plus file opens and message boxes; answers folder-browse dialogs headlessly.
// Placeholders replaced per run by oracle.py: __OUT__ (JSONL path), __BROWSE_DIR__ (folder returned by SHBrowseForFolderW).
'use strict';

const OUT = '__OUT__';
const BROWSE_DIR = '__BROWSE_DIR__';
const log = new File(OUT, 'wb');
let seq = 0;

function emit(obj) {
  obj.seq = seq++;
  log.write(JSON.stringify(obj) + '\n');
  log.flush();
}

function bytesOf(p) {
  // Raw NUL-terminated bytes as hex (the original may pass ANSI or UTF-8; keep exact bytes).
  let n = 0;
  while (p.add(n).readU8() !== 0) n++;
  return new Uint8Array(p.readByteArray(n));
}

function hex(u8) {
  let s = '';
  for (let i = 0; i < u8.length; i++) s += (u8[i] < 16 ? '0' : '') + u8[i].toString(16);
  return s;
}

function ascii(u8) {
  let s = '';
  for (let i = 0; i < u8.length; i++) {
    if (u8[i] >= 0x80) return null;
    s += String.fromCharCode(u8[i]);
  }
  return s;
}

function units16(p) {
  const u = [];
  for (let i = 0; ; i += 2) {
    const c = p.add(i).readU16();
    if (c === 0) return u;
    u.push(c);
  }
}

function hasLoneSurrogate(u) {
  for (let i = 0; i < u.length; i++) {
    if (u[i] >= 0xd800 && u[i] < 0xdc00 && i + 1 < u.length && u[i + 1] >= 0xdc00 && u[i + 1] < 0xe000) i++;
    else if (u[i] >= 0xd800 && u[i] < 0xe000) return true;
  }
  return false;
}

function fromUnits(u) {
  let s = '';
  for (let i = 0; i < u.length; i += 4096) s += String.fromCharCode.apply(null, u.slice(i, i + 4096));
  return s;
}

function hex16(u) {
  let s = '';
  for (const c of u) s += ('000' + c.toString(16)).slice(-4);
  return s;
}

function exp(mod, name) {
  const m = Process.findModuleByName(mod) || Module.load(mod);
  return m.getExportByName(name);
}

function hookSqlite() {
  Interceptor.attach(exp('sqlite3.dll', 'sqlite3_exec'), {
    onEnter(args) {
      const u8 = bytesOf(args[1]);
      const a = ascii(u8);
      this.rec = a !== null ? { ev: 'exec', sql: a } : { ev: 'exec', sql_hex: hex(u8) };
    },
    onLeave(ret) {
      this.rec.rc = ret.toInt32();
      emit(this.rec);
    },
  });
  const stmtSeq = new Map();
  Interceptor.attach(exp('sqlite3.dll', 'sqlite3_prepare16'), {
    onEnter(args) {
      // readUtf16String fails on lone surrogates (valid in NTFS names): read raw code units instead.
      const u = units16(args[1]);
      const lone = hasLoneSurrogate(u);
      this.rec = lone ? { ev: 'prepare16', sql16: hex16(u) } : { ev: 'prepare16', sql: fromUnits(u) };
      this.pp = args[3];
    },
    onLeave(ret) {
      this.rec.rc = ret.toInt32();
      emit(this.rec);
      if (!this.pp.isNull()) stmtSeq.set(this.pp.readPointer().toString(), this.rec.seq);
    },
  });
  // Record every step result that is not SQLITE_ROW(100)/SQLITE_DONE(101), e.g. a PRIMARY KEY conflict (19).
  Interceptor.attach(exp('sqlite3.dll', 'sqlite3_step'), {
    onEnter(args) {
      this.stmt = args[0].toString();
    },
    onLeave(ret) {
      const rc = ret.toInt32();
      if (rc !== 100 && rc !== 101) emit({ ev: 'step', of: stmtSeq.has(this.stmt) ? stmtSeq.get(this.stmt) : null, rc });
    },
  });
  Interceptor.attach(exp('sqlite3.dll', 'sqlite3_get_table'), {
    onEnter(args) {
      emit({ ev: 'get_table', sql: args[1].readUtf8String() });
    },
  });
  Interceptor.attach(exp('sqlite3.dll', 'sqlite3_open16'), {
    onEnter(args) {
      emit({ ev: 'open16', path: args[0].readUtf16String() });
    },
  });
  Interceptor.attach(exp('sqlite3.dll', 'sqlite3_close'), {
    onEnter() {
      emit({ ev: 'close' });
    },
  });
}

function hookFiles() {
  Interceptor.attach(exp('kernel32.dll', 'CreateFileW'), {
    onEnter(args) {
      this.path = args[0].isNull() ? null : args[0].readUtf16String();
      this.access = args[1].toUInt32();
      this.disp = args[4].toUInt32();
    },
    onLeave(ret) {
      if (this.path && !/\\Windows\\|\.dll$|\.mui$|^\\\\\.\\pipe/i.test(this.path)) {
        emit({ ev: 'createfile', path: this.path, access: this.access, disp: this.disp, ok: ret.toInt32() !== -1 });
      }
    },
  });
}

function hookDialogs() {
  const coTaskMemAlloc = new NativeFunction(exp('ole32.dll', 'CoTaskMemAlloc'), 'pointer', ['size_t']);
  const fakePidls = new Set();

  Interceptor.replace(exp('shell32.dll', 'SHBrowseForFolderW'), new NativeCallback(function (bi) {
    const pidl = coTaskMemAlloc(2);
    pidl.writeU16(0); // empty ITEMIDLIST, freeable by CoTaskMemFree / IMalloc::Free
    fakePidls.add(pidl.toString());
    emit({ ev: 'browse_folder', returned: BROWSE_DIR });
    return pidl;
  }, 'pointer', ['pointer'], 'stdcall'));

  const realGetPath = new NativeFunction(exp('shell32.dll', 'SHGetPathFromIDListW'), 'int', ['pointer', 'pointer'], 'stdcall');
  Interceptor.replace(exp('shell32.dll', 'SHGetPathFromIDListW'), new NativeCallback(function (pidl, buf) {
    if (fakePidls.has(pidl.toString())) {
      buf.writeUtf16String(BROWSE_DIR);
      return 1;
    }
    return realGetPath(pidl, buf);
  }, 'int', ['pointer', 'pointer'], 'stdcall'));

  // Headless message boxes: record the text and answer OK / YES.
  Interceptor.replace(exp('user32.dll', 'MessageBoxW'), new NativeCallback(function (hwnd, text, caption, type) {
    const t = type & 0xf;
    const answer = (t === 3 || t === 4) ? 6 : 1; // MB_YESNO(CANCEL) -> IDYES, else IDOK
    emit({ ev: 'msgbox', text: text.isNull() ? null : text.readUtf16String(), caption: caption.isNull() ? null : caption.readUtf16String(), type, answer });
    return answer;
  }, 'int', ['pointer', 'pointer', 'pointer', 'uint'], 'stdcall'));
}

hookSqlite();
hookFiles();
hookDialogs();
emit({ ev: 'ready', pid: Process.id });
