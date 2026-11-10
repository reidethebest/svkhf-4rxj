import fs from 'node:fs';
import path from 'node:path';
import os from 'node:os';
import crypto from 'node:crypto';
import vm from 'node:vm';
import { extractAll, createPackage, extractFile, uncacheAll } from '@electron/asar';

const [originalAsar, mobileDirectory, resultAsar, reportPath] = process.argv.slice(2);
if (!reportPath) throw new Error('Usage: node rebuild.mjs original.asar mobile/www result.asar report.json');
const originalHash = '4201d7d64befd669fbfcfca09b96bd62c36722ef6403cf4b14580252f6f2d88f';
const sha256 = data => crypto.createHash('sha256').update(data).digest('hex');
if (sha256(fs.readFileSync(originalAsar)) !== originalHash) throw new Error('Unexpected desktop ASAR; refusing to patch an unverified version.');
const tmp = fs.mkdtempSync(path.join(process.cwd(), '.build-'));
const dst = path.resolve(resultAsar);
const replaceExactlyOnce = (text, oldText, newText, what) => {
  const at = text.indexOf(oldText);
  if (at < 0 || text.indexOf(oldText, at + oldText.length) !== -1) throw new Error(`Could not uniquely locate ${what}.`);
  return text.slice(0, at) + newText + text.slice(at + oldText.length);
};
try {
  extractAll(path.resolve(originalAsar), tmp);
  const appDir = path.join(tmp, 'app');
  const manifestPath = path.join(appDir, 'cifrados.json');
  const manifest = JSON.parse(fs.readFileSync(manifestPath, 'utf8'));
  if (!Array.isArray(manifest.archivos) || manifest.archivos.length !== 77) throw new Error('Unexpected encrypted-file inventory.');
  const recovered = [], missing = [];
  for (const name of manifest.archivos) {
    if (name.includes('..') || path.isAbsolute(name)) throw new Error(`Invalid path: ${name}`);
    const encrypted = path.join(appDir, `${name}.enc`);
    const mobile = path.join(mobileDirectory, name);
    if (!fs.existsSync(mobile)) { missing.push(name); continue; }
    const expectedSize = fs.statSync(encrypted).size - 28;
    const source = fs.readFileSync(mobile);
    if (source.length !== expectedSize) throw new Error(`Length differs for ${name}: ${source.length} vs ${expectedSize}`);
    // Parse each recovered browser script without executing it.
    new vm.Script(source.toString('utf8'), { filename: name });
    const target = path.join(appDir, name);
    fs.mkdirSync(path.dirname(target), { recursive: true });
    fs.writeFileSync(target, source);
    fs.unlinkSync(encrypted);
    recovered.push({ name, size: source.length, sha256: sha256(source) });
  }
  if (recovered.length !== 76 || missing.length !== 1 || missing[0] !== 'cervi-bench.js') {
    throw new Error(`Unexpected recovery coverage: ${recovered.length} recovered; missing ${missing.join(', ')}.`);
  }
  // The file protocol must read the recovered scripts as normal files.
  fs.writeFileSync(manifestPath, JSON.stringify({ archivos: [] }));

  const mainPath = path.join(tmp, 'main.js');
  let main = fs.readFileSync(mainPath, 'utf8');
  main = replaceExactlyOnce(main,
    "if(!app[_0x5c9d57(0x174)+'ed']){arrancarApp();return;}",
    'arrancarApp();return;', 'startup license gate');
  main = replaceExactlyOnce(main,
    "if(app[_0x3c576e(0x174)+'ed'])iniciarActualizaciones();",
    'void 0;', 'automatic update call');
  new vm.Script(main, { filename: 'main.js' });
  fs.writeFileSync(mainPath, main);

  // Existing IPC registrations can still call these methods. No licensing
  // server is contacted and no identity is fabricated for remote services.
  fs.writeFileSync(path.join(appDir, 'licencia-main.js'), `'use strict';\nmodule.exports = {\n  revisar: async () => ({ estado: 'ok' }),\n  activar: async () => ({ ok: true }),\n  leer: () => null,\n  borrar: () => {},\n  huella: () => ''\n};\n`);
  fs.rmSync(path.join(appDir, 'licencia-main.js.sinofuscar'), { force: true });

  // Do not show license details or offer an update that restores the original.
  const settings = path.join(appDir, 'hb-settings.js');
  let ui = fs.readFileSync(settings, 'utf8');
  const begin = ui.indexOf('    // CerviApp: ACTUALIZACIONES');
  const end = ui.indexOf('    // CerviApp: MIS MAPAS', begin);
  if (begin < 0 || end < 0 || end <= begin) throw new Error('Could not uniquely locate license and update settings.');
  ui = ui.slice(0, begin) + ui.slice(end);
  new vm.Script(ui, { filename: 'hb-settings.js' });
  fs.writeFileSync(settings, ui);

  fs.mkdirSync(path.dirname(dst), { recursive: true });
  if (fs.existsSync(dst)) throw new Error('Output ASAR already exists.');
  await createPackage(tmp, dst);
  uncacheAll();
  const check = JSON.parse(extractFile(dst, 'app/cifrados.json').toString('utf8'));
  if (check.archivos.length !== 0 || !extractFile(dst, 'app/init.js').equals(fs.readFileSync(path.join(mobileDirectory, 'init.js')))) {
    throw new Error('Output package verification failed.');
  }
  const report = {
    originalAsarSha256: originalHash,
    outputAsarSha256: sha256(fs.readFileSync(dst)),
    recoveredCount: recovered.length,
    missing,
    recovered,
    limitations: [
      'Equal lengths do not prove that recovered mobile files are byte-identical to the encrypted desktop originals.',
      'cervi-bench.js remains encrypted and was not recovered.',
      'Remote features requiring a license or account cannot be guaranteed to work without one.',
      'Automatic updates are disabled so that the original build does not overwrite this one.'
    ]
  };
  fs.writeFileSync(reportPath, JSON.stringify(report, null, 2));
  console.log(JSON.stringify({ output: dst, recovered: recovered.length, missing, outputSha256: report.outputAsarSha256 }));
} finally {
  fs.rmSync(tmp, { recursive: true, force: true });
}
