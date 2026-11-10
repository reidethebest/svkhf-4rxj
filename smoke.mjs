import fs from 'node:fs';
import path from 'node:path';
import { spawn } from 'node:child_process';

const [exe, output] = process.argv.slice(2);
if (!output) throw new Error('Usage: node smoke.mjs CerviApp.exe output-directory');
fs.mkdirSync(output, { recursive: true });
const wait = ms => new Promise(resolve => setTimeout(resolve, ms));
const allowedEnv = ['PATH', 'Path', 'PATHEXT', 'SystemRoot', 'SYSTEMROOT', 'WINDIR', 'ComSpec', 'TEMP', 'TMP', 'APPDATA', 'LOCALAPPDATA', 'USERPROFILE', 'USERNAME', 'COMPUTERNAME', 'PROGRAMDATA', 'ProgramFiles', 'ProgramFiles(x86)'];
const appEnv = Object.fromEntries(allowedEnv.filter(k => process.env[k] !== undefined).map(k => [k, process.env[k]]));
const proc = spawn(exe, ['--remote-debugging-port=9222', '--remote-allow-origins=*', '--disable-gpu'], { windowsHide: true, stdio: 'ignore', env: appEnv });
let socket;
let nextId = 0;
const pending = new Map();
const events = [];
const errors = [];
const requests = new Map();
const failedLocal = [];
const completedLocal = new Set();

function send(method, params = {}) {
  return new Promise((resolve, reject) => {
    const id = ++nextId;
    const timer = setTimeout(() => { pending.delete(id); reject(new Error(`Timeout: ${method}`)); }, 15000);
    pending.set(id, { resolve, reject, timer });
    socket.send(JSON.stringify({ id, method, params }));
  });
}
async function evaluate(expression) {
  const result = await send('Runtime.evaluate', { expression, returnByValue: true, awaitPromise: true });
  if (result.exceptionDetails) throw new Error(result.exceptionDetails.text);
  return result.result.value;
}
try {
  let target;
  for (let attempt = 0; attempt < 80; attempt++) {
    if (proc.exitCode !== null) throw new Error(`Application exited with code ${proc.exitCode}`);
    try {
      const response = await fetch('http://127.0.0.1:9222/json/list');
      const targets = await response.json();
      target = targets.find(t => t.type === 'page' && t.webSocketDebuggerUrl && t.url.startsWith('file:'));
      if (target) break;
    } catch {}
    await wait(1000);
  }
  if (!target) throw new Error('No Electron page became available through the debugger.');
  socket = new WebSocket(target.webSocketDebuggerUrl);
  socket.addEventListener('message', ({ data }) => {
    const msg = JSON.parse(data);
    if (msg.id && pending.has(msg.id)) {
      const p = pending.get(msg.id); clearTimeout(p.timer); pending.delete(msg.id);
      msg.error ? p.reject(new Error(msg.error.message)) : p.resolve(msg.result);
    } else if (msg.method === 'Network.requestWillBeSent') {
      requests.set(msg.params.requestId, msg.params.request?.url || '');
    } else if (msg.method === 'Network.loadingFinished') {
      const url = requests.get(msg.params.requestId);
      if (url?.startsWith('file:')) completedLocal.add(url);
    } else if (msg.method === 'Runtime.exceptionThrown') {
      errors.push(msg.params.exceptionDetails?.exception?.description || msg.params.exceptionDetails?.text || 'JavaScript exception');
    } else if (msg.method === 'Network.loadingFailed' || msg.method === 'Log.entryAdded') {
      if (msg.method === 'Network.loadingFailed' && requests.get(msg.params.requestId)?.startsWith('file:')) failedLocal.push({ url: requests.get(msg.params.requestId), error: msg.params.errorText });
      events.push({ method: msg.method, params: msg.params });
    }
  });
  await new Promise((resolve, reject) => { socket.addEventListener('open', resolve, { once: true }); socket.addEventListener('error', reject, { once: true }); });
  await send('Page.enable'); await send('Runtime.enable'); await send('Network.enable'); await send('Log.enable');
  await send('Page.reload', { ignoreCache: true });
  await wait(12000);
  let state = await evaluate(`(() => ({url:location.href,title:document.title,ready:document.readyState,text:(document.body?.innerText||'').slice(0,2000),settings:!!window.HBSettings,bridge:!!window.CerviBridge,scriptCount:document.scripts.length,nicknamePrompt:!!document.querySelector('#cvBienv')}))()`);
  if (/activacion\.html/i.test(state.url) || /peg[aá].*key|activ[aá].*app/i.test(state.text)) throw new Error(`Unexpected activation screen: ${JSON.stringify(state)}`);
  if (state.ready !== 'complete' || state.text.length < 20) throw new Error(`Main page did not load: ${JSON.stringify(state)}`);
  if (/roomList\.html/i.test(state.url)) {
    if (!state.settings || !state.bridge || state.scriptCount < 15) throw new Error(`Room-list scripts did not finish loading: ${JSON.stringify(state)}`);
    await evaluate(`(() => {document.querySelector('#cvn button')?.click();return true;})()`);
    await wait(500);
    await evaluate(`(() => {let input=document.querySelector('#cvBvNick'); if(input){input.value='PruebaWindows';input.dispatchEvent(new Event('input',{bubbles:true}));document.querySelector('#cvBvOk')?.click();} return true;})()`);
    await wait(1000);
    const settingsOpened = await evaluate(`(() => {document.querySelector('#bSettings')?.click();return true;})()`);
    await wait(1500);
    const after = await evaluate(`(() => {const o=document.querySelector('.hbs-overlay');return {nickname:document.querySelector('#nickName')?.textContent||'',settingsVisible:!!o&&!o.hidden&&getComputedStyle(o).display!=='none',trainingButtonReady:typeof document.querySelector('#bEntreno')?.onclick==='function',text:(document.body?.innerText||'').slice(0,3000)};})()`);
    if (!after.settingsVisible) throw new Error(`Settings did not open: ${JSON.stringify(after)}`);
    if (!after.trainingButtonReady) throw new Error(`Training action did not initialize: ${JSON.stringify(after)}`);
    const sandboxGame = await evaluate(`(() => {try {const api=abcHaxballAPI(window,{noVariableValueChangeEvent:true});const room=api.Room.sandbox({},{controlledPlayerId:1});room.playerJoin(1,'Prueba','ar',null,'local','local');room.setPlayerTeam(1,1,0);room.startGame(0);const result={started:!!room.state?.gameState,players:room.state?.players?.length??null};room.stopGame(0);return result;}catch(e){return {error:String(e&&e.stack||e)};}})()`);
    if (!sandboxGame.started || sandboxGame.players !== 1) throw new Error(`Sandbox game did not start: ${JSON.stringify(sandboxGame)}`);
    const online = await evaluate(`(() => ({geoResolved:!!window.geo,roomCount:Array.isArray(window.roomList)?window.roomList.length:null,roomLabel:document.querySelector('#roomCount')?.textContent||''}))()`);
    state = { ...state, afterInteraction: after, settingsClickSent: settingsOpened, sandboxGame, online };
  }
  const unexpectedErrors = errors.filter(e => !/failed to fetch|networkerror|net::err_/i.test(e));
  const unresolvedLocal = failedLocal.filter(item => !(item.error === 'net::ERR_ABORTED' && completedLocal.has(item.url)));
  if (unresolvedLocal.length || unexpectedErrors.length) throw new Error(`Local asset or JavaScript errors: ${JSON.stringify({ unresolvedLocal, unexpectedErrors })}`);
  const screenshot = await send('Page.captureScreenshot', { format: 'png' });
  fs.writeFileSync(path.join(output, 'windows.png'), Buffer.from(screenshot.data, 'base64'));
  const report = { startup: state, javascriptExceptions: errors, unresolvedLocal, cancelledOnReload: failedLocal.length - unresolvedLocal.length, eventCount: events.length, events: events.slice(0, 30) };
  fs.writeFileSync(path.join(output, 'windows-smoke.json'), JSON.stringify(report, null, 2));
  console.log(JSON.stringify(report));
} catch (err) {
  fs.writeFileSync(path.join(output, 'windows-smoke-failure.txt'), String(err.stack || err));
  throw err;
} finally {
  if (socket) socket.close();
  if (proc.exitCode === null) spawn('taskkill', ['/PID', String(proc.pid), '/T', '/F'], { stdio: 'ignore' });
}
