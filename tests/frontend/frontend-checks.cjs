// Browser-free UI checks: app.js is loaded with a fake DOM and pure functions are tested.
// Run: node tests/frontend/frontend-checks.cjs
'use strict';
const fs = require('fs');
const path = require('path');
const vm = require('vm');

const src = fs.readFileSync(path.join(__dirname, '..', '..', 'src', 'Lanora', 'wwwroot', 'app.js'), 'utf8');

function el() {
  return { innerHTML: '', textContent: '', dataset: {}, classList: { add() {}, remove() {} }, style: {},
    addEventListener() {}, setAttribute() {}, close() {}, showModal() {}, focus() {}, open: false };
}
const elements = {};
const document = {
  getElementById: id => (elements[id] ??= el()),
  addEventListener() {}, querySelector: () => null, querySelectorAll: () => [],
  documentElement: {}, body: { dataset: {} }, activeElement: null, title: '',
};
const context = {
  document, console, setTimeout, clearTimeout,
  window: { scrollTo() {} },
  navigator: { language: 'tr-TR' },
  location: { hash: '', pathname: '/' },
  history: { replaceState() {} },
  localStorage: { getItem: () => null, setItem() {} },
  fetch: () => Promise.reject(new Error('offline')),
  Intl, TextDecoderStream: class {}, crypto: {},
};
vm.createContext(context);
vm.runInContext(src, context);
const M = vm.runInContext('M', context); // const declarations are not context properties

let failed = 0, passed = 0;
function check(name, fn) {
  try { fn(); passed++; console.log('PASS', name); }
  catch (e) { failed++; console.log('FAIL', name, '-', e.message); }
}
function assert(cond, msg) { if (!cond) throw new Error(msg); }

check('Traceroute displays API snake case RTT', () => {
  const html = context.traceHopHtml({ ttl: 1, ip: '192.168.1.1', host: 'gw', rtt_ms: 12.5 });
  assert(html.includes('12.5 ms'), html);
  assert(html.includes('192.168.1.1'), html);
  assert(html.includes('gw'), html);
});

check('Traceroute unanswered hop shows *', () => {
  const html = context.traceHopHtml({ ttl: 3, ip: null, host: null, rtt_ms: null });
  assert(html.includes('>*<'), html);
  assert(!html.includes(' ms'), html);
});

check('Traceroute escapes untrusted host names', () => {
  const html = context.traceHopHtml({ ttl: 2, ip: '10.0.0.1', host: '<img src=x onerror=alert(1)>', rtt_ms: 1 });
  assert(!html.includes('<img'), html);
  assert(html.includes('&lt;img'), html);
});

check('Service check results use API snake case fields', () => {
  const html = context.advEvidence({ scripts: [{ id: 'http-title (80)', output: 'Router <b>' }], trace: [] });
  assert(html.includes('http-title (80)'), html);
  assert(html.includes('Router &lt;b&gt;'), html);
});

check('Every translation key has three non-empty languages', () => {
  const bad = Object.entries(M).filter(([, v]) => !Array.isArray(v) || v.length !== 3 || v.some(x => !x));
  assert(bad.length === 0, 'missing: ' + bad.map(([k]) => k).join(', '));
});

check('Translation dictionary has no duplicate keys', () => {
  const body = src.slice(src.indexOf('const M = {'), src.indexOf('\n};', src.indexOf('const M = {')));
  const keys = [...body.matchAll(/(?:^|[,{\s])([A-Za-z_][\w]*):\[/g)].map(m => m[1]);
  const dups = keys.filter((k, i) => keys.indexOf(k) !== i);
  assert(keys.length === Object.keys(M).length + dups.length, 'key scan mismatch');
  assert(dups.length === 0, 'duplicate: ' + dups.join(', '));
});

check('English is the primary language and fallback', () => {
  assert(vm.runInContext("LANGS[0]", context) === 'en', 'LANGS[0] is not en');
  assert(/lang:'en'/.test(src) && /LANGS\.includes\(nav\)\?nav:'en'/.test(src), 'default language is not en');
  const nonEnglish = Object.entries(M).filter(([, v]) => /[çğıİşŞöüÇĞÖÜäß]/.test(v[0])).map(([k]) => k);
  assert(nonEnglish.length === 0, 'first column is not English: ' + nonEnglish.join(', '));
});

check('No third-party engine name in UI texts', () => {
  const all = JSON.stringify(M).toLowerCase();
  assert(!all.includes('nmap') && !all.includes('npcap'), 'found engine name in translations');
});

check('Error codes from advanced scan have translations', () => {
  for (const code of ['AUTHORIZATION_REQUIRED', 'HOST_RESOLVE_FAILED', 'TARGET_RESERVED', 'USE_ADVANCED_SCAN', 'PORTS_REQUIRED'])
    assert(M['err_' + code], 'missing err_' + code);
});

check('esc() neutralises HTML special characters', () => {
  assert(context.esc(`<a href="x">'&`) === '&lt;a href=&quot;x&quot;&gt;&#39;&amp;', context.esc(`<a href="x">'&`));
});

console.log(`\n${passed} passed, ${failed} failed`);
process.exit(failed ? 1 : 0);
