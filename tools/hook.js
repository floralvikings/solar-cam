// Frida hook for UBox -- final capture, deadlock-safe (deferred logging).
// p4p_crypto_encode(buf=arg0, len_u16=arg1) obfuscates EVERY outgoing P4P packet;
// at onEnter arg0 is PLAINTEXT (magic 07 18 10 00), so we read msgtype directly.
// Requires the app on the LOCAL P4P path (disable the HA integration so the
// camera's single session is free). Hooks are SDK-only (no libc -> no frida-
// channel reentrancy) and do ZERO I/O; a timer flushes.
'use strict';

function hx(a) { var h = ''; for (var i = 0; i < a.length; i++) { var b = a[i].toString(16); h += (b.length < 2 ? '0' : '') + b; } return h; }
function rd(p, n) { var a = new Array(n); for (var i = 0; i < n; i++) a[i] = p.add(i).readU8(); return a; }
function exp(m, n) { var r = null; m.enumerateExports().forEach(function (e) { if (e.name === n) r = e.address; }); return r; }
function findSdk() { var f = null; Process.enumerateModules().forEach(function (m) { if (/libUBICAPIs/i.test(m.name)) f = f || m; }); return f; }

var pending = [], seen = {}, rawN = {};

// NO I/O here -- decode + buffer only.
function grab(tag, buf, len) {
  if (buf.isNull()) return;
  len = len & 0xffff;
  rawN[tag] = rawN[tag] || 0;
  if (rawN[tag] < 6 && len >= 8) { rawN[tag]++; pending.push({ k: 'RAW', tag: tag, len: len, b: rd(buf, len > 40 ? 40 : len) }); }
  if (len < 16) return;
  var h = rd(buf, 16);
  if (h[0] !== 0x07 || h[1] !== 0x18) return;      // plaintext P4P magic
  var mt = h[8] | (h[9] << 8), key = tag + ':' + mt;
  if (seen[key]) return;
  seen[key] = 1;
  pending.push({ k: 'PKT', tag: tag, mt: '0x' + mt.toString(16), len: len, b: rd(buf, len > 300 ? 300 : len) });
}

function attach() {
  var mod = findSdk();
  if (!mod) return false;
  console.log('[+] SDK: ' + mod.name);
  var ce = exp(mod, 'p4p_crypto_encode');
  if (ce) { Interceptor.attach(ce, { onEnter: function (a) { try { grab('enc', a[0], a[1].toInt32()); } catch (e) {} } }); console.log('  hooked p4p_crypto_encode'); }
  var su = exp(mod, 'p4p_send_udp');
  if (su) { Interceptor.attach(su, { onEnter: function (a) { try { grab('udp', a[1], a[2].toInt32()); } catch (e) {} } }); console.log('  hooked p4p_send_udp'); }
  setInterval(function () {
    if (!pending.length) return;
    var b = pending; pending = [];
    for (var i = 0; i < b.length; i++) {
      var p = b[i];
      if (p.k === 'RAW') console.log('[RAW ' + p.tag + ' len=' + p.len + '] ' + hx(p.b));
      else console.log('[PKT ' + p.tag + ' ' + p.mt + ' len=' + p.len + '] ' + hx(p.b));
    }
  }, 400);
  console.log('[+] capture installed (need app on LOCAL P4P -> disable HA integration)');
  return true;
}
if (!attach()) { console.log('[i] waiting for SDK...'); var t = setInterval(function () { if (attach()) clearInterval(t); }, 300); }
