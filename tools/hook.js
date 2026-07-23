// Frida hook for UBox / libUBICAPIs*.so -- diagnostic: hook multiple points on
// the send path and log unconditionally, so we can see which one fires and grab
// the lanstreamreq (with the 16-byte view password). Keep output OUT of git.
'use strict';

function hexAll(ptr, len) {
  var out = '';
  for (var i = 0; i < len; i++) {
    var b = ptr.add(i).readU8().toString(16);
    out += (b.length < 2 ? '0' : '') + b;
  }
  return out;
}
function exp(mod, name) {
  var a = null;
  mod.enumerateExports().forEach(function (e) { if (e.name === name) a = e.address; });
  return a;
}
function findSdk() {
  var f = null;
  Process.enumerateModules().forEach(function (m) { if (/libUBICAPIs/i.test(m.name)) f = f || m; });
  return f;
}

// Look for a P4P packet (magic 07 18 10 00) among a call's pointer args, and a
// plausible length among the integer args; dump it if the msgtype is a request.
function scanArgs(tag, args, n) {
  for (var i = 0; i < n; i++) {
    var p;
    try { p = args[i]; } catch (e) { continue; }
    if (p.isNull()) continue;
    var b0;
    try { b0 = p.readU8(); } catch (e) { continue; }
    if (b0 !== 0x07) continue;
    try {
      if (p.add(1).readU8() !== 0x18) continue;         // magic 07 18 10 00
      var mt = p.add(8).readU16();
      // find a length arg
      var len = 0;
      for (var j = 0; j < n; j++) {
        var v = args[j].toInt32() & 0xffff;
        if (v >= 16 && v <= 2000) { len = v; }
      }
      if (!len) len = 128;
      console.log('\n[' + tag + '] P4P in arg' + i + ' msgtype=0x' + mt.toString(16) + ' len=' + len);
      console.log('  full=' + hexAll(p, len));
      return true;
    } catch (e) {}
  }
  return false;
}

function attach() {
  var mod = findSdk();
  if (!mod) return false;
  console.log('[+] SDK: ' + mod.name + ' @ ' + mod.base);

  var counters = {};
  [['p4p_send_udp', 4], ['p4p_crypto_encode', 2], ['p4p_client_send_lanstreamreq', 2],
   ['p4p_client_send_rlystreamreq', 2]].forEach(function (spec) {
    var addr = exp(mod, spec[0]);
    if (!addr) { console.log('  (no export ' + spec[0] + ')'); return; }
    counters[spec[0]] = 0;
    Interceptor.attach(addr, {
      onEnter: function (args) {
        counters[spec[0]]++;
        if (counters[spec[0]] <= 3 || counters[spec[0]] % 200 === 0)
          console.log('[call] ' + spec[0] + ' #' + counters[spec[0]]);
        scanArgs(spec[0], args, spec[1]);
      }
    });
    console.log('  hooked ' + spec[0] + ' @ ' + addr);
  });
  return true;
}

if (!attach()) {
  console.log('[i] waiting for SDK...');
  var t = setInterval(function () { if (attach()) clearInterval(t); }, 300);
}
