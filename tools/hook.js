// Frida hook for the UBox / libUBICAPIs.so P4P SDK.
//
// p4p_crypto_encode(data, len) is called on EVERY outgoing packet with the
// plaintext buffer before obfuscation. We log the stream-request packets
// (msgtype 0x1307 lanstreamreq, 0x1205 rlystreamreq, 0x1301 lansearch) in full
// so we can read the 16-byte view password the app puts in the request body.
//
// Attach:  frida -U Gadget -l tools/hook.js      (gadget/non-root)
//   or:    frida -U -n Gadget -l tools/hook.js
//
// The password is a device secret -- keep the dumped output OUT of git.

'use strict';

var LIB = 'libUBICAPIs.so';
var WANT = { 0x1307: 'lanstreamreq', 0x1205: 'rlystreamreq', 0x1301: 'lansearch',
             0x1101: 'session_req', 0x1201: 'cli_session_req' };

function u16(ptr, off) { return ptr.add(off).readU16(); }

function hexAll(ptr, len) {
  var out = '';
  for (var i = 0; i < len; i++) {
    var b = ptr.add(i).readU8().toString(16);
    if (b.length < 2) b = '0' + b;
    out += b;
  }
  return out;
}

function attach() {
  var mod = Process.findModuleByName(LIB);
  if (!mod) return false;
  var enc = null;
  try { enc = Module.getExportByName(LIB, 'p4p_crypto_encode'); } catch (e) {}
  if (!enc) { console.log('[!] p4p_crypto_encode export not found'); return true; }

  Interceptor.attach(enc, {
    onEnter: function (args) {
      var data = args[0];
      var len = args[1].toInt32() & 0xffff;
      if (data.isNull() || len < 16) return;
      // magic 07 18 10 00 ?
      if (data.readU8() !== 0x07) return;
      var mt = u16(data, 8);
      if (WANT[mt]) {
        console.log('\n[SEND ' + WANT[mt] + '] msgtype=0x' + mt.toString(16) +
                    ' len=' + len);
        console.log('  full=' + hexAll(data, len));
        // For a 0x1307/0x1205 request, the body starts at offset 16; the view
        // password is the 16-byte block ~body[76] => packet offset ~92.
        if ((mt === 0x1307 || mt === 0x1205) && len >= 108) {
          console.log('  body[72:76] conv = ' + hexAll(data.add(16 + 72), 4));
          console.log('  body[44:108] descriptor = ' + hexAll(data.add(16 + 44), 64));
        }
      }
    }
  });
  console.log('[+] hooked p4p_crypto_encode in ' + LIB + ' @ ' + mod.base);
  return true;
}

// The gadget may load before libUBICAPIs.so; retry until present.
if (!attach()) {
  console.log('[i] waiting for ' + LIB + ' to load...');
  var t = setInterval(function () { if (attach()) clearInterval(t); }, 300);
}
