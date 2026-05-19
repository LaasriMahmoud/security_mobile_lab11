// anti_frida.js — Masque quelques indices Frida côté Java

Java.perform(function() {
  // Masquer des variables d’environnement mentionnant FRIDA
  try {
    const Sys = Java.use('java.lang.System');
    Sys.getenv.overload('java.lang.String').implementation = function (name) {
      if (name && name.toLowerCase().indexOf('frida') !== -1) {
        console.log('[+] Hiding env var', name);
        return null;
      }
      return this.getenv(name);
    };
  } catch (e) {}

  // Bloquer connexions aux ports Frida habituels
  try {
    const InetSocketAddress = Java.use('java.net.InetSocketAddress');
    const Socket = Java.use('java.net.Socket');
    Socket.connect.overload('java.net.SocketAddress').implementation = function (addr) {
      try {
        const s = addr.toString();
        if (s.indexOf(':27042') !== -1 || s.indexOf(':27043') !== -1) {
          console.log('[+] Blocked connect to', s);
          throw new Error('Connection refused');
        }
      } catch (_) {}
      return this.connect(addr);
    };
  } catch (e) {}
});
