// bypass_native.js — Neutralise open/openat/access/stat/lstat sur chemins suspects

const SUS = [
  '/system/bin/su', '/system/xbin/su', '/sbin/su', '/system/su',
  '/system/bin/busybox', '/system/xbin/busybox'
];

function isSuspiciousPath(ptrPath) {
  try { const p = ptrPath.readCString(); return !!p && (SUS.indexOf(p) !== -1 || p.indexOf('/proc/mounts') !== -1 || p.indexOf('/proc/self/mounts') !== -1); } catch (_) { return false; }
}

function hookFunc(name, argIndexForPath) {
  try {
    const addr = Module.getExportByName(null, name);
    Interceptor.attach(addr, {
      onEnter(args) {
        const pathPtr = argIndexForPath >= 0 ? args[argIndexForPath] : null;
        if (pathPtr && isSuspiciousPath(pathPtr)) {
          this.block = true;
          this.path = pathPtr.readCString();
        }
      },
      onLeave(retval) {
        if (this.block) {
          console.log('[+] Blocked', name, 'on', this.path);
          retval.replace(ptr(-1));
        }
      }
    });
    console.log('[+] Hooked', name);
  } catch (e) { /* silencieux si non dispo sur la plateforme */ }
}

hookFunc('open', 0);     // int open(const char *pathname, int flags, ...)
hookFunc('openat', 1);   // int openat(int dirfd, const char *pathname, int flags, ...)
hookFunc('access', 0);   // int access(const char *pathname, int mode)
hookFunc('stat', 0);     // int stat(const char *pathname, struct stat *buf)
hookFunc('lstat', 0);    // int lstat(const char *pathname, struct stat *buf)