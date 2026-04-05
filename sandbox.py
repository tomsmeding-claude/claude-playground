#!/usr/bin/env python3
import ctypes
import ctypes.util
import json
import os
import platform
import sys
import optparse

DEFAULT_BINDS = [
    "/bin",
    "/usr/bin",
    "/lib",
    "/lib64",
    "/usr/lib",
    "/usr/libexec",
    "/usr/include",
    "/etc/alternatives",
]

_SECCOMP_PROFILE = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                                "seccomp-default.json")

def _build_seccomp_fd(profile_path):
    """Compile a Docker-format seccomp JSON profile into a BPF fd for bwrap --seccomp."""
    lib = ctypes.CDLL(ctypes.util.find_library("seccomp"))

    lib.seccomp_init.restype = ctypes.c_void_p
    lib.seccomp_init.argtypes = [ctypes.c_uint32]
    lib.seccomp_release.restype = None
    lib.seccomp_release.argtypes = [ctypes.c_void_p]
    lib.seccomp_syscall_resolve_name.restype = ctypes.c_int
    lib.seccomp_syscall_resolve_name.argtypes = [ctypes.c_char_p]
    lib.seccomp_rule_add_array.restype = ctypes.c_int
    lib.seccomp_rule_add_array.argtypes = [ctypes.c_void_p, ctypes.c_uint32,
                                           ctypes.c_int, ctypes.c_uint,
                                           ctypes.c_void_p]
    lib.seccomp_export_bpf.restype = ctypes.c_int
    lib.seccomp_export_bpf.argtypes = [ctypes.c_void_p, ctypes.c_int]

    SCMP_ACT_ALLOW = 0x7fff0000
    def SCMP_ACT_ERRNO(e): return 0x00050000 | (e & 0xffff)

    OP = {"SCMP_CMP_NE": 1, "SCMP_CMP_LT": 2, "SCMP_CMP_LE": 3,
          "SCMP_CMP_EQ": 4, "SCMP_CMP_GE": 5, "SCMP_CMP_GT": 6,
          "SCMP_CMP_MASKED_EQ": 7}

    class ArgCmp(ctypes.Structure):
        _fields_ = [("arg", ctypes.c_uint), ("op", ctypes.c_int),
                    ("datum_a", ctypes.c_uint64), ("datum_b", ctypes.c_uint64)]

    # Map uname machine name to the Docker arch name(s) used in the profile.
    _arch_names = {
        "x86_64":  {"amd64", "x32", "x86"},
        "i686":    {"x86"},
        "aarch64": {"arm64"},
        "armv7l":  {"arm"},
        "ppc64le": {"ppc64le"},
        "s390x":   {"s390x", "s390"},
    }.get(platform.machine(), set())

    def _include_entry(entry):
        """Return True if this entry applies (no capabilities, current arch)."""
        inc = entry.get("includes", {})
        exc = entry.get("excludes", {})
        if inc.get("caps"):                               # requires caps we don't have
            return False
        if inc.get("arches") and not (_arch_names & set(inc["arches"])):
            return False                                  # for a different arch
        if exc.get("arches") and (_arch_names & set(exc["arches"])):
            return False                                  # explicitly excluded for our arch
        return True

    with open(profile_path) as f:
        profile = json.load(f)

    errno_ret = profile.get("defaultErrnoRet", 1)
    ctx = lib.seccomp_init(SCMP_ACT_ERRNO(errno_ret))
    if not ctx:
        sys.exit("error: seccomp_init failed")

    try:
        for entry in profile["syscalls"]:
            if not _include_entry(entry):
                continue
            action = SCMP_ACT_ALLOW if entry["action"] == "SCMP_ACT_ALLOW" \
                     else SCMP_ACT_ERRNO(errno_ret)
            raw_args = entry.get("args", [])
            # MASKED_EQ: datum_a = mask (value), datum_b = expected (valueTwo, default 0)
            arg_array = (ArgCmp * len(raw_args))(*[
                ArgCmp(a["index"], OP[a["op"]], a["value"], a.get("valueTwo", 0))
                for a in raw_args
            ]) if raw_args else None
            for name in entry["names"]:
                nr = lib.seccomp_syscall_resolve_name(name.encode())
                if nr < 0:
                    continue  # syscall unknown on this architecture
                lib.seccomp_rule_add_array(ctx, action, nr, len(raw_args), arg_array)

        r, w = os.pipe()
        if lib.seccomp_export_bpf(ctx, w) != 0:
            sys.exit("error: seccomp_export_bpf failed")
        os.close(w)
        os.set_inheritable(r, True)  # survive os.execvp (Python sets O_CLOEXEC by default)
        return r
    finally:
        lib.seccomp_release(ctx)


def main():
    bind_ops = []  # list of ("ro"|"rw", path), preserving user-specified order

    def collect_bind(option, opt_str, value, parser):
        kind = "ro" if option.dest == "read_paths" else "rw"
        bind_ops.append((kind, value))

    parser = optparse.OptionParser(usage="%prog [options] [--] [command]")
    parser.disable_interspersed_args()

    parser.add_option("-r", "--read", action="callback", callback=collect_bind,
                      type="string", dest="read_paths", metavar="PATH",
                      help="bind PATH read-only in the sandbox")
    parser.add_option("-w", "--write", action="callback", callback=collect_bind,
                      type="string", dest="write_paths", metavar="PATH",
                      help="bind PATH read-write in the sandbox")
    parser.add_option("--env", action="append", dest="env_vars",
                      metavar="VAR", help="preserve VAR inside the sandbox")
    parser.add_option("--nonet", action="store_true", default=False,
                      help="disable networking (default: share host network)")
    parser.add_option("--bare", action="store_true", default=False,
                      help="skip default bind list")

    opts, args = parser.parse_args()

    if os.getuid() == 0:
        sys.exit("error: refusing to run as root")

    seccomp_fd = _build_seccomp_fd(_SECCOMP_PROFILE)

    bwrap = ["bwrap",
             "--new-session", "--unshare-all", "--die-with-parent",
             "--proc", "/proc",
             "--dev", "/dev",
             "--seccomp", str(seccomp_fd)]

    if not opts.nonet:
        bwrap += ["--share-net"]

    if not opts.bare:
        for path in DEFAULT_BINDS:
            if os.path.exists(path):
                bwrap += ["--ro-bind", path, path]

    for kind, path in bind_ops:
        flag = "--ro-bind" if kind == "ro" else "--bind"
        bwrap += [flag, path, path]

    bwrap += ["--setenv", "PATH", os.environ.get("PATH", "/usr/local/bin:/usr/bin:/bin")]

    for var in (opts.env_vars or []):
        val = os.environ.get(var)
        if val is None:
            sys.exit(f"error: environment variable {var!r} is not set")
        bwrap += ["--setenv", var, val]

    if args:
        command = args
    else:
        shell = os.environ.get("SHELL", "/bin/sh")
        command = [shell, "-l"]

    os.execvp("bwrap", bwrap + command)

if __name__ == "__main__":
    main()
