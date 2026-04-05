#!/usr/bin/env python3.12
import json
import os
import platform
import seccomp
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

_OP = {"SCMP_CMP_NE": seccomp.NE, "SCMP_CMP_LT": seccomp.LT, "SCMP_CMP_LE": seccomp.LE,
       "SCMP_CMP_EQ": seccomp.EQ, "SCMP_CMP_GE": seccomp.GE, "SCMP_CMP_GT": seccomp.GT,
       "SCMP_CMP_MASKED_EQ": seccomp.MASKED_EQ}

# Map uname machine name to the Docker arch name(s) used in the profile.
_machine = platform.machine()
if _machine not in ("x86_64", "aarch64"):
    sys.exit(f"error: unsupported architecture {_machine!r}")
_ARCH_NAMES = {"x86_64": {"amd64", "x32", "x86"}, "aarch64": {"arm64"}}[_machine]


def _include_entry(entry):
    """Return True if this profile entry applies (no capabilities, current arch)."""
    inc = entry.get("includes", {})
    exc = entry.get("excludes", {})
    if inc.get("caps"):                                   # requires caps we don't have
        return False
    if inc.get("arches") and not (_ARCH_NAMES & set(inc["arches"])):
        return False                                      # for a different arch
    if exc.get("arches") and (_ARCH_NAMES & set(exc["arches"])):
        return False                                      # explicitly excluded for our arch
    return True


def _build_seccomp_fd(profile_path):
    """Compile a Docker-format seccomp JSON profile into a BPF fd for bwrap --seccomp."""
    with open(profile_path) as f:
        profile = json.load(f)

    errno_ret = profile.get("defaultErrnoRet", 1)
    filt = seccomp.SyscallFilter(defaction=seccomp.ERRNO(errno_ret))

    for entry in profile["syscalls"]:
        if not _include_entry(entry):
            continue
        action = seccomp.ALLOW if entry["action"] == "SCMP_ACT_ALLOW" \
                 else seccomp.ERRNO(entry.get("errnoRet", errno_ret))
        # MASKED_EQ: datum_a = mask (value), datum_b = expected (valueTwo, default 0)
        args = [seccomp.Arg(a["index"], _OP[a["op"]], a["value"], a.get("valueTwo", 0))
                for a in entry.get("args", [])]
        for name in entry["names"]:
            if seccomp.resolve_syscall(seccomp.Arch.NATIVE, name) == -1:
                continue  # syscall unknown on this architecture
            filt.add_rule(action, name, *args)

    r, w = os.pipe()
    with os.fdopen(w, "wb") as wf:
        filt.export_bpf(wf)
    os.set_inheritable(r, True)  # survive os.execvp (Python sets O_CLOEXEC by default)
    return r


def _build_tiocsti_block_fd():
    """Block TIOCSTI (terminal keystroke injection) via a supplemental seccomp filter.

    This is needed because we don't use --new-session, so the sandbox inherits
    the caller's controlling terminal. TIOCSTI is enabled on this system
    (legacy_tiocsti=1) and would otherwise allow injecting keystrokes into the
    parent shell after the sandbox exits.
    """
    TIOCSTI = 0x5412
    filt = seccomp.SyscallFilter(defaction=seccomp.ALLOW)
    filt.add_rule(seccomp.ERRNO(1), "ioctl", seccomp.Arg(1, seccomp.EQ, TIOCSTI))
    r, w = os.pipe()
    with os.fdopen(w, "wb") as wf:
        filt.export_bpf(wf)
    os.set_inheritable(r, True)
    return r


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
    tiocsti_fd = _build_tiocsti_block_fd()

    bwrap = ["bwrap",
             "--unshare-all", "--die-with-parent",
             "--proc", "/proc",
             "--dev", "/dev",
             "--add-seccomp-fd", str(seccomp_fd),
             "--add-seccomp-fd", str(tiocsti_fd)]

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
