#!/usr/bin/env python3
import os
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

def main():
    parser = optparse.OptionParser(usage="%prog [options] [--] [command]")
    parser.disable_interspersed_args()

    parser.add_option("-r", "--read", action="append", dest="read_paths",
                      metavar="PATH", help="bind PATH read-only in the sandbox")
    parser.add_option("-w", "--write", action="append", dest="write_paths",
                      metavar="PATH", help="bind PATH read-write in the sandbox")
    parser.add_option("--env", action="append", dest="env_vars",
                      metavar="VAR", help="preserve VAR inside the sandbox")
    parser.add_option("--nonet", action="store_true", default=False,
                      help="disable networking (default: share host network)")
    parser.add_option("--bare", action="store_true", default=False,
                      help="skip default bind list")

    opts, args = parser.parse_args()

    bwrap = ["bwrap",
             "--new-session", "--unshare-all", "--die-with-parent",
             "--proc", "/proc",
             "--dev", "/dev"]

    if not opts.nonet:
        bwrap += ["--share-net"]

    if not opts.bare:
        for path in DEFAULT_BINDS:
            if os.path.exists(path):
                bwrap += ["--ro-bind", path, path]

    for path in (opts.read_paths or []):
        bwrap += ["--ro-bind", path, path]

    for path in (opts.write_paths or []):
        bwrap += ["--bind", path, path]

    bwrap += ["--setenv", "PATH", "/usr/local/bin:/usr/bin:/bin"]

    for var in (opts.env_vars or []):
        val = os.environ.get(var)
        if val is not None:
            bwrap += ["--setenv", var, val]

    if args:
        command = args
    else:
        shell = os.environ.get("SHELL", "/bin/sh")
        command = [shell, "-l"]

    os.execvp("bwrap", bwrap + command)

if __name__ == "__main__":
    main()
