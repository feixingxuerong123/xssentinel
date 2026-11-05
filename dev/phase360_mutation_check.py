# -*- coding: utf-8 -*-
"""Phase 360 mutation control: baseline green -> mutated RED -> restored green.

Project rule (AGENTS.md "变异对照"): assert the text exists before mutating
(ABORT if not -- never "just run it and see"), run three passes, and accept
only a mutated-pass that is actually RED with a restored pass that is green.

Usage:  python dev/phase360_mutation_check.py
"""
from __future__ import annotations

import os
import subprocess
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
TEST = "tests/test_phase360_cli_compat.py"

# (name, relative file, old bytes, mutated bytes, pytest -k selector)
MUTATIONS = [
    ("version flag removed", "xssentinel/__main__.py",
     b'    ap.add_argument("-V", "--version", action="version",\n'
     b'                    version=f"xssentinel {__version__}",\n'
     b'                    help="show program\'s version number and exit")\n',
     # Renaming the flags is NOT a real mutation: argparse abbreviation
     # still resolves --version to --version-x.  Remove the action outright.
     b'    if False:  # MUTATED: version action removed\n'
     b'        ap.add_argument("-Vx", "--version-x", action="version",\n'
     b'                        version=f"xssentinel {__version__}",\n'
     b'                        help="show program\'s version number and exit")\n',
     "test_version_flags or test_version_flag_is_registered"),

    ("bare print returns to cli_runner", "xssentinel/cli_runner.py",
     b'print("[+] Token accepted" if ok else "[!] Token rejected", file=human())',
     b'print("[+] Token accepted" if ok else "[!] Token rejected")',
     "test_every_cli_print_names_its_stream or login"),

    ("Config.load silently swallows bad JSON again",
     "xssentinel/core/config.py",
     b'raise ConfigError(f"{path}: invalid JSON: {e}") from e',
     b'return cls()  # MUTATED: silent empty config',
     "test_bad_config_is_an_honest_usage_error"),

    ("nuclei stdout gate removed", "xssentinel/__main__.py",
     b'if stdout_output and args.format == "nuclei":',
     b'if False and stdout_output and args.format == "nuclei":',
     "test_nuclei_cannot_be_written_to_stdout"),

    ("broken pipe swallowed as a target failure", "xssentinel/__main__.py",
     b'        except OutputPipeClosed:\r\n'
     b'            # The reader left; do NOT mark this target (or the other 39 in\r\n'
     b'            # the batch) as "scan failed" -> exit 3.  main() ends the run.\r\n'
     b'            raise\r\n',
     b'        except OutputPipeClosed:\r\n'
     b'            st["status"] = "failed"\r\n'
     b'            return st\r\n',
     "test_broken_pipe_ends_cleanly"),

    ("config keys shadowed by argparse defaults again",
     "xssentinel/__main__.py",
     b'cli_dict = _explicit_cli_values(mode, argv)',
     b'cli_dict = {k: v for k, v in vars(args).items()}  # MUTATED',
     "test_config_options_are_not_shadowed"),
]


def run(selector):
    cmd = [sys.executable, "-m", "pytest", TEST, "-q", "--no-header",
           "-p", "no:cacheprovider", "-k", selector]
    r = subprocess.run(cmd, cwd=ROOT, capture_output=True, timeout=600)
    tail = (r.stdout + r.stderr).decode("utf-8", "replace")
    return r.returncode, tail[-500:]


def main():
    verdicts = []
    for name, rel, old, mutated, selector in MUTATIONS:
        path = os.path.join(ROOT, rel)
        with open(path, "rb") as f:
            original = f.read()
        # This tree is CRLF (core.autocrlf=true); normalise the anchors so
        # the control also works on a LF checkout.
        nl = b"\r\n" if b"\r\n" in original else b"\n"
        def norm(x):
            return x.replace(b"\r\n", b"\n").replace(b"\n", nl)
        old, mutated = norm(old), norm(mutated)
        if original.count(old) != 1:
            print("ABORT: %s -> found %d occurrences of the mutation anchor"
                  % (name, original.count(old)))
            return 1
        try:
            base_rc, base_out = run(selector)
            if base_rc != 0:
                print("ABORT: %s baseline is not green\n%s"
                      % (name, base_out))
                return 1
            with open(path, "wb") as f:
                f.write(original.replace(old, mutated, 1))
            mut_rc, mut_out = run(selector)
            if mut_rc == 0:
                print("FAIL: %s mutated pass is GREEN (guard has no teeth)\n%s"
                      % (name, mut_out))
                return 1
            failed = [ln for ln in mut_out.splitlines()
                      if "failed" in ln or "passed" in ln]
            print("  mutated RED: %s" % (failed[-1] if failed else "rc=%d" % mut_rc))
        finally:
            with open(path, "wb") as f:
                f.write(original)
        rest_rc, rest_out = run(selector)
        if rest_rc != 0:
            print("FAIL: %s restored pass is not green\n%s"
                  % (name, rest_out))
            return 1
        verdicts.append((name, base_rc, mut_rc, rest_rc))
        print("OK  %-52s baseline=%d mutated=%d restored=%d" %
              (name, base_rc, mut_rc, rest_rc))

    print("\n%d mutation controls passed (all red when reverted, all green "
          "after restore)." % len(verdicts))
    return 0


if __name__ == "__main__":
    sys.exit(main())
