#!/usr/bin/env python3

"""
Concatenate object files into a single relocatable object, filter global symbols
(using a pattern or by extracting symbols from a version script), then pack into
a static archive.

Usage:
  python static_object_bundler.py --name foo [--symbols "pattern"] [--version-script path]
                                             [--link-flags "flags"] [--ld-path ld] [--objcopy-path objcopy]
                                             [--ar-path ar] [--verbose] objects...

Example:
  python static_object_bundler.py --name mylib --symbols "prefix_*" file1.o file2.o
  python static_object_bundler.py --name mylib --verbose --version-script version.map file1.o file2.o
"""

import argparse
import logging
import os
import shlex
import shutil
import subprocess
import sys
import tempfile
import re

logging.basicConfig(level=logging.INFO, format="%(levelname)s: %(message)s")
logger = logging.getLogger(__name__)


def die(msg, code=1):
    """Log an error message and exit with the given code.

        Args:
            msg (str): The error message to log.
            code (int): The exit code to use (default is 1).
    """
    logger.error(msg)
    sys.exit(code)


def check_executable(exe_path):
    """Check if an executable is available in the PATH.

        Args:
            exe_path (str): The path to the executable to check.
    """
    logger.debug(f"Checking the availability of executable: {exe_path}")
    if shutil.which(exe_path) is None:
        die(f"Required tool not found in PATH: {exe_path}")


def parse_version_script(path):
    """Extract global symbols from a GNU ld version script.

        Args:
            path (str): Path to the version script file.

        Returns:
            list: A list of symbol patterns extracted from the script.
    """
    symbols = []
    logger.debug(f"Parsing version script: {path}")
    try:
        with open(path, "r", encoding="utf-8") as f:
            text = f.read()
    except Exception as e:
        die(f"Cannot read version script {path}: {e}")

    # Remove C-style comments
    text = re.sub(r'/\*.*?\*/', '', text, flags=re.S)
    # Find all 'global:' sections
    for m in re.finditer(r'global\s*:\s*(.*?)\s*(?:local\s*:|};)', text, flags=re.S):
        block = m.group(1)
        # find tokens that look like symbols ending with ;
        for line in block.splitlines():
            line = line.strip()
            if not line:
                continue
            # ignore braces or extraneous lines
            # symbols usually terminated by ';'
            parts = [p.strip() for p in line.split(';') if p.strip()]
            for p in parts:
                # skip directives that are not symbols
                if p in ('*',):
                    symbols.append(p)
                else:
                    # remove trailing comments on the same line
                    p = re.sub(r'//.*', '', p).strip()
                    if p:
                        symbols.append(p)
    # fallback: if no global: found, try to collect top-level symbols before first 'local:' or '};'
    if not symbols:
        # try to find any simple symbol lines like "sym;" globally
        for m in re.finditer(r'(^|\s)([A-Za-z_][A-Za-z0-9_*\-]*)\s*;', text):
            symbols.append(m.group(2))
    return symbols


def main(argv=None):
    parser = argparse.ArgumentParser(description="Bundle object files to .a using ld/objcopy/ar")
    parser.add_argument("--name", required=True, help="Base name for bundle_object_<name>.o and <name>.a")
    group = parser.add_mutually_exclusive_group()
    group.add_argument("--symbols", help="Pattern (glob/wildcard) to keep (passed to objcopy)")
    group.add_argument("--version-script", help="Path to a GNU ld version script to extract global symbols")
    parser.add_argument("--link-flags", help='Extra flags to pass to ld (quoted string)', default="")
    parser.add_argument("--ld-path", help="Path or name of ld executable", default="ld")
    parser.add_argument("--objcopy-path", help="Path or name of objcopy executable", default="objcopy")
    parser.add_argument("--ar-path", help="Path or name of ar executable", default="ar")
    parser.add_argument("--verbose", action="store_true", help="Enable verbose output")
    parser.add_argument("objects", nargs="+", help="Object files (*.o) to bundle")
    args = parser.parse_args(argv)

    # set logging level
    if args.verbose:
        logger.setLevel(logging.DEBUG)

    # check tools
    for tool in (args.ld_path, args.objcopy_path, args.ar_path):
        check_executable(tool)

    # validate object files
    for o in args.objects:
        if not os.path.isfile(o):
            die(f"Encountered an invalid object file: {o}")

    safe_name = args.name.replace(" ", "_")
    bundle_obj = f"bundle_object_{safe_name}.o"
    archive_name = f"{safe_name}.a"

    # 1) ld -r *.o -o bundle_object_<name>.o
    logger.info(f"Creating bundle object: {bundle_obj}")
    ld_cmd = [args.ld_path, "-r"] + args.objects + ["-o", bundle_obj]
    if args.link_flags:
        ld_cmd[1:1] = shlex.split(args.link_flags)  # insert flags after ld command
    logger.debug(f"Running: {' '.join(shlex.quote(x) for x in ld_cmd)}")
    try:
        subprocess.run(ld_cmd, check=True)
    except subprocess.CalledProcessError as e:
        die(f"ld failed (exit {e.returncode})")

    # 2) objcopy filtering
    logger.info("Keeping only the requested symbols")
    objcopy_cmd = [args.objcopy_path]
    tmp_sym_file = None
    if args.symbols:
        # Use wildcard mode so patterns like '*' are supported
        objcopy_cmd += ["--wildcard", f"--keep-global-symbol={args.symbols}", bundle_obj]
    elif args.version_script:
        symbols = parse_version_script(args.version_script)
        if not symbols:
            die("No global symbols were extracted from version script")
        # write to temporary file
        fd, tmp_sym_file = tempfile.mkstemp(prefix="keep_symbols_", text=True)
        logger.debug(f"Writing the {len(symbols)} extracted symbols to temporary file: {tmp_sym_file}")
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            for s in symbols:
                f.write(s + "\n")
        objcopy_cmd += [f"--keep-global-symbols={tmp_sym_file}", bundle_obj]
    else:
        die("Either --symbols or --version-script must be provided")

    logger.debug(f"Running: {' '.join(shlex.quote(x) for x in objcopy_cmd)}")
    try:
        subprocess.run(objcopy_cmd, check=True)
    except subprocess.CalledProcessError as e:
        if tmp_sym_file and os.path.exists(tmp_sym_file):
            os.remove(tmp_sym_file)
            die(f"objcopy failed (exit {e.returncode})")
        if tmp_sym_file and os.path.exists(tmp_sym_file):
            os.remove(tmp_sym_file)

    # 3) ar rcs <name>.a bundle_object_<name>.o
    logger.info(f"Creating static archive: {archive_name}")
    ar_cmd = [args.ar_path, "rcs", archive_name, bundle_obj]
    logger.debug(f"Running: {' '.join(shlex.quote(x) for x in ar_cmd)}")
    try:
        subprocess.run(ar_cmd, check=True)
    except subprocess.CalledProcessError as e:
        die(f"ar failed (exit {e.returncode})")

    logger.info(f"Successfully created static archive: {archive_name}")


if __name__ == "__main__":
    main()
