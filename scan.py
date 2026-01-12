# /usr/bin/python3
"""
scan.py - a simple automatic tool to scan a binary file in ctf pwn

- tools incorporated : checksec, file, ROPgadget, strings
- check what protection it has
- showcase bits and how it is linked
- find possibly available gadgets for ROP
- find critical strings /bin/sh

have fun!

"""

from __future__ import annotations
import argparse
import shutil
import subprocess
import sys
from pathlib import Path
from typing import Dict, List, Optional

# readable colors
GREEN = "\033[92m"
RED = "\033[91m"
YELLOW = "\033[93m"
BLUE = "\033[94m"
RESET = "\033[0m"


def run(cmd: List[str]) -> str:
    try:
        out = subprocess.check_output(cmd, stderr=subprocess.DEVNULL)
        return out.decode(errors="ignore")
    except Exception:
        return ""


def tool_available(name: str) -> bool:
    return bool(shutil.which(name))


def parse_checksec(binary: str) -> Dict[str, str]:
    out = run(["checksec", "--file=" + binary]) if tool_available("checksec") else ""
    res = {"RELRO": "unknown", "Canary": "not found", "NX": "unknown", "PIE": "unknown"}
    if not out:
        return res

    lines = [l for l in out.splitlines() if l.strip()]
    text = "\n".join(lines[1:]) if len(lines) >= 2 else out

    # RELRO
    if "Partial RELRO" in text or "Partial" in text:
        res["RELRO"] = "Partial"
    elif "Full RELRO" in text or "Full" in text:
        res["RELRO"] = "Full"
    elif "No RELRO" in text or "No RELRO" in text:
        res["RELRO"] = "None"

    # Canary
    if "Canary found" in text or ("canary" in text.lower() and "found" in text.lower()):
        res["Canary"] = "found"
    else:
        res["Canary"] = "not found"

    # NX
    if "NX enabled" in text or ("nx" in text.lower() and "enabled" in text.lower()):
        res["NX"] = "enabled"
    elif "NX disabled" in text or ("nx" in text.lower() and "disabled" in text.lower()):
        res["NX"] = "disabled"

    # PIE
    if "No PIE" in text or "no pie" in text.lower():
        res["PIE"] = "No PIE"
    elif "PIE" in text or "pie" in text.lower():
        res["PIE"] = "PIE enabled"

    return res


def parse_file(binary: str) -> Dict[str, str]:
    out = run(["file", binary]) if tool_available("file") else ""
    bits = "unknown"
    link = "unknown"
    if "64-bit" in out:
        bits = "64"
    elif "32-bit" in out:
        bits = "32"
    if "statically linked" in out:
        link = "static"
    elif "dynamically linked" in out or "shared object" in out:
        link = "dynamic"
    return {"bits": bits, "link": link}


def has_binsh(binary: str) -> bool:
    if tool_available("strings"):
        out = run(["strings", binary])
        return "/bin/sh" in out
    try:
        return b"/bin/sh" in Path(binary).read_bytes()
    except Exception:
        return False


def find_gadgets(binary: str) -> Dict[str, str]:
    keys = ["ret", "leave_ret", "syscall", "pop_rdi_ret", "pop_rsi_ret", "pop_rdx_ret", "pop_rax_ret"]
    gadgets: Dict[str, str] = {k: "not found" for k in keys}

    ropgadget = None
    for name in ("ROPgadget", "ropgadget", "ROPgadget.py"):
        if shutil.which(name):
            ropgadget = name
            break
    if not ropgadget:
        return gadgets

    out = run([ropgadget, "--binary", binary])
    if not out:
        return gadgets

    for line in out.splitlines():
        low = line.lower()
        addr = line.split(":", 1)[0].strip() if ":" in line else ""
        if gadgets["leave_ret"] == "not found" and "leave" in low and "ret" in low:
            gadgets["leave_ret"] = addr or gadgets["leave_ret"]
        if gadgets["syscall"] == "not found" and "syscall" in low:
            gadgets["syscall"] = addr or gadgets["syscall"]
        if gadgets["pop_rdi_ret"] == "not found" and "pop rdi" in low and "ret" in low:
            gadgets["pop_rdi_ret"] = addr or gadgets["pop_rdi_ret"]
        if gadgets["pop_rsi_ret"] == "not found" and "pop rsi" in low and "ret" in low:
            gadgets["pop_rsi_ret"] = addr or gadgets["pop_rsi_ret"]
        if gadgets["pop_rdx_ret"] == "not found" and "pop rdx" in low and "ret" in low:
            gadgets["pop_rdx_ret"] = addr or gadgets["pop_rdx_ret"]
        if gadgets["pop_rax_ret"] == "not found" and "pop rax" in low and "ret" in low:
            gadgets["pop_rax_ret"] = addr or gadgets["pop_rax_ret"]
        if gadgets["ret"] == "not found" and low.strip().endswith("ret"):
            gadgets["ret"] = addr or gadgets["ret"]
        if all(v != "not found" for v in gadgets.values()):
            break

    return gadgets


def main() -> None:
    parser = argparse.ArgumentParser(description="Simple quick binary scanner")
    parser.add_argument("binary", help="target binary path")
    args = parser.parse_args()

    path = args.binary
    if not Path(path).exists():
        print("Binary not found:", path)
        sys.exit(1)

    prot = parse_checksec(path)
    fb = parse_file(path)
    binsh = has_binsh(path)
    gadgets = find_gadgets(path)

    # output
    print("\n" + BLUE + "[ Protection ]" + RESET)
    print(f"RELRO     : {prot.get('RELRO', 'unknown')}")
    canary_display = GREEN + "found" + RESET if prot.get("Canary") == "found" else RED + "not found" + RESET
    print(f"Canary    : {canary_display}")
    nx_val = prot.get("NX", "unknown")
    nx_display = GREEN + nx_val + RESET if nx_val == "enabled" else RED + nx_val + RESET
    print(f"NX        : {nx_display}")
    pie_raw = prot.get("PIE", "")
    pie_display = "No PIE" if pie_raw.lower().startswith("no") or pie_raw == "" else "PIE enabled"
    print(f"PIE       : {YELLOW + pie_display + RESET}")

    print("\n" + BLUE + "[ Binary ]" + RESET)
    print(f"Bits      : {YELLOW + fb.get('bits', 'unknown') + RESET}")
    print(f"Link      : {YELLOW + fb.get('link', 'unknown') + RESET}")

    print("\n" + BLUE + "[ Strings ]" + RESET)
    print(f"/bin/sh   : {GREEN + 'FOUND' + RESET if binsh else RED + 'NOT FOUND' + RESET}")

    print("\n" + BLUE + "[ Gadgets ]" + RESET)
    for k in ("ret", "leave_ret", "pop_rdi_ret", "pop_rsi_ret", "pop_rdx_ret", "pop_rax_ret", "syscall"):
        v = gadgets.get(k, "not found")
        color = GREEN if v != "not found" else RED
        label = k.ljust(15)
        print(f"{label}: {color}{v}{RESET}")


if __name__ == "__main__":
    main()
