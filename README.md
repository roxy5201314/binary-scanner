# Binary Scanner

A simple, automatic ELF binary security scanner for **ctf / pwn / exploitation**.

This tool is designed to speed up the *initial analysis phase* of a pwn challenge or real-world ELF binary by automatically collecting:

* common binary protections
* basic binary attributes
* presence of `/bin/sh`
* frequently used ROP gadgets (with addresses)

It is intentionally **simple, readable, and hackable**, not a full framework.

I will do my best to ameliorate it as I progress, I swear.

---

## Features

### Protection checks (via `checksec`)

* RELRO: `Full / Partial / None`
* Stack Canary: `found / not found`
* NX: `enabled / disabled`
* PIE: `PIE enabled / No PIE`

### Binary information

* Architecture bits: `32 / 64`
* Link type: `dynamic / static`

### Strings

* Detects whether `/bin/sh` exists in the binary (FOUND / NOT FOUND)

### ROP Gadgets (via `ROPgadget`)

Prints the first found address of common gadgets:

* `ret`
* `leave ; ret` for stack pivot
* `pop rdi ; ret` for ROP...
* `pop rsi ; ret`
* `pop rdx ; ret`
* `pop rax ; ret`
* `syscall`

If a gadget is not found, it is explicitly shown as `not found`.

---

## Requirements

Linux environment

Tools incorporated:

* `checksec`
* `ROPgadget`
* `strings` (from binutils)

Python:

* Python 3.8+

Install dependencies on Ubuntu / WSL:

```bash
sudo apt update
sudo apt install -y checksec binutils
pip3 install ropgadget
```

---

## Usage

```bash
python3 scan.py ./binary
```

Example output:

```
[ Protection ]
RELRO     : Full
Canary    : found
NX        : enabled
PIE       : PIE enabled

[ Binary ]
Bits      : 64
Link      : dynamic

[ Strings ]
/bin/sh   : NOT FOUND

[ Gadgets ]
ret            : 0x0000000000001399
leave_ret      : 0x0000000000001399
pop_rdi_ret    : 0x0000000000001413
pop_rsi_ret    : 0x0000000000001411
pop_rdx_ret    : not found
pop_rax_ret    : not found
syscall        : not found
```

---

## Design Philosophy

* **Fast**: one command, useful output
* **Human-readable**: with eye-catching colors
* **CTF-oriented**: focuses on what matters for exploitation
* **Extensible**: easy to add more gadgets or checks for deeper research

This tool is meant to replace **repetitive** manual steps like:

* running `checksec`
* grepping `/bin/sh`
* manually scanning ROPgadget output

---

## Possible Improvements in the future

* Add **heap-related** checks
* Support ARM / AArch64
* Add `--short` summary mode
* Integrate with pwntools templates

---

## 📄 License

MIT License

---

## 👤 Author

Built by roxy

- an enthusiastic cybersecurity student focusing on **binary exploitation and pwn challenges**.

If you use or extend this tool, feel free to ⭐ the repo or open an issue.

Thanks!

Have fun!
