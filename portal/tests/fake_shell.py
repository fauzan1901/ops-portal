#!/usr/bin/env python3
"""A fake interactive host for the Web Terminal module (test mode and tests): run on the pseudo-terminal of a session instead of
ssh. The terminal is raw (as ssh leaves it), so this program echoes and edits the line itself, like a remote shell.

    fake_shell.py <name> [--user U] [--kind K] [--sudo-password P]

Commands: hostname, whoami, id, uptime, echo ..., size (rows and columns of the terminal), lines N, sudo -i (asks the
password when --sudo-password is given), sleep N, exit / logout (exit 0), and on a name containing "unreachable" ssh's
connection error (exit 255). Ctrl+C drops the line, Ctrl+D on an empty line exits.
"""
import argparse
import fcntl
import os
import struct
import sys
import termios
import time
import tty


def out(text):
    os.write(1, text.encode())


def size():
    try:
        rows, cols = struct.unpack("HHHH", fcntl.ioctl(0, termios.TIOCGWINSZ, b"\0" * 8))[:2]
        return rows, cols
    except OSError:
        return 0, 0


def read_line(echo=True):
    """A line typed on the raw terminal; None on Ctrl+D (empty line) or end of input; "" on Ctrl+C."""
    line = b""
    while True:
        ch = os.read(0, 1)
        if not ch:
            return None
        if ch in (b"\r", b"\n"):
            out("\r\n")
            return line.decode("utf-8", "replace")
        if ch == b"\x03":
            out("^C\r\n")
            return ""
        if ch == b"\x04" and not line:
            out("\r\n")
            return None
        if ch in (b"\x7f", b"\b"):
            if line:
                line = line[:-1]
                if echo:
                    out("\b \b")
            continue
        if ch == b"\x1b":   # an escape sequence (arrows, bracketed paste markers): ignored
            seq = os.read(0, 1)
            if seq == b"[":
                while True:
                    c = os.read(0, 1)
                    if not c or 0x40 <= c[0] <= 0x7e:
                        break
            continue
        line += ch
        if echo:
            os.write(1, ch)


def main():
    p = argparse.ArgumentParser()
    p.add_argument("name")
    p.add_argument("--user", default="admin")
    p.add_argument("--kind", default="host")
    p.add_argument("--sudo-password", default=None)
    a = p.parse_args()
    if "unreachable" in a.name:
        out(f"ssh: connect to host {a.name} port 22: Connection refused\r\n")
        sys.exit(255)
    user, host = a.user, a.name
    if os.isatty(0):
        tty.setraw(0)   # as ssh leaves the terminal: no echo, no line editing, no \n -> \r\n
    out(f"Last login: {time.strftime('%a %b %d %H:%M:%S %Y')} from 172.26.32.100\r\n")
    while True:
        out(f"[{user}@{host} ~]{'#' if user == 'root' else '$'} ")
        line = read_line()
        if line is None:
            out("logout\r\n")
            return 0
        words = line.split()
        if not words:
            continue
        cmd = words[0]
        if cmd in ("exit", "logout"):
            out("logout\r\n")
            return 0
        if cmd == "hostname":
            out(f"{host}\r\n")
        elif cmd == "whoami":
            out(f"{user}\r\n")
        elif cmd == "id":
            out(f"uid={0 if user == 'root' else 1000}({user}) gid={0 if user == 'root' else 1000}({user})\r\n")
        elif cmd == "uptime":
            out(" 10:42:07 up 87 days,  3:12,  1 user,  load average: 0.41, 0.38, 0.35\r\n")
        elif cmd == "echo":
            out(" ".join(words[1:]) + "\r\n")
        elif cmd == "size":
            rows, cols = size()
            out(f"rows={rows} cols={cols}\r\n")
        elif cmd == "lines":
            n = int(words[1]) if len(words) > 1 and words[1].isdigit() else 10
            for i in range(1, n + 1):
                out(f"line {i}\r\n")
        elif cmd == "sleep":
            time.sleep(float(words[1]) if len(words) > 1 else 1)
        elif line.strip() == "sudo -i":
            if a.sudo_password is not None:
                out(f"[sudo] password for {user}: ")
                given = read_line(echo=False)
                if given != a.sudo_password:
                    out("Sorry, try again.\r\nsudo: 1 incorrect password attempt\r\n")
                    continue
            user = "root"
        else:
            out(f"bash: {cmd}: command not found\r\n")


if __name__ == "__main__":
    sys.exit(main())
