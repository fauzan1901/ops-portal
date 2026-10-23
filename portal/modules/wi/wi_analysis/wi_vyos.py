#!/usr/bin/env python3
"""Runs ON a VyOS (sent by the portal for one command, then removed): the image commands that ask questions. Rule of the
operations team (2026-10-22): every yes/no question is answered Yes, every other question keeps its proposed value
(Enter), whatever the order (the prompts differ between VyOS 1.3, 1.4, 1.5 and 2026.x). With it, add system image keeps
the configuration and the SSH host keys, makes the new image the default boot, and replaces an image of the same name
left by an install that was stopped (it is not in show system image, so it cannot boot).

    wi_vyos.py install <folder>/<image>.iso  add system image (folder: /tmp or /home/<user>)
    wi_vyos.py default-boot <image name>     set system image default-boot (roll back to the previous image)
    wi_vyos.py copy <iso> <user>@<host> <port> [folder]   ON THE JUMP HOST: scp of the image to /tmp (or folder) of a VyOS that logs in with a
                                             password, read from stdin (never on a command line or in a file) and typed
                                             once into the password prompt of scp
    wi_vyos.py fetch <user>@<host> <port> <file>   ON THE JUMP HOST: scp of /config/config.boot of that VyOS to <file>
                                             (the configuration backup), the password as for copy

A question that is neither yes/no nor has a proposed value stops the command (nothing is typed by guess). Exit 0 done,
5 refused, 6 such a question or timeout (a person looks at the output). Python 3.7 (VyOS 1.3) and later.
"""
import os
import pty
import re
import select
import signal
import sys
import time

WRAPPER = os.environ.get("WI_VYOS_WRAPPER", "/opt/vyatta/bin/vyatta-op-cmd-wrapper")
SCP = os.environ.get("WI_VYOS_SCP", "/usr/bin/scp")
TIMEOUT = int(os.environ.get("WI_VYOS_TIMEOUT", "1800"))
QUIET = float(os.environ.get("WI_VYOS_QUIET", "3"))   # seconds without output: the command waits for an answer

YES_NO = re.compile(r"[(\[]\s*y(es)?\s*/\s*n(o)?\s*[)\]]", re.I)   # (Yes/No), [Y/n], (y/n), [yes/no]
PROPOSED = re.compile(r"\[[^\]]*\]\s*:?\s*$")


def yes_or_default(question):
    """Yes to a yes/no question, Enter (the proposed value) to any other question with one; None: neither."""
    if YES_NO.search(question):
        return "Yes"
    if PROPOSED.search(question):
        return ""
    return None


def no_answer(question):
    return None
# a question: ends with "?", a proposed value "[...]" or "(yes/no)" (optionally followed by ":"); progress lines that
# stay quiet for a while (copying the image) never look like this
QUESTION = re.compile(r"(\?|\[[^\]]*\]|\((yes/no|y/n)\))\s*:?\s*$", re.I)


def say(text):
    sys.stdout.write(text.rstrip("\n") + "\n")
    sys.stdout.flush()


PASSWORD_PROMPT = re.compile(r"(password|passphrase)[^\n]*:\s*$", re.I)


def drive(argv, answer, question=None, secret=None):
    """Run argv in a pseudo-terminal; answer(question) gives the text typed for each question (None: stopped without
    answering). Returns (exit code, transcript). secret: typed once into a password prompt (a second prompt means it was
    refused: stopped)."""
    question = question or QUESTION
    secret_used = False
    pid, fd = pty.fork()
    if pid == 0:
        os.execv(argv[0], argv)
    transcript, pending, last, start = "", "", time.time(), time.time()
    rc = None
    try:
        while True:
            if time.time() - start > TIMEOUT:
                os.kill(pid, signal.SIGTERM)
                return 6, transcript + f"\n[portal] no end after {TIMEOUT} s: stopped"
            ready, _, _ = select.select([fd], [], [], 0.5)
            if ready:
                try:
                    chunk = os.read(fd, 4096).decode("utf-8", "replace")
                except OSError:
                    chunk = ""
                if not chunk:
                    break
                transcript += chunk
                pending += chunk
                last = time.time()
                continue
            done, status = os.waitpid(pid, os.WNOHANG)
            if done:
                rc = os.WEXITSTATUS(status) if os.WIFEXITED(status) else 1
                break
            asked = pending.strip().splitlines()[-1] if pending.strip() else ""
            if secret is not None and asked and time.time() - last >= QUIET and PASSWORD_PROMPT.search(asked):
                if secret_used:
                    os.kill(pid, signal.SIGTERM)
                    return 5, transcript + "\n[portal] the password was refused: stopped"
                os.write(fd, (secret + "\n").encode())
                transcript += "\n[portal] password typed\n"
                secret_used, pending, last = True, "", time.time()
                continue
            question_text = asked
            if question_text and time.time() - last >= QUIET and question.search(question_text):
                reply = answer(question_text)
                if reply is None:
                    os.kill(pid, signal.SIGTERM)
                    return 6, transcript + f"\n[portal] unknown question, stopped without answering: {question_text}"
                os.write(fd, (reply + "\n").encode())
                transcript += f"\n[portal] answered {reply or '(the proposed value)'} to: {question_text}\n"
                pending, last = "", time.time()
    finally:
        try:
            os.close(fd)
        except OSError:
            pass
    if rc is None:
        _, status = os.waitpid(pid, 0)
        rc = os.WEXITSTATUS(status) if os.WIFEXITED(status) else 1
    return rc, transcript


def scp(src, dest, port, secret):
    """scp with the password typed once; again with the old protocol (-O) for a VyOS without SFTP."""
    base = [SCP, "-o", "StrictHostKeyChecking=accept-new", "-o", "PubkeyAuthentication=no", "-o", "NumberOfPasswordPrompts=1",
            "-o", "PreferredAuthentications=password,keyboard-interactive", "-o", "ConnectTimeout=15", "-P", port]
    rc, text = drive(base + [src, dest], no_answer, secret=secret)
    if rc not in (0, 5, 6) or (rc != 0 and re.search(r"subsystem|sftp", text, re.I)):   # an old VyOS without SFTP
        rc, more = drive(base + ["-O", src, dest], no_answer, secret=secret)
        text += "\n[portal] again with the old scp protocol (-O)\n" + more
    return rc, text


def main(argv):
    if len(argv) == 2 and argv[0] == "install" and re.match(r"^/(tmp|home/[A-Za-z0-9_.-]{1,32})/[A-Za-z0-9_.-]+\.iso$", argv[1]):
        if not os.path.isfile(argv[1]):
            say(f"RESULT failed: {argv[1]} is not on the VyOS")
            return 5
        rc, text = drive([WRAPPER, "add", "system", "image", argv[1]], yes_or_default)
    elif len(argv) == 2 and argv[0] == "default-boot" and re.match(r"^[A-Za-z0-9_.+-]{1,80}$", argv[1]):
        rc, text = drive([WRAPPER, "set", "system", "image", "default-boot", argv[1]], yes_or_default)
    elif (len(argv) in (4, 5) and argv[0] == "copy" and re.match(r"^/[A-Za-z0-9_./-]+\.iso$", argv[1])
          and re.match(r"^[A-Za-z0-9_.-]{1,32}@[A-Za-z0-9_.:-]+$", argv[2]) and argv[3].isdigit()
          and re.match(r"^/(tmp|home/[A-Za-z0-9_.-]{1,32})$", (argv + ["/tmp"])[4])):
        secret = sys.stdin.readline().rstrip("\n")
        if not secret:
            say("RESULT failed: no password on stdin")
            return 5
        dest = f"{argv[2]}:{(argv + ['/tmp'])[4]}/{os.path.basename(argv[1])}"
        rc, text = scp(argv[1], dest, argv[3], secret)
    elif (len(argv) == 4 and argv[0] == "fetch" and re.match(r"^[A-Za-z0-9_.-]{1,32}@[A-Za-z0-9_.:-]+$", argv[1])
          and argv[2].isdigit() and re.match(r"^/[A-Za-z0-9_./-]+$", argv[3]) and ".." not in argv[3]):
        secret = sys.stdin.readline().rstrip("\n")
        if not secret:
            say("RESULT failed: no password on stdin")
            return 5
        rc, text = scp(f"{argv[1]}:/config/config.boot", argv[3], argv[2], secret)
    else:
        say("usage: wi_vyos.py install <folder>/<image>.iso | default-boot <image name> | copy <iso> <user>@<host> <port> [folder]"
            " | fetch <user>@<host> <port> <file>")
        return 5
    say(text)
    if rc in (5, 6):
        say(f"RESULT {'failed' if rc == 5 else 'attention'}: {text.strip().splitlines()[-1] if text.strip() else 'stopped'}")
        return rc
    # judged by the exit code; the playbook then checks show system image (a "signature check failed" line is normal
    # for a local ISO: its sha256 was compared with the jump host's)
    say("RESULT " + (f"attention: the command ended with exit {rc} (see above)" if rc != 0 else "ok"))
    return 6 if rc != 0 else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
