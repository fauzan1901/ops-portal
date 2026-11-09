#!/usr/bin/env bash
# Demo only (DEMO_REAL_SHELL=1 ./test_mode.sh): the terminals of the Shell module open a real bash on this laptop instead
# of tests/fake_shell.py, to try line editing (Ctrl+R, arrows, Tab), vim, top and long output. The prompt names the demo
# host; nothing connects anywhere. Never used on the bastion (test mode only).
#   demo_bash.sh <host name> [user]
name="${1:-demo}"
user="${2:-user}"
export PS1="[$user@${name// /-} \\W]\\$ " HISTFILE=/dev/null BASH_SILENCE_DEPRECATION_WARNING=1
cd "${DEMO_SHELL_DIR:-${TMPDIR:-/tmp}}" || exit 1
exec bash --noprofile --norc -i
