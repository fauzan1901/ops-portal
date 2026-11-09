#!/usr/bin/env bash
# Runs on this Mac. push: copies the read-only ACI access policy dump to the bastion (~/aci-access-dump/).
# fetch: brings ~/aci-access-dump/out.tar.gz back to aci-access-dump-results/<time>/ next to tools/.
# You type the SSH password once (or an open connection is reused); nothing is stored.
#   bash tools/aci-access-dump/transfer.sh push
#   (on the bastion)  sudo bash ~/aci-access-dump/aci-access-dump.sh
#   bash tools/aci-access-dump/transfer.sh fetch
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
ROOT="$(cd "$HERE/../.." && pwd)"
SSH=(ssh -o ControlMaster=auto -o ControlPath=/tmp/aci-cm-%C -o ControlPersist=1800 -p 2222 deploy@172.26.0.100)
case "${1:-}" in
  push)
    tar -czf - -C "$HERE" aci_access_dump.py portal_credential.py aci-access-dump.sh README.md \
      | "${SSH[@]}" "mkdir -p ~/aci-access-dump && tar -xzf - -C ~/aci-access-dump && sed -i 's/\r\$//' ~/aci-access-dump/*.sh \
          && echo 'Copied to ~/aci-access-dump. On the bastion: sudo bash ~/aci-access-dump/aci-access-dump.sh'"
    ;;
  fetch)
    dest="$ROOT/aci-access-dump-results/$(date +%Y%m%d-%H%M%S)"
    mkdir -p "$dest"
    "${SSH[@]}" "cat ~/aci-access-dump/out.tar.gz" > "$dest/out.tar.gz"
    tar -xzf "$dest/out.tar.gz" -C "$dest"
    echo "Fetched to $dest:"
    ls "$dest"
    ;;
  *)
    echo "Usage: $0 push|fetch" >&2
    exit 1
    ;;
esac
