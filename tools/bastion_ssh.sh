# Sourced by the tools that copy files to the bastion (deploy_portal.sh, deploy_portals.sh, push_portal_proxy.sh,
# aci-access-dump/transfer.sh). bastion_connect sets SSH to the first account that can sign in: deploy@172.26.32.100, else
# syw@172.26.32.100. An open ControlMaster connection of an account is reused; otherwise you type its password.
# Other accounts or order: BASTION_ACCOUNTS="syw@172.26.32.100 deploy@172.26.32.100" bash tools/deploy_portal.sh
# Port: BASTION_PORT (default 2222).
bastion_connect() {
  local persist="${1:-1800}" dest
  local -a opts=(-o ControlMaster=auto -o ControlPath=/tmp/ops-cm-%C -o ControlPersist="$persist" -p "${BASTION_PORT:-2222}")
  local -a accounts
  read -r -a accounts <<< "${BASTION_ACCOUNTS:-deploy@172.26.32.100 syw@172.26.32.100}"
  for dest in "${accounts[@]}"; do
    echo "== SSH to the bastion as $dest" >&2
    if ssh "${opts[@]}" -o ConnectTimeout=15 "$dest" true; then
      SSH=(ssh "${opts[@]}" "$dest")
      BASTION_DEST="$dest"
      return 0
    fi
    echo "   SSH as $dest failed, trying the next account" >&2
  done
  echo "== SSH to the bastion failed for every account: ${accounts[*]}" >&2
  return 1
}
