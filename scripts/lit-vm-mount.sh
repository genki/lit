#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat <<USAGE
Usage: ${0##*/} <command>

Commands:
  prepare   Install NFS server + lit workspace on the VM (requires SSH access).
  mount     Mount the VM workspace via NFS onto HOST_MOUNT (uses sudo mount).
  umount    Unmount HOST_MOUNT (uses sudo umount).
  stop      Run 'lit off' on the VM workspace and remove export.
  status    Show 'lit info' for the VM workspace.

Environment variables:
  VM_HOST        SSH host name (default: vagrant)
  VM_LIT_ROOT    Path to lit repo on VM (default: ~/lit)
  VM_WORKSPACE   Path to workspace to mount on VM (default: ~/lit/tmp/vm-workspace)
  HOST_MOUNT     Local mountpoint (default: ./tmp/vm-workspace)
  EXPORT_FILE    Remote exports file (default: /etc/exports.d/lit-vm.exports)
USAGE
}

if [[ ${1:-} == "--help" || ${1:-} == "-h" || $# -eq 0 ]]; then
  usage
  exit 0
fi

COMMAND=$1
shift || true

VM_HOST=${VM_HOST:-vagrant}
VM_LIT_ROOT=${VM_LIT_ROOT:-\~/lit}
VM_WORKSPACE=${VM_WORKSPACE:-\~/lit/tmp/vm-workspace}
HOST_MOUNT=${HOST_MOUNT:-$(pwd)/tmp/vm-workspace}
EXPORT_FILE=${EXPORT_FILE:-/etc/exports.d/lit-vm.exports}

rem_sh() {
  ssh "$VM_HOST" "$@"
}

ensure_remote_packages() {
  rem_sh "sudo apt-get update -qq && sudo apt-get install -y nfs-kernel-server"
}

configure_export() {
  local uid gid
  uid=$(rem_sh id -u)
  gid=$(rem_sh id -g)
  rem_sh "sudo mkdir -p ${EXPORT_FILE%/*}"
  rem_sh "printf '%s *(rw,sync,no_subtree_check,all_squash,anonuid=%s,anongid=%s)\\n' $VM_WORKSPACE $uid $gid | sudo tee $EXPORT_FILE > /dev/null"
  rem_sh "sudo exportfs -ra"
}

start_lit_workspace() {
  rem_sh "mkdir -p $VM_WORKSPACE"
  rem_sh "cd $VM_LIT_ROOT && . \$HOME/.cargo/env && (lit info $VM_WORKSPACE >/dev/null 2>&1 && lit off $VM_WORKSPACE || true) && lit on $VM_WORKSPACE"
}

stop_lit_workspace() {
  rem_sh "cd $VM_LIT_ROOT && . \$HOME/.cargo/env && (lit info $VM_WORKSPACE >/dev/null 2>&1 && lit off $VM_WORKSPACE || true)"
  rem_sh "sudo rm -f $EXPORT_FILE && sudo exportfs -ra"
}

host_mount() {
  sudo mkdir -p "$HOST_MOUNT"
  sudo mount -t nfs -o vers=4 "$VM_HOST:$VM_WORKSPACE" "$HOST_MOUNT"
}

host_umount() {
  if mount | grep -q "on $HOST_MOUNT"; then
    sudo umount "$HOST_MOUNT"
  fi
}

host_status() {
  rem_sh "cd $VM_LIT_ROOT && . \$HOME/.cargo/env && lit info $VM_WORKSPACE"
}

case "$COMMAND" in
  prepare)
    ensure_remote_packages
    start_lit_workspace
    configure_export
    ;;
  mount)
    host_mount
    ;;
  umount)
    host_umount
    ;;
  stop)
    host_umount || true
    stop_lit_workspace
    ;;
  status)
    host_status
    ;;
  *)
    usage
    exit 1
    ;;
esac
