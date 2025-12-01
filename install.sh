#!/bin/bash
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
while true; do
    read -p "Will you be using Checksum-Sentinel as a persistent daemon? " daemon
    case "$daemon" in
        [Yy]* ) daemon="y"; break;;
        [Nn]* ) daemon="n"; break;;
        * ) echo "Please answer y or n.";;
    esac
done
cargo build --release || { echo "Build failed"; exit 1; }
systemctl is-active --quiet css.service && sudo systemctl stop css.service
systemctl is-active --quiet css-update-persistent.timer && sudo systemctl stop css-update-persistent.timer
systemctl is-active --quiet css-update-recent.timer && sudo systemctl stop css-update-recent.timer
systemctl is-active --quiet css-update-persistent.service && sudo systemctl stop css-update-persistent.service
systemctl is-active --quiet css-update-recent.service && sudo systemctl stop css-update-recent.service
[ -f /usr/local/bin/css ] && sudo rm /usr/local/bin/css
sudo mv "$SCRIPT_DIR"/target/release/css /usr/local/bin/css
if [ "$(getenforce)" = "Enforcing" ]; then
    sudo restorecon /usr/local/bin/css
fi
[ -f /etc/systemd/system/css.service ] && sudo rm /etc/systemd/system/css.service
[ -f /etc/systemd/system/css-update-persistent.service ] && sudo rm /etc/systemd/system/css-update-persistent.service
[ -f /etc/systemd/system/css-update-recent.service ] && sudo rm /etc/systemd/system/css-update-recent.service
[ -f /etc/systemd/system/css-update-persistent.timer ] && sudo rm /etc/systemd/system/css-update-persistent.timer
[ -f /etc/systemd/system/css-update-recent.timer ] && sudo rm /etc/systemd/system/css-update-recent.timer
if [ "$daemon" = "y" ]; then
    USERNAME=$(whoami)
    sudo sed -i "s/^User=.*/User=$USERNAME/" "$SCRIPT_DIR"/systemd/css.service
    sudo cp "$SCRIPT_DIR"/systemd/css.service /etc/systemd/system/css.service
    sudo cp "$SCRIPT_DIR"/systemd/css-update-persistent.service /etc/systemd/system/css-update-persistent.service
    sudo cp "$SCRIPT_DIR"/systemd/css-update-recent.service /etc/systemd/system/css-update-recent.service
else
    sudo cp "$SCRIPT_DIR"/systemd/no-daemon/css-update-persistent.service /etc/systemd/system/css-update-persistent.service
    sudo cp "$SCRIPT_DIR"/systemd/no-daemon/css-update-recent.service /etc/systemd/system/css-update-recent.service
fi
sudo cp "$SCRIPT_DIR"/systemd/css-update-persistent.timer /etc/systemd/system/css-update-persistent.timer
sudo cp "$SCRIPT_DIR"/systemd/css-update-recent.timer /etc/systemd/system/css-update-recent.timer
if [ "$(getenforce)" = "Enforcing" ]; then
    sudo restorecon -v /etc/systemd/system/css*.service /etc/systemd/system/css*.timer
fi
sudo systemctl daemon-reload
sudo systemctl enable --now css-update-persistent.timer
sudo systemctl enable --now css-update-recent.timer
if [ "$daemon" = "y" ]; then
    sudo systemctl enable --now css.service
fi
