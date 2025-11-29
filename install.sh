SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

while true; do
    read -p "Will you be using Checksum-Sentinel as a persistent daemon? " daemon
    case "$daemon" in
        [Yy]* ) daemon="y"; break;;
        [Nn]* ) daemon="n"; break;;
        * ) echo "Please answer y or n.";;
    esac
done

sudo pip install .
cargo build --release
sudo mv "$SCRIPT_DIR"/target/release/css /usr/local/bin/css
sudo restorecon /usr/local/bin/css
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
sudo restorecon -v /etc/systemd/system/css*.service /etc/systemd/system/css*.timer
sudo systemctl daemon-reload
sudo systemctl enable --now css-update-persistent.timer
sudo systemctl enable --now css-update-recent.timer
if [ "$daemon" = "y" ]; then
    sudo systemctl enable --now css.service
fi
