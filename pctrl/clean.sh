pgrep -fa mininet > /dev/null && sudo mn -c
sudo killall -q python || true
sudo killall -q exabgp || true
sudo fuser -k 6633/tcp || true
