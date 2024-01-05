#!/bin/sh

sudo airmon-ng check kill
sudo ip link set wlan0 down
sudo iw dev wlan0 set type monitor
sudo ip link set wlan0 up
sudo iw dev wlan0 set channel 44 HT40+
sudo iw wlan0 set txpower fixed 3000
sudo service wpa_supplicant stop
sudo service networking stop
# sudo service network-manager stop
sudo service bluetooth stop
