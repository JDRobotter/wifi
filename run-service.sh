#!/usr/bin/env bash

d=$(dirname $0)
$d/run.py -o -n "orange" -n "SFR WiFi FON" -n "FreeWifi" -n "Bouygues Telecom Wi-Fi" -n "SFR WiFi Mobile" -a wlan0,wlan1,wlan2,wlan3,wlan4
