# privsep
An implementation that utilize the privilege separated wpa_supplicant

## Introduction
Hostapd supports privilege separation mode. This make it possible to write our own implementation of wireless client without going through wpa_supplicant.
Please see the details in the secion `Privilege separation` in the [offical document](https://w1.fi/cgit/hostap/plain/wpa_supplicant/README).

## Features
This program allow users to send low-level management frames from CLI. Currently, only the following management frames are supported:
  * Authenticate
  * Associate
  
## How to run it
  1. First of all, you have to prepare the privilege separated daemon `wpa_priv` by adding `CONFIG_PRIVSEP=y` to build configuration.
  2. Disable native wap_supplicant in your linux distribution if any. (optional)
  3. Compile this programe and run it.
  
## Usage
### Authenitcate
```privsep -a -b <BSSID> -S <SSID> -d <DELAY> [-s]```
### Associate
```privsep -A -b <BSSID> -S <SSID> -d <DELAY> [-s]```
  
