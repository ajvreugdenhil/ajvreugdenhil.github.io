---
layout: post
title: Dual printering Klipper
categories: Misc
published: true
last_modified_at: 2022-11-29
excerpt_separator: <!--more-->
---

Ever since installing Klipper+Fluidd on my printers I haven't looked back. However, even though the Pi-per-printer configuration is great for experimenting, I'd like one of the Pi's available for other purposes. There wasn't a lot of information out there on how to do this so here we are.

## Basic install

For this project I decided it was best to go with a fresh Raspberry OS install instead of using the premade Klipper image. Setting up the Pi is straightforward. I used the Raspberry Pi Imaging tool, wich lets you set the user, hostname and enable SSH. No further changes necessary.

After boot, I SSH'ed in and ran the following commands:

<!--more-->

```bash
sudo apt update
sudo apt upgrade
sudo apt install git
git clone https://github.com/th33xitus/kiauh.git
./kiauh/kiauh.sh
```

Using Kiauh, I installed Klipper first. The tools lets you easily create 2 instances instead of 1. I named both. When asked if the tool should add the user to the tty group, I selected yes.

Then installing Moonraker was simple as the default settings were fine. The same went for Fluidd.

## Basic setup

Now in Fluidd, we can simply make the following adjustments:

- `Settings` -> `printer name` set to a name that makes sense to you
- `manage` -> `add user` a new user with password
- Edit moonraker.conf:
  
```diff
[authorization]
+force_logins: True
-trusted_clients:
-	10.0.0.0/8
-	127.0.0.0/8
-	169.254.0.0/16
-	172.16.0.0/12
-	192.168.0.0/16
-	FE80::/10
-	::1/128
```

Then find the meatball menu and add an instance. I added printer.local:7126. Go through the exact same three steps as above.

Then reboot the Pi.

Finally, for both Pi's, update the printer.cfg and fluidd.cfg. You may need to edit moonraker.conf as well. Do not overwrite the Moonraker port with old settings.

### printer.cfg

``` diff
[virtual_sdcard]
-path: ~/gcode_files
+path: ~/anet_data/gcodes
```

### fluidd.cfg

``` diff
[virtual_sdcard]
-path: /home/arjan/gcode_files
+path: /home/arjan/anet_data/gcodes
```

## Printer picking problems

The last change that had to be made is the serial port. My Ender 3 V2 and Anet A8 Plus both connected to the Pi without Serial ID. This meant that running `ls /dev/serial/by-id/*` showed only one file. Using this is not possible. We need a unique descriptor for each of the printers.

We can achieve this with udev. Running `udevadm info -a -n /dev/ttyUSB2` gives a lot of details about the serial port and how it is connected. Depending on which hardware you're using, the numbers may not entirely line up with mine.

With this information we can write our own udev rules. Instead of relying on the serial ID that turned out to not be unique, we can use the physical location of the USB connection. Because our physical configuration will not change often, this is acceptable. I made a file in `/etc/udev/rules.d` named `98-printer.rules`. This contained the following:

```udev
ACTION=="add", ATTRS{product}=="USB Serial", ATTRS{devpath}=="1.1.3", SYMLINK+="printer_usb_1_3"
ACTION=="add", ATTRS{product}=="USB Serial", ATTRS{devpath}=="1.1.2", SYMLINK+="printer_usb_1_2"
ACTION=="add", ATTRS{product}=="USB Serial", ATTRS{devpath}=="1.2", SYMLINK+="printer_usb_2"
ACTION=="add", ATTRS{product}=="USB Serial", ATTRS{devpath}=="1.3", SYMLINK+="printer_usb_3"
```

Now each of the four physical ports on the Pi gets their own symlink in /dev/. This symlink can then be used in the `printer.cfg`.

## Further bodging shenanigans

Lastly, I wanted to have the system restart on plugging in. Details on how to achieve this are available but only on 1 printer systems. I achieved this goal by taking the following steps.

In both `printer.cfg` files, I changed `/dev/printer_usb_n_n` values to `/dev/printer_ender` and `/dev/printer_anet`. Then, I modified the printer.rules udev file to the following:

```udev
ACTION=="add", ATTRS{product}=="USB Serial", ATTRS{devpath}=="1.3", SYMLINK+="printer_anet", RUN+="/usr/bin/sudo -u arjan /bin/sh -c '/bin/echo RESTART > /home/arjan/anet_data/comms/klippy.serial'"
ACTION=="add", ATTRS{product}=="USB Serial", ATTRS{devpath}=="1.2", SYMLINK+="printer_ender", RUN+="/usr/bin/sudo -u arjan /bin/sh -c '/bin/echo RESTART > /home/arjan/ender_data/comms/klippy.serial'"
```

Of course you'll have to adjust your system username and symlinks to match your own.

Now when the printer is powered up, it automatically resets and Klippy connects automatically.
