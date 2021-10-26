---
layout: post
title: Intro to linux kernel module programming on the Zybo Z7-10
categories: LKM
published: true
---

This post describes my experience with first setting up my enviroment for working with the Zybo Z7-10.

## It's only a little scary

When originally drafting this post, this paragraph was titled "It's not that scary." And then I spent 4 days debugging the toolchain. But even though many things are different in kernel module land, it's just another little step up from programming for userspace in C.

## Getting set up

If you first venture out into embedded linux past Raspberries, you'll quickly run into Buildroot, Yocto and Zephyr. Each with their own strengths. For working with the Zybo board, we didn't have to make a choice. Xilinx provides a [Petalinux](http://www.xilinx.com/petalinux) demo which *should* be easy to set up. (subtle foreshadowing.) With Petalinux, we can simply build an image for the board and build applications and kernel modules.

To get us going, we make an Ubuntu 16.04.x VM and we install Petalinux and download the bsp. While Xilinx' [demo page](https://digilent.com/reference/programmable-logic/zybo-z7/demos/petalinux?redirect=1) suggests that 2017.4 is not the latest release, the latest release link (`https://github.com/Digilent/(Board)/releases/tag/(tag)`) doesn't go anywhere so we'll stick with 2017.4. Following their [guide on github](https://github.com/Digilent/Petalinux-Zybo-Z7-10/tree/v2017.4-1) we get most of the way there.

Building the image now gives us the error `WARNING: u-boot-xlnx-v2017.01-xilinx-v2017.4+gitAUTOINC+42deb242f9-r0 do_fetch: Failed to fetch URL git://github.com/digilent/u-boot-digilent.git;protocol=https;branch=master, attempting MIRRORS if available`. The repo seems to be fine, and picking the Petalinux built in u-boot or a different repo or different commit does not solve the issue. The solution for this can be found [here](https://forum.digilentinc.com/topic/22104-u-boot-digilent-fetching-error-building-petalinux-zybo-z7-20-bsp-project/). What we're doing is taking commit `42deb242f961ce317366566666cbbddfb198bc9f` from the official digilent u-boot repository and manually retrieving it. I have no explanation for why this is necessary. It has taken me days to get to this point so now I'll just take the win.

## Workflow

We can now simply follow Digilents [ug1144](https://www.xilinx.com/support/documentation/sw_manuals/xilinx2017_4/ug1144-petalinux-tools-reference-guide.pdf) to make a new module. This includes the following commands.

```bash
cd ~/Zybo-Z7-10/
source /opt/pkg/petalinux/settings.sh
petalinux-create -t modules --name <user-module-name> --enable
petalinux-build -c <user-module-name>
nano project-spec/meta-user/recipes-modules/helloworld/files/helloworld.c
upl <ip> <user-module-name> # eg upl 192.168.2.49 helloworld
```

upl is a custom bash function that scp's the .ko file. After building, the .ko file ends up in `~/Zybo-Z7-10/build/tmp/sysroots/plnx_arm/lib/modules/4.9.0-xilinx-v2017.4/extra/`. Petalinux takes care of all the other build files.

Do not name your module `peekpoke`. There is presumably already a module with that name and the build process will fail silently. You'll bawl your eyes out before you figure that out.

The process of building the modules is still painfully slow compared to using the toolchain for the LPC3250 board. This is because there are a few steps in the module build process that are not cached. It might be possible to further optimize this process. To save a little extra time, we can use ssh to transfer over the .ko file. The prebuilt image includes dropbear. Credentials are root:root. Consider the security implications of this.

I've decided that I do not want to work inside the VM. So for the actual work I will be using a git repository on my main machine, mapped into the vm. For a new project, I will copy the template from Petalinux into the git folder and to build, I will be using an alias to copy from git into Petalinux, build, and upload.

```bash
cp -r project-spec/meta-user/recipes-modules/es6peekpoke/files/ /mnt/hgfs/es6git/es6peekpoke/

cp -r /mnt/hgfs/es6git/peekpoke/files/ project-spec/meta-user/recipes-modules/es6peekpoke/

petalinux-build -c es6peekpoke
```
