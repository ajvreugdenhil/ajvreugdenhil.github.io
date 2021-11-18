---
layout: post
title: Poking the beast
categories: LKM
published: true
---

This post describes the peek/poke driver for the Zybo Z7-10. A peek/poke driver may be used to write to addresses that can be accessed from kernel space but not from user space. It serves as a good introductory project for making kernel modules.

## Talking to our driver

The first thing to worry about for making this driver is how we'll be talking to it. In this case, using sysfs makes more sense over devfs because we'll always be dealing with small bits of data.

Because we will be needing to read and write to memory, we'll need to specify the operation in the message. For reading memory we'll need to specify an address to read from, and we may also specify how many words to read. For the writing operation, we'll need to specify an address and a value. With our current architecture, these all need to be a `u32`. We will be sending the result of the read operation to the user via printk. This is not acceptable for serious drivers, but it more than suffices for our use case.

To process the users input we can easily use sscanf as follows.

```c
chars_read = sscanf(buffer, "%c %li %li", &operation, &location, &arg2);
```

Of course, we mustn't forget to check the validity of all parameters. If they are not as expected, we can return -E

## Oh no

If we let ourselves be inspired by the lkmpg and use the following snippet, we run into a wall.

```c
static DEVICE_ATTR(data, S_IWUGO | S_IRUGO, sysfs_show, sysfs_store);
```

This is because the permissions that `S_IWUGO | S_IRUGO` resolve to, are too broad. They may be no more permissive than `0664`. Keep in mind that these are octal values.

## Scratch scratch

In the enviroment we created, we don't have the luxury of using iowrite32 and io_p2v(). So we will have to use iomem. The following code allows us to read and write to an address.

```c
void __iomem *io_base = ioremap_nocache(location, 4);
if (operation == 'r')
{
    unsigned long value = readl(io_base);
    printk(KERN_INFO "read value  0x%lx from physical memory location 0x%lx\n", value, location);
}
else if (operation == 'w')
{
    writel(arg2, io_base);
    printk(KERN_INFO "wrote value 0x%lx   to physical memory location 0x%lx\n", arg2, location);
}
iounmap(io_base);
```

Of course, we also make sure that invalid code paths are handled correctly.

## The beast growls

Testing this module gives some interesting results. At first I tried setting one of the on board leds. These were not documented extensively but using the [reference guide](https://digilent.com/reference/programmable-logic/zybo-z7/reference-manual) I thought I had a reasonable grasp. I set all the right registers but nothing happened.

Reading from non-gpio registers seemed to work. One USB register has a version number, and this was read just fine by the driver.

Further debugging, it turned out that the issue lies in writing to the GPIO registers. This is because of the way the CPU and the FPGA interact. One has to set up the FPGA correctly before being able to use the GPIO.
