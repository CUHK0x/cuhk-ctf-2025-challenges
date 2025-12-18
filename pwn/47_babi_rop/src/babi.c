/**********************************
*
*  An intentionally vulnerable Linux kernel module for CUHK CTF 2025
*
***********************************/

#include <linux/init.h>
#include <linux/module.h>
#include <linux/fs.h>
#include <linux/device.h>
#include <linux/cdev.h>
#include <linux/slab.h>
#include <linux/ioctl.h>

#include <asm/uaccess.h>

#define DEVICE_NAME "babi"
#define DEVICE_CLASS_NAME "babi_dev"

// define commands
#define IOCTL_BASE 'W'
#define	CMD_READ		_IO(IOCTL_BASE, 0)
#define	CMD_WRITE		_IO(IOCTL_BASE, 1)

/***************************************
 *
 * structs and global variables
 *
 ***************************************/

/* global variables */
static struct class *babi_class;
static int major_num;
static struct file_operations file_ops;

/***************************************
 *
 * device driver code
 *
 ***************************************/

typedef struct request {
	void*	ubuf;
	size_t	size;
} request_t;

static int babi_open(struct inode *inode, struct file *file)
{
	printk(KERN_INFO "device is opened\n");
	return 0;
}

static int babi_release(struct inode *inode, struct file *file)
{
	printk(KERN_INFO "device is closed\n");
	return 0;
}

static long babi_ioctl(struct file *file, unsigned int cmd, unsigned long arg)
{
	char buf[0x10] = {0};
	request_t req;

	printk(KERN_INFO "babi_ioctl called with cmd: %d, arg: 0x%lx\n", cmd, arg);

	if (copy_from_user(&req, (void*)arg, sizeof(request_t)))
		return -EINVAL;

	if(cmd == CMD_READ) {
		return __arch_copy_to_user(req.ubuf, buf, req.size);
	} else if (cmd == CMD_WRITE) {
		return __arch_copy_from_user(buf, req.ubuf, req.size);
	} else {
		return -EINVAL;
	}
}

static struct file_operations file_ops = { 
	.unlocked_ioctl = babi_ioctl,
	.open = babi_open,
	.release = babi_release
};

/***************************************
 * 
 * kernel module related code
 *
 **************************************/
MODULE_LICENSE("GPL");
MODULE_AUTHOR("Kyle Zeng; zengyhkyle@gmail.com");
MODULE_DESCRIPTION("An kernel module for CUHK CTF 2025");
MODULE_VERSION("0.01");

static int __init babi_init(void)
{
	printk(KERN_INFO "module initialization\n");

	// this registers 0x100 minor numbers
	major_num = register_chrdev(0, DEVICE_NAME, &file_ops);
	if(major_num < 0) {
		printk(KERN_WARNING "Fail to get major number");
		return -EINVAL;
	}

	/* populate a device node */
	babi_class = class_create(DEVICE_CLASS_NAME);
	device_create(babi_class, NULL, MKDEV(major_num, 0), NULL, DEVICE_NAME);

	return 0;
}

static void __exit babi_exit(void)
{
	printk(KERN_INFO "module destruction\n");

	// destory the device node first
	device_destroy(babi_class, MKDEV(major_num, 0));

	// destroy the device class
	class_destroy(babi_class);

	// unregister chrdev
	unregister_chrdev(major_num, DEVICE_NAME);
}

module_init(babi_init);
module_exit(babi_exit);