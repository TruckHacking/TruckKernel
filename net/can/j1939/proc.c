/*
 * Copyright (c) 2010-2011 EIA Electronics
 *
 * Authors:
 * Kurt Van Dijck <kurt.van.dijck@eia.be>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the version 2 of the GNU General Public License
 * as published by the Free Software Foundation
 */

#include <linux/version.h>
#include <linux/string.h>
#include <linux/seq_file.h>
#include <linux/proc_fs.h>
#include <linux/uaccess.h>

#include "j1939-priv.h"

const char j1939_procname[] = "can-j1939";

static struct proc_dir_entry *rootdir;

static int j1939_proc_open(struct inode *inode, struct file *file)
{
	struct proc_dir_entry *pde = PDE(inode);
	int (*fn)(struct seq_file *sqf, void *v) = pde->data;

	return single_open(file, fn, pde);
}

/* copied from fs/proc/generic.c */
static ssize_t
proc_file_write(struct file *file, const char __user *buffer,
		size_t count, loff_t *ppos)
{
	struct inode *inode = file->f_path.dentry->d_inode;
	struct proc_dir_entry *dp;

	dp = PDE(inode);

	if (!dp->write_proc)
		return -EIO;

	/* FIXME: does this routine need ppos?  probably... */
	return dp->write_proc(file, buffer, count, dp->data);
}

static const struct file_operations j1939_proc_ops = {
	.owner		= THIS_MODULE,
	.open		= j1939_proc_open,
	.read		= seq_read,
	.write		= proc_file_write,
	.llseek		= seq_lseek,
	.release	= single_release,
};

int j1939_proc_add(const char *file,
		int (*seq_show)(struct seq_file *sqf, void *v),
		write_proc_t write)
{
	struct proc_dir_entry *pde;
	int mode = 0;

	if (seq_show)
		mode |= 0444;
	if (write)
		mode |= 0200;

	if (!rootdir)
		return -ENODEV;
	pde = proc_create(file, mode, rootdir, &j1939_proc_ops);
	if (!pde)
		goto fail_create;
	pde->data = seq_show;
	pde->write_proc = write;
	return 0;

fail_create:
	return -ENOENT;
}
EXPORT_SYMBOL(j1939_proc_add);

void j1939_proc_remove(const char *file)
{
	remove_proc_entry(file, rootdir);
}
EXPORT_SYMBOL(j1939_proc_remove);

__init int j1939_proc_module_init(void)
{
	/* create /proc/net/can directory */
	rootdir = proc_mkdir(j1939_procname, init_net.proc_net);
	if (!rootdir)
		return -EINVAL;
	return 0;
}

void j1939_proc_module_exit(void)
{
	if (rootdir)
		proc_net_remove(&init_net, j1939_procname);
}

