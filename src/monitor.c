/*
 * monitor.c
 * Intercepts specific syscalls and writes them in a log file.
 * Author: Fabjan Sukalia <fsukalia@gmail.com>
 * Date: 2017-11-15
 * 
 * Copyright (C) 2017 Fabjan Sukalia
 * 
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 * 
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 * 
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
*/

#define _GNU_SOURCE
#include <unistd.h>
#include <dlfcn.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>

#include <linux/ioctl.h>

#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>

/* Function pointer to functions in libc */
int     (*orig_open)(const char *path, int oflag, ...)       = NULL;
int     (*orig_close)(int fd)                                = NULL;
ssize_t (*orig_write)(int fd, const void *buf, size_t count) = NULL;
ssize_t (*orig_read)(int fd, void *buf, size_t count)        = NULL;
int     (*orig_ioctl)(int fd, int request, ...)              = NULL;

static void *get_func(const char *fname)
{
	void *res = dlsym(RTLD_NEXT, fname);
	if (res == NULL) {
		fprintf(stderr, "dlsym(%s): %s", fname, dlerror());
		exit(EXIT_FAILURE);
	}

	return res;
}

int open(const char *path, int oflag, ...)
{
	va_list args;
	va_start(args, oflag);

	if (orig_open == NULL) {
		orig_open = get_func("open");
	}

	if ((oflag & O_CREAT) != 0) {
		mode_t mode = va_arg(args, int);
		va_end(args);
		printf("open(%s, %u, %i)\n", path, oflag, mode);
		return orig_open(path, oflag, mode);
	} else {
		printf("open(%s, %u)\n", path, oflag);
		va_end(args);
		return orig_open(path, oflag);
	}
}

int close(int fd)
{
	if (orig_close == NULL) {
		orig_close = get_func("close");
	}

	printf("close(%i)\n", fd);

	return orig_close(fd);
}

ssize_t write(int fd, const void *buf, size_t count)
{
	if (orig_write == NULL) {
		orig_write = get_func("write");
	}

	printf("write(%i, %lu, %zu)\n", fd, (long unsigned)buf, count);

	return orig_write(fd, buf, count);
}

ssize_t read(int fd, void *buf, size_t count)
{
	if (orig_read == NULL) {
		orig_read = get_func("read");
	}

	printf("read(%i, %lu, %zu)\n", fd, (long unsigned)buf, count);

	return orig_read(fd, buf, count);
}

int ioctl(int fd, int request, ...)
{
	va_list args;
	va_start(args, request);

	if (orig_ioctl == NULL) {
		orig_ioctl = get_func("ioctl");
	}

	int ioc_size = _IOC_SIZE(request);
	if (ioc_size != 0) {
		void *ptr = va_arg(args, void *);
		va_end(args);
		printf("ioctl(%i, %i, %p)\n", fd, request, ptr);
		return orig_ioctl(fd, request, ptr);
	} else {
		printf("ioctl(%i, %i)\n", fd, request);
		va_end(args);
		return orig_ioctl(fd, request);
	}
}

