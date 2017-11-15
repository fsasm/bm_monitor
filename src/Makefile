# Makefile
# Author: Fabjan Sukalia <fsukalia@gmail.com>
# Date: 2017-11-15

.PHONY: all clean

all: libbmmonitor.so

CFLAGS=-O2 -shared -ldl -fPIC -Wall -Wextra -std=c99

clean:
	rm -f libwrapper.so

libbmmonitor.so: monitor.c
	$(CC) $(CFLAGS) -o $@ $^
