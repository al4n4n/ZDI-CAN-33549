# s3rig — SMB Direct PoC for ZDI-CAN-33549
# Author: al4n4n (Dadb0d)
CC      ?= gcc
CFLAGS  ?= -O2 -Wall -Wno-unused-variable
LDFLAGS  = -lrdmacm -libverbs -lpthread -lssl -lcrypto

all: s3rig

s3rig: s3rig.c
	$(CC) $(CFLAGS) -o $@ $< $(LDFLAGS)

clean:
	rm -f s3rig

.PHONY: all clean
