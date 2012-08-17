CC = gcc
CFLAGS = -m64
OPTFLAGS = -O3 
SRCFILES = mef_lib.c
INCLUDE = .
LF = -lm

read: #build read header
	$(CC) -o show_mef_header $(CFLAGS) $(OPTFLAGS) read_mef_header.c $(SRCFILES) -I $(INCLUDE) $(LF)

check: #build mef file check program
	$(CC) -o check_mef $(CFLAGS) $(OPTFLAGS) check_mef.c $(SRCFILES) -I $(INCLUDE) $(LF)

anon:
	$(CC) -o anon_mef $(CFLAGS) $(OPTFLAGS) anon_mef.c $(SRCFILES) -I $(INCLUDE) $(LF)

m2r: #build mef2raw32
	$(CC) -o mef2raw $(CFLAGS) $(OPTFLAGS) mef2raw32.c $(SRCFILES) -I $(INCLUDE) $(LF)

all:  read check anon m2r  


