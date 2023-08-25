xodump: helper.o inject.o xodump.o
	cc helper.o inject.o xodump.o -o xodump

helper.o: helper.c helper.h xodump.h
	cc -c -Wall helper.c -o helper.o

inject.o: inject.c inject.h helper.h xodump.h
	cc -c -Wall inject.c -o inject.o

xodump.o: xodump.c xodump.h helper.h inject.h
	cc -c -Wall xodump.c -o xodump.o
