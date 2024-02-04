CC = gcc 

CFILES=$(wildcard *.c)
OBJ_FILES=$(patsubst %.c,%.o,${CFILES})
DEP_FILES=$(patsubst %.o,%.d,${CFILES})

CFLAGS=

%.o : %.c
	$(CC) -c -o $@ $< $(CFLAGS) 

main : $(OBJ_FILES)
	$(CC) -o send $^ $(CFLAGS)
