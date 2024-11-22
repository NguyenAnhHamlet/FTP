CC=gcc
DEBUG_FLAGS=-g -lpam
CFLAGS=-MMD -MP -lcrypto -lz -lpam

SRC=$(wildcard *.c)
ALGO_OBJS=$(patsubst %.c,obj/%.o,$(SRC))
ALGO_DEPS=$(ALGO_OBJS:.o=.d)
INC_ALGO_FLAGS=-I ../

# main rules here
all: ${ALGO_OBJS}

obj/%.o: %.c 
	${CC} ${DEBUG_FLAGS} ${CFLAGS} ${INC_ALGO_FLAGS} -c $< -o $@ 

clean: 
	rm -rf obj/*

-include $(ALGO_DEPS)

.PHONY:clean



