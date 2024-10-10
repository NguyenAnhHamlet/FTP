CC=gcc
DEBUG_FLAGS=-g
CFLAGS=-MMD -MP -Wno-deprecated-declarations 
LDFLAGS=-lcrypto -lz -lpam -lpam_misc -lssl -ldl -lrt -L/usr/lib/x86_64-linux-gnu/

SRC=$(wildcard *.c)
COMMON_OBJS=$(patsubst %.c,obj/%.o,$(SRC))
COMMON_DEPS=$(COMMON_OBJS:.o=.d)
INC_COMMON_FLAGS=-I ../

# main rules here
all: ${COMMON_OBJS}

obj/%.o: %.c 
	${CC} ${DEBUG_FLAGS} ${CFLAGS} ${INC_COMMON_FLAGS} -c $< -o $@ ${LDFLAGS} 

clean: 
	rm -rf obj/*

-include $(COMMON_DEPS)

.PHONY:clean