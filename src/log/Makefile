CC=gcc
DEBUG_FLAGS=-g 
CFLAGS=-MMD -MP -Wno-deprecated-declarations -lcrypto -lz -lpam

SRC=$(wildcard *.c)
LOG_OBJS=$(patsubst %.c,obj/%.o,$(SRC))
LOG_DEPS=$(LOG_OBJS:.o=.d)
INC_LOG_FLAGS=-I ../

# main rules here
all: ${LOG_OBJS}

obj/%.o: %.c 
	${CC} ${DEBUG_FLAGS} ${CFLAGS} ${INC_LOG_FLAGS} -c $< -o $@ 

# clean: 
# 	rm -rf obj/*

-include $(LOG_DEPS)

.PHONY:clean



