CC=gcc
DEBUG_FLAGS=-g 
CFLAGS=-MMD -MP -Wno-deprecated-declarations

SRC=$(wildcard *.c)
OBJ=$(patsubst %.c,obj/%.o,$(SRC))
DEPS=$(OBJS:.o=.d)
INCLUDES_FLAGS=-I ../

# main rules here
all: ${OBJ}

obj/%.o: %.c 
	${CC} ${DEBUG_FLAGS} ${CFLAGS} ${INCLUDES_FLAGS} -c $< -o $@ 

clean: 
	rm -rf obj/*

-include $(DEP)

.PHONY:clean



