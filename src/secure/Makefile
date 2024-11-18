CC=gcc
DEBUG_FLAGS=-g 
CFLAGS=-MMD -MP -Wno-deprecated-declarations 
LDFLAGS= -lcrypto -lz -lpam -lpam_misc -lssl -ldl -lrt -L/usr/lib/x86_64-linux-gnu/ 

SRC=$(wildcard *.c)
SECURE_OBJS=$(patsubst %.c,obj/%.o,$(SRC))
SECURE_DEPS=$(SECURE_OBJS:.o=.d)
INC_SECURE_FLAGS=-I ../

openssl := $(shell openssl version | cut -d ' ' -f2 | cut -d '.' -f1 )
OPENSSL_FLAG := $(if $(filter 3,$(openssl)), -DOPENSSL_3, -DOPENSSL_OLDER)

# main rules here
all: ${SECURE_OBJS}

obj/%.o: %.c 
	${CC} ${DEBUG_FLAGS} ${CFLAGS} ${INC_SECURE_FLAGS} -c $< -o $@ ${LDFLAGS} ${OPENSSL_FLAG}

clean: 
	rm -rf obj/*

-include $(SECURE_DEPS)

.PHONY:clean



