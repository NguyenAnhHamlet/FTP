CC=gcc
DEBUG_FLAGS=-g
CFLAGS=-MMD -MP

SRC=$(wildcard *.c)
OBJ=$(patsubst %.c,obj/%.o,$(SRC))
DEPS=$(OBJS:.o=.d)
INCLUDES_FLAGS=-I ../

# create a storage
define storage_create
	for dir in $(1); do \
		if [ ! -d $$dir ]; then	\
			mkdir $$dir && chmod 755 $$dir;	\
		fi	\
	done
endef

# main rules here
all: create_dirs ${OBJ}

create_dirs:
	$(call storage_create,obj)

obj/%.o: %.c 
	${CC} ${DEBUG_FLAGS} ${CFLAGS} ${INCLUDES_FLAGS} -c $< -o $@ 

clean: 
	rm -rf obj

-include $(DEP)

.PHONY:clean



