include algo/Makefile
include common/Makefile
include log/Makefile
include secure/Makefile

SUBDIRS=algo common log secure
CURRENT_DIR := $(CURDIR)
BINS=bin

SRCS=$(wildcard *.c)
OBJS := $(patsubst ./common/%.c,./common/obj/%.o,$(wildcard ./common/*.c)) \
		$(patsubst ./algo/%.c,./algo/obj/%.o,$(wildcard ./algo/*.c))	\
        $(patsubst ./secure/%.c,./secure/obj/%.o,$(wildcard ./secure/*.c))	\
        $(patsubst ./log/%.c,./log/obj/%.o,$(wildcard ./log/*.c))	

OBJS_CURRENT=$(patsubst %.c,obj/%.o,$(SRC))
DEPS=$(OBJS:.o=.d) 	
LDFLAGS=-lcrypto -lz -lpam -lpam_misc -lssl -ldl -lrt -L/usr/lib/x86_64-linux-gnu/

# main rules here
define make_subdirs
	   	@for dir in $(SUBDIRS); do \
       		$(MAKE) -C $$dir; \
   		done
endef

obj/%.o:%.c
	${CC} ${DEBUG_FLAGS} ${CFLAGS} -I $(CURRENT_DIR)  -c $< -o $@ ${LDFLAGS}

.PHONY: all

all: ftpclient ftpserver ftpkeygen

ftpclient: $(OBJS_CURRENT)
	@$(call make_subdirs)
	${CC} ${DEBUG_FLAGS} ${CFLAGS} -o ${BINS}/$@  $(OBJS) obj/control.o obj/data.o obj/client.o obj/cmd.o ${LDFLAGS}

ftpserver: $(OBJS_CURRENT)
	@$(call make_subdirs)
	${CC} ${DEBUG_FLAGS} ${CFLAGS} -o ${BINS}/$@ $(OBJS) obj/control.o obj/data.o obj/server.o obj/cmd.o ${LDFLAGS}

ftpkeygen: $(OBJS_CURRENT)
	@$(call make_subdirs)
	${CC} ${DEBUG_FLAGS} ${CFLAGS} -o ${BINS}/$@ $(OBJS) obj/keygen.o ${LDFLAGS}

cleanall: 
	rm -rf obj/* bin/*
	rm -rf ${OBJS}

install:
	chmod 755 bin/* && sudo mv bin/* /usr/bin/
	chmod 755 ../script/* && sudo cp ../script/ftp* /usr/bin;
	chmod 644 ../script/sftp.pam && sudo cp ../script/sftp.pam /etc/pam.d/sftp

-include $(DEPS)

.PHONY:cleanall



