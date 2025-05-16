include algo/Makefile
include common/Makefile
include log/Makefile
include secure/Makefile

SUBDIRS=algo common log secure
CURRENT_DIR := $(CURDIR)
BINS=./bin
DESTDIR ?=  
TARBALL= rhel/sftp-1.0.0.tar.gz

SRCS=$(wildcard *.c)
OBJS := $(patsubst ./common/%.c,./common/obj/%.o,$(wildcard ./common/*.c)) \
		$(patsubst ./algo/%.c,./algo/obj/%.o,$(wildcard ./algo/*.c))	\
        $(patsubst ./secure/%.c,./secure/obj/%.o,$(wildcard ./secure/*.c))	\
        $(patsubst ./log/%.c,./log/obj/%.o,$(wildcard ./log/*.c))	

OBJS_CURRENT=$(patsubst %.c,obj/%.o,$(SRC))
DEPS=$(OBJS:.o=.d) 

openssl := $(shell openssl version | cut -d ' ' -f2 | cut -d '.' -f1 )
OPENSSL_FLAG := $(if $(filter 3,$(openssl)), -DOPENSSL_3, -DOPENSSL_1)

LDFLAGS=-lcrypto -lz -lpam -lpam_misc -lssl -ldl -lrt -L/usr/lib/x86_64-linux-gnu/ -lreadline

# main rules here
define make_subdirs
	   	@for dir in $(SUBDIRS); do \
       		$(MAKE) -C $$dir; \
   		done
endef

obj/%.o:%.c
	${CC} ${DEBUG_FLAGS} ${CFLAGS} -I $(CURRENT_DIR)  -c $< -o $@ ${LDFLAGS} ${OPENSSL_FLAG}

.PHONY: all

all: ftpclient ftpserver ftpkeygen

ftpclient: $(OBJS_CURRENT)
	@$(call make_subdirs)
	${CC} ${DEBUG_FLAGS} ${CFLAGS} -o ${BINS}/$@  $(OBJS) obj/control.o obj/data.o obj/client.o obj/cmd.o obj/datab.o ${LDFLAGS} ${OPENSSL_FLAG}

ftpserver: $(OBJS_CURRENT)
	@$(call make_subdirs)
	${CC} ${DEBUG_FLAGS} ${CFLAGS} -o ${BINS}/$@ $(OBJS) obj/control.o obj/data.o obj/server.o obj/cmd.o obj/datab.o ${LDFLAGS} ${OPENSSL_FLAG}

ftpkeygen: $(OBJS_CURRENT)
	@$(call make_subdirs)
	${CC} ${DEBUG_FLAGS} ${CFLAGS} -o ${BINS}/$@ $(OBJS) obj/keygen.o ${LDFLAGS} ${OPENSSL_FLAG}

cleanall: 
	rm -rf obj/* bin/*
	rm -rf ${OBJS}

install:
	chmod 755 ${BINS}/* && sudo mv bin/* ${DESTDIR}/usr/bin/
	chmod 644 script/sftp.pam && sudo cp script/sftp.pam ${DESTDIR}/etc/pam.d/sftp
	chmod 644 script/*config && sudo cp script/*config ${DESTDIR}/etc/ftp/

compress: 
	@if [ ! -f ${TARBALL} ]; then 	\
		cp -r ../src ../rhel/sftp-1.0.0; \
		cd ../rhel;	\
		tar -czf sftp-1.0.0.tar.gz sftp-1.0.0; \
		rm -rf sftp-1.0.0; \
		echo "Creating TARBALL rhel/sftp-1.0.0.tar.gz"; \
	fi

rhel: 
	# prepare the environment for building rpm package for rhel platform 
	sudo mkdir -p ~/rpmbuild/{SOURCES,SPECS,RPMS,SRPMS,BUILD}
	sudo cp ../rhel/*.spec ~/rpmbuild/SPECS
	sudo cp ../rhel/sftp-[0-9]*.tar.gz ~/rpmbuild/SOURCES  
	# Start to build the rpm package
	sudo rpmbuild --define "_topdir ${HOME}/rpmbuild" -ba ~/rpmbuild/SPECS/sftp.spec

-include $(DEPS)

.PHONY:cleanall



