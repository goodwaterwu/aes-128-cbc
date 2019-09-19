include ../Makefile.in

LIBFILES = \
        libaes-128-cbc.a

AES_OBJS = \
        aes.o

.PHONY: all

all: aes

.PHONY: aes

aes: $(AES_OBJS) libs

%.o: %.c
	$(CC) -c $< $(CFLAGS) -o $@

.PHONY: strip

strip:
	$(STRIP) $(LIBFILES)

.PHONY: libs

libs:
	ar rcs $(LIBFILES) $(AES_OBJS)

.PHONY: install

install:
	$(shell echo $(DESTDIR) > .install)
	install -d ${DESTDIR}/usr/lib/aes-128-cbc/
	install -m 755 $(LIBFILES) $(DESTDIR)/usr/lib/aes-128-cbc

.PHONY: uninstall

uninstall:
	$(eval DESTDIR := $(shell cat .install))
	@for f in $(LIBFILES); \
	do \
		rm -f $(DESTDIR)/usr/lib/aes-128-cbc/$$f; \
	done

.PHONY: clean

clean: 
	rm -f $(LIBFILES) $(AES_OBJS)
