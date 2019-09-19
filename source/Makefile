include ../Makefile.in

EXECFILES = \
	aes-128-cbc

AES_OBJS = \
	aes-128-cbc.o

.PHONY: all

all: aes-128-cbc

.PHONY: aes-128-cbc

aes-128-cbc: $(AES_OBJS)
	$(CC) $(AES_OBJS) $(CFLAGS) $(LDFLAGS) $(LIBS) -o $@

%.o: %.c
	$(CC) -c $< $(CFLAGS) $(LDFLAGS) $(LIBS) -o $@

.PHONY: strip

strip:
	$(STRIP) $(EXECFILES)

.PHONY: libs

libs:

.PHONY: install

install:
	$(shell echo $(DESTDIR) > .install)
	install -d ${DESTDIR}/usr/local/sbin
	install -m 755 $(EXECFILES) $(DESTDIR)/usr/local/sbin

.PHONY: uninstall

uninstall:
	$(eval DESTDIR := $(shell cat .install))
	@for f in $(EXECFILES); \
	do \
		rm -f $(DESTDIR)/usr/local/sbin/$$f; \
	done

.PHONY: clean

clean:
	rm -f $(EXECFILES) $(AES_OBJS)
