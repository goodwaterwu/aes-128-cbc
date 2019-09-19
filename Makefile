include Makefile.in

SUBDIRS = \
	./lib \
	./source

.PHONY: all

all:
	$(info compile packages)
	@for dir in $(SUBDIRS); \
	do \
		$(MAKE) -C $$dir; \
	done

.PHONY: strip

strip:
	$(info strip packages)
	@for dir in $(SUBDIRS); \
	do \
		$(MAKE) -C $$dir strip; \
	done

.PHONY: libs

libs:
	$(info make libraries)
	@for dir in $(SUBDIRS); \
	do \
		$(MAKE) -C $$dir libs; \
	done


.PHONY: install

install:
	$(info install packages)
	@for dir in $(SUBDIRS); \
	do \
		$(MAKE) -C $$dir install; \
	done

.PHONY: uninstall

uninstall:
	$(info uninstall packages)
	@for dir in $(SUBDIRS); \
	do \
		$(MAKE) -C $$dir uninstall; \
	done

.PHONY: clean

clean:
	$(info clean packages)
	@for dir in $(SUBDIRS); \
	do \
		$(MAKE) -C $$dir clean; \
	done
	@rm -rf $(INSTALLDIR)
