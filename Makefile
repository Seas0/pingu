
-include config.mk

PINGU_VERSION := $(shell \
	if [ -d .git ]; then \
		git describe --long; \
	else \
		echo $(PACKAGE_VERSION); \
	fi)

export PINGU_VERSION

SUBDIRS := src

ifdef ENABLE_DOC
SUBDIRS += doc
endif

all: $(SUBDIRS)

$(SUBDIRS):
	$(MAKE) -C $@

install clean:
	for dir in $(SUBDIRS); do \
		$(MAKE) -C $$dir $@ || break; \
	done

check:
	$(MAKE) -C src check

check-integration: src
	python3 tests/integration.py

.PHONY: $(SUBDIRS) all install clean check check-integration
