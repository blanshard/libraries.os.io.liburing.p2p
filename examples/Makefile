CPPFLAGS ?=
override CPPFLAGS += -D_GNU_SOURCE -I../src/include/
CFLAGS ?= -g -O2 -Wall
LDFLAGS ?=
override LDFLAGS += -L../src/ -luring

include ../Makefile.quiet

ifneq ($(MAKECMDGOALS),clean)
include ../config-host.mak
endif

example_srcs := \
	io_uring-cp.c \
	io_uring-test.c \
	link-cp.c \
	dma-buf-example.c

all_targets :=


ifdef CONFIG_HAVE_UCONTEXT
	example_srcs += ucontext-cp.c
endif
all_targets += ucontext-cp

example_targets := $(patsubst %.c,%,$(patsubst %.cc,%,$(example_srcs)))
all_targets += $(example_targets)


all: $(example_targets)

%: %.c
	$(QUIET_CC)$(CC) $(CPPFLAGS) $(CFLAGS) -o $@ $< $(LDFLAGS)

clean:
	@rm -f $(all_targets)

.PHONY: all clean
