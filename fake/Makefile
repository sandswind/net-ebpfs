src := $(HOME)/linux

DEBUGBPF = -DDEBUG
DEBUGFLAGS = -O0 -g -Wall
PFLAGS = $(DEBUGFLAGS)

INCLUDEFLAGS = -I$(src)/usr/include \
	       -I$(src)/include \
	       -I$(src)/tools/testing/selftests/bpf

kfiles = net_fake_kern.o

HOSTCFLAGS += $(INCLUDEFLAGS) $(PFLAGS)
HOSTCFLAGS_bpf_load.o += $(INCLUDEFLAGS) $(PFLAGS) -Wno-unused-variable


# Allows pointing LLC/CLANG to a LLVM backend with bpf support, redefine on cmdline:
#  make samples/bpf/ LLC=~/git/llvm/build/bin/llc CLANG=~/git/llvm/build/bin/clang
LLC ?= llc
CLANG ?= clang

# Trick to allow make to be run from this directory
all: $(kfiles)
	echo "bpfs done"
	
clean:
	@rm -f *.o

%.o: %.c
	$(CLANG) $(INCLUDEFLAGS) $(EXTRA_CFLAGS) \
	$(DEBUGBPF) -D__KERNEL__ -Wno-unused-value -Wno-pointer-sign \
		-Wno-compare-distinct-pointer-types \
		-O2 -emit-llvm -c -g $< -o -| $(LLC) -march=bpf -filetype=obj -o $@

