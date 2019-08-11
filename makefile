debug:=1

ifneq (,$(debug))
CFLAGS += -DDEBUG -g
endif

CC = gcc
CCFLAGS += -I. -Wall
LDFLAGS += -lpthread -ljansson -lcurl -L./argon2 -L./blake2

libraries_yo += $(wildcard argon2/*.c)
libraries_yo += $(wildcard blake2/*.c)
libraries_yo += $(wildcard vendor/*.c)

prog := $(notdir $(PWD))
$(prog): $(wildcard *.c) $(libraries_yo)
	$(CC) $(CFLAGS) -o $@  $(LDFLAGS) $^
%.o: %.c
alltests=$(subst .c,,$(wildcard *.c))
clean:
	rm -f *.o *.a *.out */*.o */*.a $(prog) $(addprefix test_,$(alltests))

tests: $(addprefix test/,$(alltests))
$(addprefix test/,$(alltests)):
ifneq ($@, test/aqua)
	$(CC) $(CCFLAGS) -DRUN_TEST -o test_$(notdir $@) $(LDFLAGS) $(notdir $@).c aqua.c
endif

