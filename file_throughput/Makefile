OBJS =
OBJS += main.o

DEF =
DEF += -O3
DEF += --std=c99
DEF += -I../
DEF += -D_LARGEFILE64_SOURCE
DEF += -D_GNU_SOURCE
DEF += -Wno-unused-result
DEF += -Wno-discarded-qualifiers

LIBS =
LIBS += -lpthread
LIBS += -lm

%.o: %.c
	gcc $(DEF) -c -o $@  $<

all: $(OBJS)
	gcc -o file_test  $(OBJS)  $(LIBS)

clean:
	rm -f $(OBJS)
	rm -f file_test 
