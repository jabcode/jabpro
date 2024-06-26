PREFIX 	=
CC 	= $(PREFIX)gcc
AR 	= $(PREFIX)ar
RANLIB	= $(PREFIX)ranlib
CFLAGS	= -O2 -std=c11

TARGET = build/libjabpro.a

OBJECTS := $(patsubst %.c,%.o,$(wildcard *.c))

$(TARGET): $(OBJECTS)
	$(AR) cr $@ $?
	$(RANLIB) $@

$(OBJECTS): %.o: %.c
	$(CC) -c -I. $(CFLAGS) $< -o $@

clean:
	rm -f $(TARGET) $(OBJECTS)
