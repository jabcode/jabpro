PREFIX 	=
CC 	= $(PREFIX)gcc
CFLAGS	 = -O2 -std=c11

TARGET = bin/jproEncoder

OBJECTS = $(patsubst %.c,%.o,$(wildcard *.c))

$(TARGET): $(OBJECTS)
	$(CC) $^ -L../jabpro/build -ljabpro -lm $(CFLAGS) -o $@

$(OBJECTS): %.o: %.c
	$(CC) -c -I. -I../jabpro -I../jabpro/include $(CFLAGS) $< -o $@

clean:
	rm -f $(TARGET) $(OBJECTS)