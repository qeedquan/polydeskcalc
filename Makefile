CFLAGS=-Wall -Wextra -pedantic -fsanitize=address -g3 -ggdb -std=gnu11
LDFLAGS=-lm

all:
	cc $(CFLAGS) -o poly src/*.c $(LDFLAGS)

clean:
	rm -f poly
