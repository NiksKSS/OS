CC=clang
CFLAGS=-Wall -Wextra -pedantic -fPIC
LIB=libcaesar.dylib

all: $(LIB) test_program

$(LIB): caesar.o
	$(CC) -dynamiclib -o $(LIB) caesar.o

caesar.o: caesar.c
	$(CC) $(CFLAGS) -c caesar.c

test_program: test.c
	$(CC) -Wall -Wextra -pedantic test.c -o test_program -ldl

install: $(LIB)
	cp $(LIB) /usr/local/lib/

test: all
	echo "Hello XOR!" > input.txt
	./test_program ./$(LIB) K input.txt output.txt
	./test_program ./$(LIB) K output.txt decrypted.txt
	cat decrypted.txt

clean:
	rm -f *.o *.dylib test_program input.txt output.txt decrypted.txt

secure_copy: secure_copy.c $(LIB)
	$(CC) secure_copy.c -o secure_copy -L. -lcaesar -pthread -Wall
