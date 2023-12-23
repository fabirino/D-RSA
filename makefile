FLAGS	= -Wall -O2 -g -Wno-deprecated-declarations
CC	= gcc
LIBS = -lssl -lcrypto -lgmp

PROG1 = randgen
OBJS1 = randgen.o d-rsa.o

PROG2 = rsagen
OBJS2 = rsagen.o d-rsa.o

PROG3 = time_seed
OBJS3 = time_seed.o d-rsa.o

###############################################

all: ${PROG1} ${PROG2} ${PROG3} clean

${PROG1}: ${OBJS1}
	${CC} ${FLAGS} ${OBJS1} -o $@ ${LIBS}

${PROG2}: ${OBJS2}
	${CC} ${FLAGS} ${OBJS2} -o $@ ${LIBS}

${PROG3}: ${OBJS3}
	${CC} ${FLAGS} ${OBJS3} -o $@ ${LIBS}

.PHONY: clean
clean:
	rm -f ${OBJS1} ${OBJS2} ${OBJS3}

###############################################

d-rsa.o: d-rsa.c d-rsa.h

# randgen
randgen.o: randgen.c d-rsa.c

randgen: randgen.o d-rsa.o

# rsagen
rsagen.o: rsagen.c d-rsa.c

rsagen: rsagen.o d-rsa.o

# time_seed
time_seed.o: time_seed.c d-rsa.c

time_seed: time_seed.o d-rsa.o