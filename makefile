FLAGS	= -Wall -O2 -g -Wno-deprecated-declarations
CC	= gcc
LIBS = -lssl -lcrypto

PROG1 = randgen
OBJS1 = randgen.o PRBG.o

PROG2 = rsagen
OBJS2 = rsagen.o PRBG.o

###############################################

all: ${PROG1} ${PROG2} clean

${PROG1}: ${OBJS1}
	${CC} ${FLAGS} ${OBJS1} -o $@ ${LIBS}

${PROG2}: ${OBJS2}
	${CC} ${FLAGS} ${OBJS2} -o $@ ${LIBS}

.PHONY: clean
clean:
	rm -f ${OBJS1} ${OBJS2} ${OBJS3}

###############################################

PRBG.o: PRBG.c PRBG.h

# randgen
randgen.o: randgen.c PRBG.c

randgen: randgen.o PRBG.o

# rsagen
rsagen.o: rsagen.c PRBG.c

rsagen: rsagen.o PRBG.o