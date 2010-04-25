
CC = gcc
CFLAGS = -g -Wall -pthread
LFLAGS = -lssl -lcrypto
RM = /bin/rm

OBJS = common.o		\
       client.o		\
       server.o	

BINS = client server

all: $(BINS)

$(BINS): $(OBJS)
	$(CC) $(CFLAGS) -o $@ $(@).o common.o $(LFLAGS)

$(OBJS): common.h msg.h

.c.o:
	$(CC) $(CFLAGS) -c $< -o $@

clean:
	$(RM) -f $(BINS) $(OBJS) *~
