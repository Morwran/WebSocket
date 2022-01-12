TESTING = 0

BIN = websocket
OBJ = websocket.o
CFLAGS = -Wall
CC = gcc

ifeq ($(TESTING), 1)
CFLAGS += -DTESTING
endif

# LDFLAGS = -L/usr/lib -lssl -lcrypto
LDFLAGS = -lm

all: $(BIN)
$(BIN): $(OBJ)
	$(CC) $(CFLAGS) -o $@ $(OBJ) $(LDFLAGS)

clean:
	rm -rf $(BIN) *.o