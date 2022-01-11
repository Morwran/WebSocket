
BIN = websocket
OBJ = websocket.o
CFLAGS = -Wall -lm
CC = gcc

# LDFLAGS = -L/usr/lib -lssl -lcrypto
LDFLAGS =

all: $(BIN)
$(BIN): $(OBJ)
	$(CC) $(CFLAGS) -o $@ $(OBJ) $(LDFLAGS)

clean:
	rm -rf $(BIN) *.o