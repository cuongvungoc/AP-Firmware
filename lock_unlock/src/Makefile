EXEC=lock_unlock
SRC=lock_unlock.c dns_parser_daemon.c
# THREAD_FLAGS=-lpthread
LDLIBS= -lpthread

all: $(EXEC)
$(EXEC): $(SRC)
	$(CC) $(LDLIBS) $(CFLAGS) $(LDFLAGS) -o $@ $(SRC) $(LDLIBS)

clean:
	-rm -f $(EXEC) *.elf *.gdb *.o