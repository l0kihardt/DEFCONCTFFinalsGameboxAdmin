CFLAGS += -std=c99 -g3 -pthread
#CFLAGS += -fkeep-inline-functions -fsanitize=address
ELF := proxy-service inotify-flag

all: $(ELF)
clean:
	$(RM) $(ELF)

proxy-service: %: %.c

inotify-flag: %: %.c

.PSEUDO: all clean
