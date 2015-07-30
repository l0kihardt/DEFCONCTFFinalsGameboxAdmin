CFLAGS += -std=c99 -g3
CXXFLAGS += -std=c++11 -g3
#CPPFLAGS += -fkeep-inline-functions -fsanitize=address
ELF := proxy-service inotify-flag grep-flag

all: $(ELF)
clean:
	$(RM) $(ELF)

inotify-flag: CFLAGS += -pthread

.PSEUDO: all clean
