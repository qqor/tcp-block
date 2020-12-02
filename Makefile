LDLIBS=-lpcap

all: tcp-block

tcp-block: main.o
	$(LINK.cc) $^ $(LOADLIBES) $(LDLIBS) -o $@

clean:
	rm -f tcp-block *.o