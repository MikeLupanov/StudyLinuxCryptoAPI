.PHONY: all clean

CXX=g++

CFLAGS=-c -Wall -std=c++11 -O2 -DNDEBUG
INCLUDES=
SOURCES=hash.cpp main.cpp
OBJECTS=$(SOURCES:.cpp=.o)
EXECUTABLE=demo-hash

all: $(SOURCES) $(EXECUTABLE)

$(EXECUTABLE): $(OBJECTS)
# Linking
	$(CXX)  $(OBJECTS) -o $@

%.o : %.cpp
# Build
	$(CXX) $(CFLAGS) $< $(INCLUDES) -o $@

clean:
	rm -f $(OBJECTS) $(EXECUTABLE) *.orig
