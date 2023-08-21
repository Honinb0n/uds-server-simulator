GXX = gcc
TARGET = uds-server-simulator
DEPENDENCY = uds-server-simulator.c third/cJSON.c

$(TARGET): $(DEPENDENCY)
	$(GXX) -w $^ -o $@
