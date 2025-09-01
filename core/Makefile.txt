# Compiler
CC = gcc

# Compiler flags
CFLAGS = -Wall -Wextra -Iinclude

# Project name
TARGET = core_app

# Source files
SRCS = core.c \
core/modules/encrypt.c \
core/modules/decrypt.c

# Object files
OBJS = $(SRCS:.c=.o)

# Default rule
all: $(TARGET)

# Build target
$(TARGET): $(OBJS)
$(CC) $(OBJS) -o $(TARGET)

# Clean build artifacts
clean:
rm -f $(OBJS) $(TARGET)

# Phony targets
.PHONY: all clean