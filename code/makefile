CC = gcc

SRCS = $(wildcard *.c)     # Get all .c files in the directory
OBJS = $(SRCS:.c=.o)       # Generate .o filenames from .c filenames
MAIN = fbi            	   # Name of the final executable

# Rule to compile each .c file into .o file
%.o: %.c
	$(CC) -c $< -o $@

# Rule to link all .o files into the final executable and then del all .o files
$(MAIN): $(OBJS)
	$(CC) $^ -o $@
	rm -f $(OBJS)


