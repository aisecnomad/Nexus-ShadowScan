CC     = arm-none-eabi-gcc
CFLAGS = -mcpu=cortex-m4 -mthumb -Os -Wall -Wextra -Iinclude -Isrc
OBJS   = src/main.o src/canbus.o src/mcp2515.o

ttu3.elf: $(OBJS)
	$(CC) $(CFLAGS) -o $@ $(OBJS)

.PHONY: ttu3 clean
ttu3: ttu3.elf

clean:
	rm -f $(OBJS) ttu3.elf
