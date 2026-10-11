# repo-canbus-fw

Firmware for the trailer telematics unit (TTU-3). Reads wheel-speed and
reefer temperature frames from the vehicle CAN bus through a Microchip
MCP2515 stand-alone CAN controller on SPI1 and forwards them to the
telematics modem over UART.

The MCP driver lives in `src/mcp2515.c`; register and command names follow
the MCP2515 datasheet (DS20001801J). The MCP interrupt line is unconnected
on rev C boards, so reception is polled from the main loop.

Internal clone: `git@git.vantor.example:firmware/repo-canbus-fw.git`

## Build

    make ttu3

Cross-compiler: arm-none-eabi-gcc 13.
