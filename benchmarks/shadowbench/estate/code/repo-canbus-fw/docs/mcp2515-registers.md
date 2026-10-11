# MCP2515 register notes

Working notes for the MCP registers the TTU-3 firmware touches. Page
numbers refer to the MCP2515 datasheet (DS20001801J).

| Register | Address | Use on the TTU-3 |
| --- | --- | --- |
| CANCTRL | 0x0F | Mode requests; the MCP boots in configuration mode |
| CANSTAT | 0x0E | Mode readback after `mcp2515_set_mode` |
| CNF1-CNF3 | 0x2A-0x28 | Bit timing, tuned for 500 kbit/s at 16 MHz |
| RXB0CTRL | 0x60 | Receive-any; filters are left open |
| TXB0SIDH/SIDL | 0x31-0x32 | Standard identifiers only on the trailer bus |

The MCP interrupt line is polled, not wired: INT stays unconnected on
rev C boards, so `canbus_poll` runs from the main loop. Keep every MCP
access on SPI1; the modem owns SPI2.
