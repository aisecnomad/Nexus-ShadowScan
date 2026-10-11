/* MCP2515 stand-alone CAN controller driver (SPI).
 *
 * The MCP sits on SPI1 and signals RX through polling; register and
 * command names follow the MCP2515 datasheet, sections 11 and 12.
 */
#ifndef MCP2515_H
#define MCP2515_H

#include <stdint.h>

/* MCP SPI instruction set (datasheet table 12-1). */
#define MCP_CMD_RESET       0xC0u
#define MCP_CMD_READ        0x03u
#define MCP_CMD_WRITE       0x02u
#define MCP_CMD_RTS_TXB0    0x81u
#define MCP_CMD_READ_STATUS 0xA0u
#define MCP_CMD_BIT_MODIFY  0x05u

/* MCP register map (datasheet table 11-1). */
#define MCP_CANSTAT  0x0Eu
#define MCP_CANCTRL  0x0Fu
#define MCP_CNF3     0x28u
#define MCP_CNF2     0x29u
#define MCP_CNF1     0x2Au
#define MCP_RXB0CTRL 0x60u
#define MCP_RXB0SIDH 0x61u

/* CANCTRL mode request values. */
#define MCP_MODE_NORMAL 0x00u
#define MCP_MODE_CONFIG 0x80u

typedef struct {
    uint32_t id;
    uint8_t  dlc;
    uint8_t  data[8];
} can_frame_t;

int  mcp2515_init(uint32_t bitrate_hz);
int  mcp2515_read_frame(can_frame_t *frame);
int  mcp2515_send_frame(const can_frame_t *frame);
void mcp2515_set_mode(uint8_t mode);

#endif /* MCP2515_H */
