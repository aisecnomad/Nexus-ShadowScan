/* MCP2515 driver: configure the MCP for 500 kbit/s and stream CAN frames.
 *
 * All SPI traffic goes through the spi.h shim so the driver stays
 * host-testable; bit timings follow the MCP2515 datasheet, section 5.
 */

#include "mcp2515.h"
#include "spi.h"

static void mcp_write_reg(uint8_t reg, uint8_t value)
{
    spi_select();
    spi_transfer(MCP_CMD_WRITE);
    spi_transfer(reg);
    spi_transfer(value);
    spi_deselect();
}

static uint8_t mcp_read_reg(uint8_t reg)
{
    uint8_t value;

    spi_select();
    spi_transfer(MCP_CMD_READ);
    spi_transfer(reg);
    value = spi_transfer(0xFFu);
    spi_deselect();
    return value;
}

void mcp2515_set_mode(uint8_t mode)
{
    spi_select();
    spi_transfer(MCP_CMD_BIT_MODIFY);
    spi_transfer(MCP_CANCTRL);
    spi_transfer(0xE0u);
    spi_transfer(mode);
    spi_deselect();
}

int mcp2515_init(uint32_t bitrate_hz)
{
    spi_select();
    spi_transfer(MCP_CMD_RESET);
    spi_deselect();

    if (bitrate_hz != 500000u) {
        return -1; /* only the 500 kbit/s trailer bus profile is tuned */
    }
    /* CNF1..CNF3 for 500 kbit/s at the 16 MHz MCP oscillator. */
    mcp_write_reg(MCP_CNF1, 0x00u);
    mcp_write_reg(MCP_CNF2, 0x90u);
    mcp_write_reg(MCP_CNF3, 0x02u);
    mcp_write_reg(MCP_RXB0CTRL, 0x60u); /* receive any standard frame */
    mcp2515_set_mode(MCP_MODE_NORMAL);
    return (mcp_read_reg(MCP_CANSTAT) & 0xE0u) == MCP_MODE_NORMAL ? 0 : -1;
}

int mcp2515_read_frame(can_frame_t *frame)
{
    uint8_t i;

    spi_select();
    spi_transfer(MCP_CMD_READ);
    spi_transfer(MCP_RXB0SIDH);
    frame->id = (uint32_t)spi_transfer(0xFFu) << 3;
    frame->id |= (uint32_t)(spi_transfer(0xFFu) >> 5);
    spi_transfer(0xFFu); /* EID8, unused on the trailer bus */
    spi_transfer(0xFFu); /* EID0 */
    frame->dlc = spi_transfer(0xFFu) & 0x0Fu;
    for (i = 0u; i < frame->dlc && i < 8u; i++) {
        frame->data[i] = spi_transfer(0xFFu);
    }
    spi_deselect();
    return 0;
}

int mcp2515_send_frame(const can_frame_t *frame)
{
    uint8_t i;

    mcp_write_reg(0x31u, (uint8_t)(frame->id >> 3)); /* TXB0SIDH */
    mcp_write_reg(0x32u, (uint8_t)(frame->id << 5)); /* TXB0SIDL */
    mcp_write_reg(0x35u, frame->dlc);                /* TXB0DLC  */
    for (i = 0u; i < frame->dlc && i < 8u; i++) {
        mcp_write_reg((uint8_t)(0x36u + i), frame->data[i]);
    }
    spi_select();
    spi_transfer(MCP_CMD_RTS_TXB0);
    spi_deselect();
    return 0;
}
