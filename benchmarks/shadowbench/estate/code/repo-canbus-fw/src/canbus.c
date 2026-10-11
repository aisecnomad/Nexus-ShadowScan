/* Route frames from the MCP receive buffer to registered sinks. */

#include "canbus.h"

#define MAX_SINKS 8u

static struct {
    uint32_t      id;
    canbus_sink_t sink;
} sinks[MAX_SINKS];
static uint8_t sink_count;

int canbus_init(void)
{
    sink_count = 0u;
    return mcp2515_init(500000u);
}

void canbus_register_sink(uint32_t can_id, canbus_sink_t sink)
{
    if (sink_count < MAX_SINKS) {
        sinks[sink_count].id = can_id;
        sinks[sink_count].sink = sink;
        sink_count++;
    }
}

void canbus_poll(void)
{
    can_frame_t frame;
    uint8_t i;

    if (mcp2515_read_frame(&frame) != 0) {
        return;
    }
    for (i = 0u; i < sink_count; i++) {
        if (sinks[i].id == frame.id) {
            sinks[i].sink(&frame);
        }
    }
}
