/* Trailer CAN bus frame routing on top of the MCP driver. */
#ifndef CANBUS_H
#define CANBUS_H

#include "mcp2515.h"

#define CANBUS_ID_WHEEL_SPEED 0x18Fu
#define CANBUS_ID_REEFER_TEMP 0x19Au

typedef void (*canbus_sink_t)(const can_frame_t *frame);

int  canbus_init(void);
void canbus_register_sink(uint32_t can_id, canbus_sink_t sink);
void canbus_poll(void);

#endif /* CANBUS_H */
