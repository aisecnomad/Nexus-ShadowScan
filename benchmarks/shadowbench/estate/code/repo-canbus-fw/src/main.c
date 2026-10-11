/* TTU-3 entry point: forward wheel-speed and reefer frames to the modem. */

#include "canbus.h"

extern void uart_send(const uint8_t *data, uint8_t len);

static void forward(const can_frame_t *frame)
{
    uart_send(frame->data, frame->dlc);
}

int main(void)
{
    if (canbus_init() != 0) {
        for (;;) {
            /* The MCP did not come up; the watchdog resets the unit. */
        }
    }
    canbus_register_sink(CANBUS_ID_WHEEL_SPEED, forward);
    canbus_register_sink(CANBUS_ID_REEFER_TEMP, forward);
    for (;;) {
        canbus_poll();
    }
}
