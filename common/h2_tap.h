#ifndef H2_TAP_H
#define H2_TAP_H

// Wall-module UART tap over Zigbee.
//
// A diagnostic for installs where the wall connector is not reachable (front plate on a
// mains-powered wall module). When enabled, every frame exchanged with the wall module is
// forwarded to the coordinator as a manufacturer-specific attribute report on the Opple
// cluster (0xFCC0, endpoint 1). A second attribute sends an arbitrary frame to the wall
// module. Off after every boot; nothing is stored.

#include <stdint.h>
#include <stdbool.h>

// Report-only, octet string: [direction, counter, frame bytes...]
//   direction: 0 = front plate -> wall module, 1 = wall module -> front plate
//   counter:   increments for every captured frame, including ones dropped because the
//              queue was full, so gaps are visible
#define H2_TAP_ATTR_FRAME   0xFFF0
// Write, uint8: capture mode (H2_TAP_MODE_*)
#define H2_TAP_ATTR_MODE    0xFFF1
// Write, octet string: [type_hi, type_lo, cmd, payload...]. The firmware adds sync byte,
// sequence number, length, header checksum and CRC, and sends it to the wall module.
#define H2_TAP_ATTR_INJECT  0xFFF2

#define H2_TAP_MODE_OFF        0
#define H2_TAP_MODE_ALL        1
// Everything except the periodic measurement reads and their replies
#define H2_TAP_MODE_NO_POLLS   2

#define H2_TAP_MAX_FRAME   56

void h2_tap_set_mode(uint8_t mode);
uint8_t h2_tap_get_mode(void);

// Called by the relay driver for every frame sent (dir 0) or received (dir 1).
void h2_tap_record(uint8_t dir, const uint8_t *frame, uint16_t len);

// Called from the main-loop tick; sends at most one queued frame per call.
void h2_tap_tick(void);

#endif // H2_TAP_H
