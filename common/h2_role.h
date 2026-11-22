#ifndef H2_ROLE_H
#define H2_ROLE_H

// Runtime Zigbee role: router (neutral-wired) or sleepy end device (no neutral).
//
// The image is built with the SDK's multi-network support and two network definitions:
// index 0 = router, index 1 = sleepy end device. Only one of them is ever joined. The
// chosen index is stored in NVM3; at boot every endpoint is moved to it and it becomes the
// framework's current network for good. Changing the role leaves the network, saves the
// new index and reboots, so the device has to join again in the new role. This mirrors
// what the stock firmware does.

#include <stdint.h>
#include <stdbool.h>

#define H2_ROLE_ROUTER   0     // network index 0
#define H2_ROLE_SLEEPY   1     // network index 1

// The role itself is applied during framework start-up (see h2_role.c). Call this from
// sl_zigbee_af_main_init_cb() to finish: power requirement, events, log line.
void h2_role_init(void);

uint8_t h2_role_get(void);

// Switch role. No effect if it is already the current role. Otherwise leaves the current
// network, stores the new role and reboots about a second later.
void h2_role_set(uint8_t role);

#endif // H2_ROLE_H
