#ifndef H2_SAFE_H
#define H2_SAFE_H

// Crash fallback ("safe mode").
//
// A front plate on a mains-powered wall module can only be reached over Zigbee. If a build
// crashes or hangs soon after every boot, it could never be replaced over the air. To keep
// OTA reachable, the firmware counts boots that did not stay up for H2_SAFE_HEALTHY_S. After
// H2_SAFE_FAIL_LIMIT such boots in a row it starts in safe mode: the Zigbee stack and OTA
// client run, but no application hardware or message handling does, and the red LED blinks.
//
// Safe mode ends when a different firmware version is installed, or by itself after
// H2_SAFE_EXIT_MIN minutes (it then reboots into normal mode for another try).
// Power-cycling the device H2_SAFE_FAIL_LIMIT times in quick succession also enters it.

#include <stdint.h>
#include <stdbool.h>

#define H2_SAFE_FAIL_LIMIT   3
#define H2_SAFE_HEALTHY_S    60
#define H2_SAFE_EXIT_MIN     30

// Call first in sl_zigbee_af_main_init_cb(). Returns true if this boot is in safe mode.
bool h2_safe_boot(uint32_t firmware_version);

// Call once from sl_zigbee_af_main_init_cb() after h2_safe_boot(), in both modes.
void h2_safe_start(void);

bool h2_safe_mode_active(void);

// Number of consecutive unhealthy boots including this one (diagnostics).
uint8_t h2_safe_fail_count(void);

#endif // H2_SAFE_H
