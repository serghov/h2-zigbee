#ifndef H2_SAFE_H
#define H2_SAFE_H

// Crash fallback ("safe mode").
//
// A front plate on a mains-powered wall module can only be reached over Zigbee. If a build
// crashes or hangs soon after every boot, it could never be replaced over the air. To keep
// OTA reachable, the firmware counts boots that did not stay up for H2_SAFE_HEALTHY_S. After
// H2_SAFE_FAIL_LIMIT such boots in a row it starts in safe mode: the Zigbee stack and OTA
// client run, but no application hardware or message handling does, and the red LED blinks.
// If the device has no network in safe mode it tries to join an open one every
// H2_SAFE_JOIN_RETRY_S seconds, starting 2 s after boot.
//
// Safe mode ends when a different firmware version is installed, or by itself after
// H2_SAFE_EXIT_MIN minutes (it then reboots into normal mode for another try).
// Power-cycling the device H2_SAFE_FAIL_LIMIT times in quick succession also enters it.

#include <stdint.h>
#include <stdbool.h>

#define H2_SAFE_FAIL_LIMIT   3
#define H2_SAFE_HEALTHY_S    60
#define H2_SAFE_EXIT_MIN     30
#define H2_SAFE_JOIN_RETRY_S 30   // in safe mode without a network: try to join this often

// Call first in sl_zigbee_af_main_init_cb(). Returns true if this boot is in safe mode.
bool h2_safe_boot(uint32_t firmware_version);

// Call once from sl_zigbee_af_main_init_cb() after h2_safe_boot(), in both modes.
void h2_safe_start(void);

bool h2_safe_mode_active(void);

// Number of consecutive unhealthy boots including this one (diagnostics).
uint8_t h2_safe_fail_count(void);

// Boot diagnostics, readable over Zigbee in normal AND safe mode: manufacturer-specific
// attribute 0xFFF4 on the Opple cluster (0xFCC0), octet string:
//   [0] 1 if this boot is in safe mode
//   [1] consecutive unhealthy boots, including this one
//   [2..] reset causes of the last H2_SAFE_RESET_HISTORY boots, newest first, two bytes
//         each (low, high) as returned by halGetExtendedResetInfo(): high byte is the base
//         cause, low byte the detail, as listed in the SDK's legacy_hal reset-def.h.
//         Common values: 0x0401 power-on, 0x0501 watchdog expired, 0x0600/0x0601 software
//         reset, 0x0201/0x0202 bootloader (for example after an OTA install), 0x0301 pin.
#define H2_SAFE_ATTR_DIAG       0xFFF4
#define H2_SAFE_RESET_HISTORY   6

// Call at the top of sl_zigbee_af_pre_message_received_cb() for Opple-cluster messages,
// before any safe-mode gate. Returns true if it answered a read of H2_SAFE_ATTR_DIAG.
bool h2_safe_handle_diag_read(uint8_t endpoint, uint16_t source_node,
                              const uint8_t *msg, uint16_t msg_len);

#endif // H2_SAFE_H
