#ifndef H2_RULES_H_FW
#define H2_RULES_H_FW

// Rule engine: user-supplied eBPF programs react to local events.
//
// A rule program (see rules/h2_rules.h and rules/h2rules.py) is one function that is
// called for every event: button gestures, knob rotation, timers, start-up. It calls
// host functions to switch the relay, send Zigbee commands to groups or nodes, set LEDs,
// keep variables and start timers. If it returns non-zero, the firmware skips its
// built-in behaviour for that event.
//
// Containment:
//   - programs are verified before they are stored or run (h2_bpf.h);
//   - each event gets a bounded number of instructions and of radio messages;
//   - a faulting program is ignored for that event and the built-in behaviour runs;
//   - rules do not run in safe mode, and the long hold that leads to commissioning and
//     factory reset is always handled by the firmware. Factory reset erases the rules.
//
// The program is stored in NVM3 and loaded at start-up. A new one is staged with
// upload_begin / upload_data / upload_commit; the running program stays in place until
// the new one has passed verification.

#include <stdint.h>
#include <stdbool.h>

#define H2_RULES_MAX_BYTES      2048       // 256 instructions
#define H2_RULES_VARS           16
#define H2_RULES_TIMERS         4

// Event numbering shared with rules/h2_rules.h.
#define H2_RULES_SRC_BUTTON0    0
#define H2_RULES_SRC_KNOB       16
#define H2_RULES_SRC_TIMER      32
#define H2_RULES_SRC_SYSTEM     48

#define H2_RULES_EV_PRESS         1
#define H2_RULES_EV_RELEASE       2
#define H2_RULES_EV_SINGLE        3
#define H2_RULES_EV_DOUBLE        4
#define H2_RULES_EV_TRIPLE        5
#define H2_RULES_EV_HOLD          6
#define H2_RULES_EV_HOLD_RELEASE  7
#define H2_RULES_EV_ROTATE        8
#define H2_RULES_EV_TIMER         9
#define H2_RULES_EV_BOOT         10
#define H2_RULES_EV_ROTATE_PRESSED 11

// Call once from sl_zigbee_af_main_init_cb(). Pass true in safe mode: rules stay off.
void h2_rules_init(bool safe_mode);

// Deliver an event. Returns true if a rule program handled it.
bool h2_rules_event(uint8_t source, uint8_t type, int32_t value);

// True if a program is loaded and running.
bool h2_rules_active(void);

// Staged upload. Data is appended in order. Commit verifies, stores and activates;
// it returns 0 on success, otherwise a non-zero reason (1 size, 2 incomplete,
// 3 verification failed, 4 storage failed); *detail gets the failing instruction index.
bool h2_rules_upload_begin(uint16_t length);
bool h2_rules_upload_data(const uint8_t *data, uint16_t length);
uint8_t h2_rules_upload_commit(uint32_t *detail);

// Remove the stored program.
void h2_rules_erase(void);

// Print state on the debug console.
void h2_rules_print_info(void);

// ---- provided by the variant ------------------------------------------------------------
// mode: 0 off, 1 on, 2 toggle.
void h2_rules_host_relay_set(uint8_t gang, uint8_t mode);
bool h2_rules_host_relay_get(uint8_t gang);
void h2_rules_host_level_set(uint8_t gang, uint8_t level);
// Multi-click detection for a button: clicks 1-3; wait: see h2_encoder_set_max_clicks().
void h2_rules_host_max_clicks(uint8_t button, uint8_t clicks, bool wait);
// Endpoint that rule-generated Zigbee commands are sent from.
uint8_t h2_rules_host_source_endpoint(void);

#endif // H2_RULES_H_FW
