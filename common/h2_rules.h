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
#define H2_RULES_SRC_REMOTE0    64      // 64..71: another device, numbered in order of first report

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
#define H2_RULES_EV_VAR          12     // a public variable was written from outside; value = index
#define H2_RULES_EV_TRIGGER      13     // a trigger was written from outside; value = its number
#define H2_RULES_EV_REPORT       14     // another device reported an attribute the program watches

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
bool h2_rules_upload_data_at(uint16_t offset, const uint8_t *data, uint16_t length);
uint8_t h2_rules_upload_commit(uint32_t *detail);

// Remove the stored program.
void h2_rules_erase(void);

// Print state on the debug console.
void h2_rules_print_info(void);

// Access over Zigbee: manufacturer-specific attributes on the Opple cluster (0xFCC0).
//
//   CONTROL  uint32, write: (operation << 24) | argument
//              BEGIN   argument = program length in bytes
//              COMMIT  argument = CRC16 of the whole program (CRC-16/MODBUS);
//                      verifies, stores and activates. The write fails if the program
//                      is refused; read CONTROL for the reason.
//              ERASE   remove the stored program
//            read: (flags << 24) | (result of the last commit << 16) | value
//              flags   bit 0 a program is running, bit 1 an upload is in progress,
//                      bit 2 safe mode (programs are stored but do not run)
//              result  0 ok, 1 nothing to commit, 2 incomplete, 3 refused by the verifier,
//                      4 storage error, 5 checksum mismatch
//              value   bytes received so far while an upload is in progress, otherwise
//                      the instruction the verifier refused
//   DATA     octet string, write only: [offset lo][offset hi][program bytes...].
//            Chunks are sent in order; repeating a chunk is harmless.
//   INFO     uint32, read: (CRC16 of the installed program << 16) | its length; 0 = none
//   FAULT    uint32, read: (last fault code << 24) | (fault count << 16) | instruction
//   VAR0..  uint32, one attribute per rule variable (0xFFA0 + index). Only variables the
//            program declared public (var_public) exist. A write with a new value sets
//            the variable and raises H2_RULES_EV_VAR in the program; a write of the
//            value it already has does nothing. When the program changes a public
//            variable, the device reports the attribute to the hub.
//   TRIGGER  uint32, write only: raises H2_RULES_EV_TRIGGER with the written number.
//   DROPPED  uint32, read: radio messages and outside events dropped by the limits.
// Radio messages a program sends while handling VAR or TRIGGER events come out of a small
// allowance (4, refilled one per 2.5 s), so reaction loops cannot flood the network.
#define H2_RULES_ATTR_VAR0      0xFFA0
#define H2_RULES_ATTR_TRIGGER   0xFFB0
#define H2_RULES_ATTR_DROPPED   0xFFC4
#define H2_RULES_ATTR_CONTROL   0xFFC0
#define H2_RULES_ATTR_DATA      0xFFC1
#define H2_RULES_ATTR_INFO      0xFFC2
#define H2_RULES_ATTR_FAULT     0xFFC3
#define H2_RULES_OP_BEGIN       1
#define H2_RULES_OP_COMMIT      2
#define H2_RULES_OP_ERASE       3

bool h2_rules_attr_get(uint16_t attr_id, uint32_t *value);

// Every incoming ZCL message, for the reports of other devices. Call from the variant's
// pre-message callback (not in safe mode); it never consumes the message.
//
// A device that is bound to this one, or that answers a group_read, sends attribute
// values here. The program names the attributes it wants (watch); for those, the newest
// value per device is kept and handed to the program as H2_RULES_EV_REPORT: only when it
// changed, and at most every 250 ms per device and attribute.
//
// A device that answers a group_read is asked, once, to report the watched clusters to
// this device from then on (ZDO bind to endpoint H2_RULES_REPORT_ENDPOINT), so no binding
// has to be set up on the hub.
#define H2_RULES_REPORT_ENDPOINT  11
void h2_rules_incoming(uint16_t source_node, uint8_t source_endpoint, uint16_t cluster,
                       const uint8_t *msg, uint16_t len);
// Returns false when the attribute is not one of the above; otherwise *ok says whether
// the write was accepted.
bool h2_rules_attr_write(uint16_t attr_id, uint8_t zcl_type, const uint8_t *data,
                         uint16_t length, bool *ok);

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
