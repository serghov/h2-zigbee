#ifndef H2_RELAY_H
#define H2_RELAY_H

#include <stdint.h>
#include <stdbool.h>
#include "h2_variant.h"

typedef enum {
  H2_RELAY_OFF = 0,
  H2_RELAY_ON  = 1
} h2_relay_state_t;

// RX callback: called from main loop with parsed command entry fields
// cmd_id: combined command (0x0600=voltage on dimmer, 0x0601=mA, 0x0602=W, 0x0608=°C)
// data_type: entry data type (0x55=float/value)
// data: little-endian value, valid for the duration of the callback
// data_len: actual value length (1 or 4 for supported command groups)
typedef void (*h2_relay_rx_callback_t)(uint16_t cmd_id, uint8_t data_type,
                                       const uint8_t *data, uint8_t data_len);

// Initialize relay hardware + start UART RX
void h2_relay_init(void);

// Send an arbitrary frame to the wall module (diagnostics). The driver adds the sync byte,
// sequence number, length, header checksum and CRC. payload_len <= 62.
void h2_relay_send_raw(uint16_t type, uint8_t cmd,
                       const uint8_t *payload, uint8_t payload_len);

// Set relay state for a gang (0-indexed)
void h2_relay_set(uint8_t gang, h2_relay_state_t state);

// A relay command is confirmed: it is repeated until the wall module replies (see
// h2_relay.c). These counters say how that went; they saturate at 255.
typedef struct {
  uint8_t  sent;               // relay commands issued
  uint8_t  acked;              // ... that the wall module replied to
  uint8_t  unacked;            // ... that got no reply after all tries
  uint8_t  last_tries;         // transmissions used by the last command (1..3)
  bool     last_acked;
  uint8_t  last_status;        // first status byte of the last reply
  uint8_t  protection_events;  // wall-module event entries 0x05xx seen
  uint16_t protection_entry;   // the last one
  uint32_t protection_value;
} h2_relay_link_stats_t;

const h2_relay_link_stats_t *h2_relay_link_stats(void);
bool h2_relay_busy(void);      // a relay command is in flight: hold other requests back
// Send the wanted state of every relay in one message (switch variants; the default).
void h2_relay_set_combined(bool on);
// The wall module acknowledged the last command for this relay.
bool h2_relay_in_step(uint8_t gang);
void h2_relay_note_protection(uint16_t entry_id, uint32_t value);

// Read-only diagnostics on the Opple cluster (uint32):
//   LINK   (unanswered << 24) | (answered << 16) | (flags << 8) | (tries << 4) | status
//          flags: bit 0 last command answered, bit 1 a command is in flight,
//                 bit 3 relays commanded together go in one message,
//                 bit 2 a wall-module event (over-power, over-temperature, ...) was seen
//   EVENT  (event count << 24) | (low byte of the value << 16) | entry id of the last event
#define H2_RELAY_ATTR_LINK    0xFFC8
#define H2_RELAY_ATTR_EVENT   0xFFC9
bool h2_relay_attr_get(uint16_t attr_id, uint32_t *value);

// Get current relay state for a gang (0-indexed)
h2_relay_state_t h2_relay_get(uint8_t gang);

// Toggle relay state for a gang, returns new state
h2_relay_state_t h2_relay_toggle(uint8_t gang);

// Register callback for received UART commands
void h2_relay_set_rx_callback(h2_relay_rx_callback_t cb);

// Process pending RX packet (call from main loop, e.g. every 10ms tick)
void h2_relay_process_rx(void);

// Send init handshake to relay module (status + relay state queries)
void h2_relay_send_init(void);

// Read device-wide measurements (gang is retained for existing callers).
void h2_relay_send_measurement_query(uint8_t gang);

#if H2_HAS_DIMMER
// Set dimmer brightness level (1-254) for a gang — applies gamma curve and sends via UART
void h2_relay_set_level(uint8_t gang, uint8_t level);

// Get current dimmer brightness level (1-254) for a gang
uint8_t h2_relay_get_level(uint8_t gang);

// Set min/max brightness range on wall module (percentage 0-100)
void h2_relay_set_brightness_range(uint8_t min_pct, uint8_t max_pct);

// Set phase mode on wall module (0=forward, 1=reverse)
void h2_relay_set_phase_mode(uint8_t mode);
#endif

#endif // H2_RELAY_H
