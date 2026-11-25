#include "app/framework/include/af.h"
#include "h2_relay.h"
#include "h2_tap.h"
#include "uartdrv.h"
#include "sl_uartdrv_instances.h"
#include "em_eusart.h"
#include "em_gpio.h"
#include "pin_config.h"
#include "sl_power_manager.h"
#include "sl_sleeptimer.h"
#include <string.h>

#include "h2_variant.h"

extern uint8_t h2_active_gang_count;

#if H2_HAS_DIMMER
#define RELAY_TYPE     0x8007
#else
#define RELAY_TYPE     0x8002
#endif
#define RELAY_CMD_SET  0x02
#define RELAY_CMD_READ 0x01
#define RELAY_CMD_QUERY 0x03

static h2_relay_state_t relay_state[H2_SWITCH_GANG_COUNT];
static uint8_t seq;

static uint16_t crc16_modbus(const uint8_t *data, uint8_t len)
{
  uint16_t crc = 0xFFFF;
  for (uint8_t i = 0; i < len; i++) {
    crc ^= data[i];
    for (uint8_t j = 0; j < 8; j++) {
      if (crc & 1) {
        crc = (crc >> 1) ^ 0xA001;
      } else {
        crc >>= 1;
      }
    }
  }
  return crc;
}

// ---------------------------------------------------------------------------
// Frame builder and transmitter
// ---------------------------------------------------------------------------

#define FRAME_MAX 72   // 8 header + max 62 payload + 2 CRC

static uint8_t build_frame(uint8_t *buf, uint16_t type, uint8_t cmd, uint8_t frame_seq,
                           const uint8_t *payload, uint8_t payload_len)
{
  // Header (big-endian type, big-endian payload_len)
  buf[0] = 0x55;
  buf[1] = (uint8_t)(type >> 8);
  buf[2] = (uint8_t)(type & 0xFF);
  buf[3] = frame_seq;
  buf[4] = cmd;
  buf[5] = (uint8_t)(payload_len >> 8);
  buf[6] = (uint8_t)(payload_len & 0xFF);

  // Header checksum: sum of bytes 0-7 == 0 mod 256
  uint8_t hdr_sum = 0;
  for (uint8_t i = 0; i < 7; i++) {
    hdr_sum += buf[i];
  }
  buf[7] = (uint8_t)(0x100 - hdr_sum);

  if (payload_len > 0 && payload != NULL) {
    memcpy(&buf[8], payload, payload_len);
  }

  // CRC-16/MODBUS over all bytes before CRC, stored little-endian
  uint16_t crc = crc16_modbus(buf, 8 + payload_len);
  buf[8 + payload_len]     = (uint8_t)(crc & 0xFF);
  buf[8 + payload_len + 1] = (uint8_t)(crc >> 8);
  return (uint8_t)(8 + payload_len + 2);
}

// True while a confirmed relay command is in flight (see "Confirmed relay commands").
// The attention line WALL2 then stays low for the whole exchange.
static bool set_in_flight(void);

static void transmit_frame(const uint8_t *buf, uint8_t total)
{
  uint8_t payload_len = (uint8_t)(total - 10);
  sl_zigbee_app_debug_print("TX PKT type=%02X%02X cmd=%02X plen=%d [",
                             buf[1], buf[2], buf[4], payload_len);
  uint8_t dump = (payload_len < 24) ? payload_len : 24;
  for (uint8_t i = 0; i < dump; i++) {
    sl_zigbee_app_debug_print("%02X", buf[8 + i]);
  }
  sl_zigbee_app_debug_println("]");

  h2_tap_record(0, buf, total);

  // Hold EM1 during TX — EM2 would stop the EUSART HF clock and cause
  // glitch pulses on the TX line that corrupt every packet
  sl_power_manager_add_em_requirement(SL_POWER_MANAGER_EM1);

  bool held = set_in_flight();          // WALL2 is already low and stays low
#if H2_HAS_DIMMER
  // Dimmer stock firmware: WALL2 only goes low for SET commands,
  // held for the entire exchange. ACK/query packets don't toggle WALL2.
  bool pulse = !held && (buf[4] == RELAY_CMD_SET);
#else
  bool pulse = !held;
#endif
  if (pulse) GPIO_PinOutClear(WALL2_PORT, WALL2_PIN);
  UARTDRV_TransmitB(sl_uartdrv_eusart_wall_uart_handle, (uint8_t *)buf, total);
  if (pulse) GPIO_PinOutSet(WALL2_PORT, WALL2_PIN);

  sl_power_manager_remove_em_requirement(SL_POWER_MANAGER_EM1);
}

// Build and send one frame at once, unconfirmed (reads, acknowledgements, settings).
static void relay_send_packet(uint16_t type, uint8_t cmd,
                               const uint8_t *payload, uint8_t payload_len)
{
  uint8_t buf[FRAME_MAX];
  uint8_t total = build_frame(buf, type, cmd, seq++, payload, payload_len);
  transmit_frame(buf, total);
}

// ---------------------------------------------------------------------------
// Confirmed relay commands
//
// The stock firmware pulls the attention line low, waits, sends the request, and repeats
// it with the same sequence number until the wall module replies (command 3, same
// sequence number). A relay command sent once with no lead time can go unheard, and the
// plate would then report a state the relay is not in. One command is in flight at a
// time; a newer command for the relays replaces a waiting one.
// ---------------------------------------------------------------------------

#define SET_LEAD_MS    20     // attention line low before the first byte
#define SET_REPLY_MS   100    // wait for the reply before repeating
#define SET_TRIES      3
#define SET_HOLD_MS    100    // attention line stays low at least this long

typedef enum { SET_IDLE, SET_LEAD, SET_WAIT, SET_HOLD } set_phase_t;

// What is in flight is "bring gang N to its wanted state", not a prepared frame: the
// frame is built when it is first transmitted, from the state wanted at that moment (on
// the dimmer that includes the current level). Each gang has its own pending flag, so a
// command for one gang never displaces a waiting command for another, and a change made
// while a gang's command is in flight is sent in a further exchange.
static struct {
  set_phase_t phase;
  uint8_t  gang;
  uint8_t  frame[FRAME_MAX];
  uint8_t  len;
  uint8_t  tries;
  uint32_t started;           // sleeptimer ticks
  uint32_t phase_since;
} set_tx;
static bool set_pending[H2_SWITCH_GANG_COUNT];
// The wanted state differs from the one last sent. Such a command goes out before one
// that only repeats a state (the plate cannot see the relay, so repeats are sent too, but
// they must not hold up a real change).
static bool set_changed[H2_SWITCH_GANG_COUNT];
// One message carries every relay that has a command waiting (switch variants). The
// 2-relay wall module accepts this and obeys both entries (living room, 2026-11-25); it
// still switches its relays one after the other, a few hundred ms apart, by itself. A
// relay nobody commanded is not in the message: what the plate holds for it is only a
// belief. Can be turned off with h2_relay_set_combined(false): one relay per message.
#if H2_HAS_DIMMER
static bool set_combined = false;
#else
static bool set_combined = true;
#endif
// The last command that included this relay got no reply.
static bool set_unacked[H2_SWITCH_GANG_COUNT];
static uint8_t set_included;          // bit per gang in the message in flight

static h2_relay_link_stats_t link_stats;

static uint8_t relay_set_payload(uint8_t gang, uint8_t *payload);   // per variant, below

static uint32_t ms_since(uint32_t tick)
{
  return sl_sleeptimer_tick_to_ms(sl_sleeptimer_get_tick_count() - tick);
}

static bool set_in_flight(void)
{
  return set_tx.phase != SET_IDLE;
}

bool h2_relay_busy(void)
{
  return set_in_flight();
}

// The gang whose command goes next: one with a real change first. 0xFF if none waits.
static uint8_t set_next_gang(void)
{
  for (uint8_t g = 0; g < H2_SWITCH_GANG_COUNT; g++) {
    if (set_pending[g] && set_changed[g]) return g;
  }
  for (uint8_t g = 0; g < H2_SWITCH_GANG_COUNT; g++) {
    if (set_pending[g]) return g;
  }
  return 0xFF;
}

// Start an exchange if a command is waiting. Which gang it is for is decided when the
// lead time is over, so commands given together are ordered by what they change.
static void set_start_next(void)
{
  for (uint8_t g = 0; g < H2_SWITCH_GANG_COUNT; g++) {
    if (!set_pending[g]) continue;
    set_tx.gang = g;
    set_tx.tries = 0;
    set_tx.started = set_tx.phase_since = sl_sleeptimer_get_tick_count();
    set_tx.phase = SET_LEAD;
    GPIO_PinOutClear(WALL2_PORT, WALL2_PIN);
    return;
  }
}

static void relay_send_confirmed(uint8_t gang)
{
  if (gang >= H2_SWITCH_GANG_COUNT) return;
  set_pending[gang] = true;
  if (link_stats.sent < 255) link_stats.sent++;
  if (set_tx.phase == SET_IDLE) set_start_next();
}

static void set_finish(bool acked, uint8_t status)
{
  link_stats.last_tries = set_tx.tries;
  link_stats.last_acked = acked;
  link_stats.last_status = status;
  for (uint8_t g = 0; g < H2_SWITCH_GANG_COUNT; g++) {
    if (set_included & (1u << g)) set_unacked[g] = !acked;
  }
  if (acked) {
    if (link_stats.acked < 255) link_stats.acked++;
  } else {
    if (link_stats.unacked < 255) link_stats.unacked++;
    sl_zigbee_app_debug_println("Relay: no reply from the wall module after %d tries", set_tx.tries);
  }
  set_tx.phase = SET_HOLD;
}

// Called for every received frame: is it the reply to the command in flight?
static void set_on_frame(const uint8_t *frame, uint16_t len)
{
  if (set_tx.phase != SET_WAIT || frame[4] != RELAY_CMD_QUERY || frame[3] != set_tx.frame[3]) {
    return;
  }
  uint16_t plen = ((uint16_t)frame[5] << 8) | frame[6];
  set_finish(true, (plen > 0 && len >= 9) ? frame[8] : 0);
}

static void set_service(void)
{
  switch (set_tx.phase) {
    case SET_IDLE:
      break;
    case SET_LEAD:
      if (ms_since(set_tx.phase_since) >= SET_LEAD_MS) {
        // Build the frame now, from the state wanted now; anything set after this point
        // marks the gang pending again.
        uint8_t payload[24];
        uint8_t n = 0;
        uint8_t next = set_next_gang();
        if (next != 0xFF) set_tx.gang = next;
        set_included = 0;
#if !H2_HAS_DIMMER
        if (set_combined) {
          for (uint8_t g = 0; g < h2_active_gang_count && g < H2_SWITCH_GANG_COUNT; g++) {
            if (!set_pending[g]) continue;
            set_pending[g] = false;
            set_changed[g] = false;
            set_included |= (uint8_t)(1u << g);
            n += relay_set_payload(g, payload + n);
          }
        }
#endif
        if (n == 0) {
          set_pending[set_tx.gang] = false;
          set_changed[set_tx.gang] = false;
          set_included = (uint8_t)(1u << set_tx.gang);
          n = relay_set_payload(set_tx.gang, payload);
        }
        set_tx.len = build_frame(set_tx.frame, RELAY_TYPE, RELAY_CMD_SET, seq++, payload, n);
        set_tx.tries = 1;
        set_tx.phase = SET_WAIT;
        set_tx.phase_since = sl_sleeptimer_get_tick_count();
        transmit_frame(set_tx.frame, set_tx.len);
      }
      break;
    case SET_WAIT:
      if (ms_since(set_tx.phase_since) >= SET_REPLY_MS) {
        if (set_tx.tries < SET_TRIES) {
          set_tx.tries++;
          set_tx.phase_since = sl_sleeptimer_get_tick_count();
          transmit_frame(set_tx.frame, set_tx.len);
        } else {
          set_finish(false, 0);
        }
      }
      break;
    case SET_HOLD:
      if (ms_since(set_tx.started) >= SET_HOLD_MS) {
        GPIO_PinOutSet(WALL2_PORT, WALL2_PIN);
        set_tx.phase = SET_IDLE;
        set_start_next();
      }
      break;
  }
}

void h2_relay_set_combined(bool on)
{
#if !H2_HAS_DIMMER
  set_combined = on;
#else
  (void)on;
#endif
}

// True if the wall module acknowledged the last command for this relay (or none was sent
// yet): the state the plate holds for it can be taken as the relay's.
bool h2_relay_in_step(uint8_t gang)
{
  return gang < H2_SWITCH_GANG_COUNT && !set_unacked[gang];
}

void h2_relay_note_protection(uint16_t entry_id, uint32_t value)
{
  link_stats.protection_entry = entry_id;
  link_stats.protection_value = value;
  if (link_stats.protection_events < 255) link_stats.protection_events++;
  sl_zigbee_app_debug_println("Relay: wall module event 0x%04X = %lu", entry_id, (unsigned long)value);
}

const h2_relay_link_stats_t *h2_relay_link_stats(void)
{
  return &link_stats;
}

bool h2_relay_attr_get(uint16_t attr_id, uint32_t *value)
{
  switch (attr_id) {
    case H2_RELAY_ATTR_LINK:
      *value = ((uint32_t)link_stats.unacked << 24) | ((uint32_t)link_stats.acked << 16)
             | ((uint32_t)((set_in_flight() ? 0x02 : 0) | (link_stats.last_acked ? 0x01 : 0)
                           | (link_stats.protection_events ? 0x04 : 0)
                           | (set_combined ? 0x08 : 0)) << 8)
             | (uint32_t)((link_stats.last_tries << 4) | (link_stats.last_status & 0x0F));
      return true;
    case H2_RELAY_ATTR_EVENT:
      *value = ((uint32_t)link_stats.protection_events << 24)
             | ((uint32_t)(link_stats.protection_value & 0xFF) << 16)
             | link_stats.protection_entry;
      return true;
    default:
      return false;
  }
}

// ---------------------------------------------------------------------------
// UART RX state machine (byte-at-a-time, ISR-driven)
// ---------------------------------------------------------------------------

#define RX_BUF_SIZE 72  // 8 header + max payload + 2 CRC
#define RX_MAX_PAYLOAD 56

typedef enum {
  RX_WAIT_SYNC,
  RX_READ_HEADER,
  RX_READ_PAYLOAD,
  RX_READ_CRC,
} rx_state_t;

static uint8_t rx_byte;                    // 1-byte DMA target
static uint8_t rx_buf[RX_BUF_SIZE];        // accumulation buffer
static uint8_t rx_pos;
static rx_state_t rx_state;
static uint16_t rx_payload_len;

static uint8_t rx_dispatch_buf[RX_BUF_SIZE]; // double-buffer for main loop
static uint16_t rx_dispatch_len;             // total packet length
static volatile bool rx_packet_ready;

static h2_relay_rx_callback_t rx_callback;

static void uart_rx_start(void);

static void uart_rx_cb(UARTDRV_Handle_t handle,
                        Ecode_t transferStatus,
                        uint8_t *data,
                        UARTDRV_Count_t transferCount)
{
  (void)handle;
  (void)transferCount;

  if (transferStatus != ECODE_EMDRV_UARTDRV_OK) {
    rx_state = RX_WAIT_SYNC;
    uart_rx_start();
    return;
  }

  uint8_t b = rx_byte;

  switch (rx_state) {
    case RX_WAIT_SYNC:
      if (b == 0x55) {
        rx_buf[0] = b;
        rx_pos = 1;
        rx_state = RX_READ_HEADER;
      }
      break;

    case RX_READ_HEADER:
      rx_buf[rx_pos++] = b;
      if (rx_pos >= 8) {
        // Validate header checksum: sum of bytes 0-7 == 0 mod 256
        uint8_t sum = 0;
        for (uint8_t i = 0; i < 8; i++) {
          sum += rx_buf[i];
        }
        if (sum != 0) {
          rx_state = RX_WAIT_SYNC;
          break;
        }
        rx_payload_len = ((uint16_t)rx_buf[5] << 8) | rx_buf[6];
        if (rx_payload_len > RX_MAX_PAYLOAD) {
          rx_state = RX_WAIT_SYNC;
          break;
        }
        if (rx_payload_len == 0) {
          rx_state = RX_READ_CRC;
        } else {
          rx_state = RX_READ_PAYLOAD;
        }
      }
      break;

    case RX_READ_PAYLOAD:
      rx_buf[rx_pos++] = b;
      if (rx_pos >= 8 + rx_payload_len) {
        rx_state = RX_READ_CRC;
      }
      break;

    case RX_READ_CRC:
      rx_buf[rx_pos++] = b;
      if (rx_pos >= 8 + rx_payload_len + 2) {
        // Validate CRC-16/MODBUS
        uint16_t pkt_len = 8 + rx_payload_len;
        uint16_t expected_crc = (uint16_t)rx_buf[pkt_len]
                              | ((uint16_t)rx_buf[pkt_len + 1] << 8);
        uint16_t calc_crc = crc16_modbus(rx_buf, pkt_len);
        if (calc_crc == expected_crc && !rx_packet_ready) {
          memcpy(rx_dispatch_buf, rx_buf, rx_pos);
          rx_dispatch_len = rx_pos;
          rx_packet_ready = true;
        }
        rx_state = RX_WAIT_SYNC;
      }
      break;
  }

  uart_rx_start();
}

static void uart_rx_start(void)
{
  UARTDRV_Receive(sl_uartdrv_eusart_wall_uart_handle, &rx_byte, 1, uart_rx_cb);
}

void h2_relay_set_rx_callback(h2_relay_rx_callback_t cb)
{
  rx_callback = cb;
}

void h2_relay_process_rx(void)
{
  set_service();
  if (!rx_packet_ready) {
    return;
  }
  set_on_frame(rx_dispatch_buf, rx_dispatch_len);

  // Log raw packet header + first bytes for debugging
  {
    uint16_t plen = ((uint16_t)rx_dispatch_buf[5] << 8) | rx_dispatch_buf[6];
    sl_zigbee_app_debug_print("RX PKT type=%02X%02X cmd=%02X plen=%d [",
                               rx_dispatch_buf[1], rx_dispatch_buf[2],
                               rx_dispatch_buf[4], plen);
    uint16_t dump = (plen < 24) ? plen : 24;
    for (uint16_t i = 0; i < dump; i++) {
      sl_zigbee_app_debug_print("%02X", rx_dispatch_buf[8 + i]);
    }
    sl_zigbee_app_debug_println("]");
  }

  h2_tap_record(1, rx_dispatch_buf, rx_dispatch_len);

  // Send ACK echoing the wall module's sequence number,
  // but only for measurement reports (cmd=0x05), not for wall ACKs (cmd=0x03)
  if (rx_dispatch_buf[4] == 0x05) {
    uint8_t ack_payload[3] = {0, 0, 0};
    uint8_t ack[FRAME_MAX];
    uint8_t ack_len = build_frame(ack, RELAY_TYPE, RELAY_CMD_QUERY, rx_dispatch_buf[3], ack_payload, 3);
    transmit_frame(ack, ack_len);
  }

  if (rx_callback != NULL) {
    uint16_t payload_len = ((uint16_t)rx_dispatch_buf[5] << 8) | rx_dispatch_buf[6];
    const uint8_t *payload = &rx_dispatch_buf[8];

    // Parse variable-length command entries from payload
    // Wire format: [cmd_hi(1), cmd_lo(1), marker(1), data(N)]
    // N determined by cmd_hi via DATA_TYPE_SIZE_LOOKUP
    uint16_t off = 0;
    while (off + 3 <= payload_len) {
      uint8_t cmd_hi = payload[off];
      uint8_t cmd_lo = payload[off + 1];
      uint8_t marker = payload[off + 2];

      // DATA_TYPE_SIZE_LOOKUP: cmd_hi → data size
      uint8_t data_size;
      switch (cmd_hi) {
        case 0x01: case 0x04: data_size = 1; break;
        case 0x00: case 0x02: case 0x03:
        case 0x05: case 0x06: data_size = 4; break;
        default:
          // Variable length: size in payload byte[3]
          if (off + 3 < payload_len) {
            data_size = payload[off + 3];
          } else {
            data_size = 0;  // can't determine size, will break below
          }
          break;
      }

      if (data_size == 0 || data_size > 8 || off + 3 + data_size > payload_len) break;

      // Data is big-endian on wire — byte-reverse for ARM little-endian
      uint8_t data_le[8];
      const uint8_t *src = &payload[off + 3];
      if (data_size == 4) {
        data_le[0] = src[3];
        data_le[1] = src[2];
        data_le[2] = src[1];
        data_le[3] = src[0];
      } else if (data_size == 1) {
        data_le[0] = src[0];
      } else {
        // Generic reverse
        for (uint8_t i = 0; i < data_size && i < sizeof(data_le); i++) {
          data_le[i] = src[data_size - 1 - i];
        }
      }

      uint16_t cmd_id = ((uint16_t)cmd_hi << 8) | cmd_lo;
      rx_callback(cmd_id, marker, data_le, data_size);

      off += 3 + data_size;
    }
  }

  rx_packet_ready = false;
}

void h2_relay_send_raw(uint16_t type, uint8_t cmd,
                       const uint8_t *payload, uint8_t payload_len)
{
  if (payload_len > 62) {
    return;
  }
  relay_send_packet(type, cmd, payload, payload_len);
}

// ---------------------------------------------------------------------------
// TX commands: init handshake + measurement query
// ---------------------------------------------------------------------------

void h2_relay_send_init(void)
{
  // Query 1: general status (type=0x0080, cmd=0x03, no payload)
  relay_send_packet(0x0080, RELAY_CMD_QUERY, NULL, 0);
  // Query 2: relay state (type=0x8001, cmd=0x03, no payload)
  relay_send_packet(0x8001, RELAY_CMD_QUERY, NULL, 0);

#if H2_HAS_DIMMER
  // Dimmer-specific init handshake — matches stock firmware UART_INIT sequence:
  // 1) INIT_QUERY_3: gang query + level + transition (off, level 0)
  {
    uint8_t q3[18] = {
      0x01, 0x00, 0x55, 0x00,                          // cmd 0x0100, marker 0x55, state=0
      0x00, 0x1A, 0x80, 0x00, 0x00, 0x00, 0x00,        // cmd 0x001A, marker 0x80, level=0
      0x00, 0x17, 0x80, 0x00, 0x00, 0x00, 0x00          // cmd 0x0017, marker 0x80, transition=0
    };
    relay_send_packet(RELAY_TYPE, RELAY_CMD_SET, q3, sizeof(q3));
  }
  // 2) + 3) are sent by h2_relay_configure_dimmer() from app.c after opple init
#endif
}

void h2_relay_send_measurement_query(uint8_t gang)
{
  (void)gang;  // Measurements are device-wide, not per output.
  // Stock READ requests contain only [cmd_hi, cmd_lo, marker], no value.
  const uint8_t payload[] = {
#if H2_HAS_DIMMER
    0x06, 0x00, 0x55,  // volts (not supported by the stock switch)
#endif
    0x06, 0x01, 0x55,  // milliamps
    0x06, 0x02, 0x55,  // watts
    0x06, 0x08, 0x55,  // degrees Celsius
  };
  relay_send_packet(RELAY_TYPE, RELAY_CMD_READ, payload, sizeof(payload));
}

// ---------------------------------------------------------------------------
// Dimmer level control
// ---------------------------------------------------------------------------

#if H2_HAS_DIMMER
static uint8_t dimmer_level[H2_SWITCH_GANG_COUNT];
static uint16_t on_off_transition_ms = 500;  // auto-set to 0 when min==max brightness

static uint8_t brightness_curve(uint8_t level)
{
  float f = (float)level / 254.0f;
  float d = f * f;  // gamma = 2.0
  int result = (int)(d * 254.0f);
  if (result < 1) result = 1;
  if (result > 254) result = 254;
  return (uint8_t)result;
}

void h2_relay_set_level(uint8_t gang, uint8_t level)
{
  if (gang >= h2_active_gang_count) return;
  if (level < 1) level = 1;
  if (level > 254) level = 254;
  if (dimmer_level[gang] == level) return;  // skip if unchanged
  dimmer_level[gang] = level;

  uint8_t phase = brightness_curve(level);

  // Level + fixed short transition for smooth stepping
  uint8_t payload[14];
  // Entry 1: level (cmd_id 0x001A, marker 0x80, 4-byte BE phase)
  payload[0]  = 0x00; payload[1]  = 0x1A; payload[2]  = 0x80;
  payload[3]  = 0x00; payload[4]  = 0x00; payload[5]  = 0x00; payload[6]  = phase;
  // Entry 2: transition (cmd_id 0x0017, marker 0x80, 100ms fixed)
  payload[7]  = 0x00; payload[8]  = 0x17; payload[9]  = 0x80;
  payload[10] = 0x00; payload[11] = 0x00; payload[12] = 0x00; payload[13] = 0x64;
  relay_send_packet(RELAY_TYPE, RELAY_CMD_SET, payload, sizeof(payload));
}

uint8_t h2_relay_get_level(uint8_t gang)
{
  if (gang >= h2_active_gang_count) return 0;
  return dimmer_level[gang];
}

void h2_relay_set_brightness_range(uint8_t min_pct, uint8_t max_pct)
{
  // Convert percentage (0-100) to phase value via brightness curve
  uint8_t min_phase = (min_pct > 0) ? brightness_curve(min_pct * 254 / 100) : 1;
  uint8_t max_phase = (max_pct < 100) ? brightness_curve(max_pct * 254 / 100) : 254;
  if (min_phase < 1) min_phase = 1;
  if (max_phase < min_phase) max_phase = min_phase;

  // When min == max brightness, on/off transition is pointless — make it instant
  on_off_transition_ms = (min_pct == max_pct) ? 0 : 500;

  uint8_t payload[14] = {
    0x00, 0x18, 0x80, 0x00, 0x00, 0x00, min_phase,
    0x00, 0x19, 0x80, 0x00, 0x00, 0x00, max_phase
  };
  relay_send_packet(RELAY_TYPE, RELAY_CMD_SET, payload, sizeof(payload));
}

void h2_relay_set_phase_mode(uint8_t mode)
{
  // Opple: 0=forward, 1=reverse → register: 0x00=leading edge, 0x01=trailing edge
  uint8_t reg_val = (mode == 1) ? 0x01 : 0x00;
  uint8_t payload[7] = {
    0x00, 0x1B, 0x80, 0x00, 0x00, 0x00, reg_val
  };
  relay_send_packet(RELAY_TYPE, RELAY_CMD_SET, payload, sizeof(payload));
}
#endif

// ---------------------------------------------------------------------------

void h2_relay_init(void)
{
  for (uint8_t i = 0; i < H2_SWITCH_GANG_COUNT; i++) {
    relay_state[i] = H2_RELAY_OFF;
#if H2_HAS_DIMMER
    dimmer_level[i] = 254;  // default to max brightness
#endif
  }
  GPIO_PinModeSet(WALL7_PORT, WALL7_PIN, gpioModePushPull, 1);
  GPIO_PinModeSet(WALL2_PORT, WALL2_PIN, gpioModePushPull, 1);
  GPIO_PinModeSet(WALL3_PORT, WALL3_PIN, gpioModeInputPull, 1);
  uart_rx_start();
}

// Payload of the relay command for a gang, from the state wanted now.
static uint8_t relay_set_payload(uint8_t gang, uint8_t *payload)
{
  h2_relay_state_t state = relay_state[gang];
  // Entry 1: output on/off (cmd_id 0x0100 + gang, marker 0x55, 1-byte state)
  payload[0] = 0x01;
  payload[1] = gang;
  payload[2] = 0x55;
  payload[3] = (state == H2_RELAY_ON) ? 0x01 : 0x00;
#if H2_HAS_DIMMER
  // The dimmer's wall module needs the output entry together with level and transition
  // to enable or disable the triac output.
  uint8_t phase = (state == H2_RELAY_ON) ? brightness_curve(dimmer_level[gang]) : 0x00;
  // Entry 2: level (cmd_id 0x001A, marker 0x80, 4-byte BE)
  payload[4]  = 0x00; payload[5]  = 0x1A; payload[6]  = 0x80;
  payload[7]  = 0x00; payload[8]  = 0x00; payload[9]  = 0x00; payload[10] = phase;
  // Entry 3: transition (cmd_id 0x0017, marker 0x80)
  payload[11] = 0x00; payload[12] = 0x17; payload[13] = 0x80;
  payload[14] = (uint8_t)(on_off_transition_ms >> 24);
  payload[15] = (uint8_t)(on_off_transition_ms >> 16);
  payload[16] = (uint8_t)(on_off_transition_ms >> 8);
  payload[17] = (uint8_t)(on_off_transition_ms);
  return 18;
#else
  return 4;
#endif
}

void h2_relay_set(uint8_t gang, h2_relay_state_t state)
{
  if (gang >= h2_active_gang_count) {
    return;
  }
  if (relay_state[gang] != state) set_changed[gang] = true;
  relay_state[gang] = state;
  relay_send_confirmed(gang);
}

h2_relay_state_t h2_relay_get(uint8_t gang)
{
  if (gang >= h2_active_gang_count) {
    return H2_RELAY_OFF;
  }
  return relay_state[gang];
}

h2_relay_state_t h2_relay_toggle(uint8_t gang)
{
  if (gang >= h2_active_gang_count) {
    return H2_RELAY_OFF;
  }
  h2_relay_state_t new_state = (relay_state[gang] == H2_RELAY_ON) ? H2_RELAY_OFF : H2_RELAY_ON;
  h2_relay_set(gang, new_state);
  return relay_state[gang];
}
