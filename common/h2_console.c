#include "h2_build.h"
#include "h2_console.h"

#if H2_BENCH

#include "app/framework/include/af.h"
#include "em_cmu.h"
#include "em_eusart.h"
#include "em_gpio.h"
#include "sl_iostream.h"
#include "sl_cli_instances.h"
#include "sl_cli_handles.h"
#include "sl_power_manager.h"
#include "sl_cli.h"
#include "sl_sleeptimer.h"
#include "btl_interface.h"
#include "h2_variant.h"
#if H2_HAS_RULES
#include "h2_rules.h"
#endif

#define CON_TX_PORT   gpioPortB
#define CON_TX_PIN    0
#define CON_RX_PORT   gpioPortA
#define CON_RX_PIN    7
#define RX_RING       1024          // power of two; must hold one loader chunk

static volatile uint8_t rx_ring[RX_RING];
static volatile uint16_t rx_head;   // written by the interrupt
static uint16_t rx_tail;

void EUSART0_RX_IRQHandler(void)
{
  while (EUSART0->STATUS & EUSART_STATUS_RXFL) {
    uint8_t b = (uint8_t)EUSART0->RXDATA;
    uint16_t next = (uint16_t)((rx_head + 1) & (RX_RING - 1));
    if (next != rx_tail) {
      rx_ring[rx_head] = b;
      rx_head = next;
    }
  }
  EUSART_IntClear(EUSART0, EUSART_IF_RXFL);
}

static sl_status_t con_write(void *context, const void *buffer, size_t length)
{
  (void)context;
  const uint8_t *p = (const uint8_t *)buffer;
  for (size_t i = 0; i < length; i++) {
    EUSART_Tx(EUSART0, p[i]);       // blocking, about 87 us per byte
  }
  return SL_STATUS_OK;
}

static sl_status_t con_read(void *context, void *buffer, size_t length, size_t *bytes_read)
{
  (void)context;
  uint8_t *p = (uint8_t *)buffer;
  size_t n = 0;
  while (n < length && rx_tail != rx_head) {
    p[n++] = rx_ring[rx_tail];
    rx_tail = (uint16_t)((rx_tail + 1) & (RX_RING - 1));
  }
  *bytes_read = n;
  return n ? SL_STATUS_OK : SL_STATUS_EMPTY;
}

static sl_iostream_t console_stream = {
  .write = con_write,
  .read  = con_read,
};

// ---------------------------------------------------------------------------
// Serial image loader: console command "h2load <size>".
//
// Receives a GBL upgrade image (the same file Zigbee OTA wraps) over the console, writes
// it to bootloader storage slot 0 and tells the bootloader to install it. Works in safe
// mode too. The main loop is blocked while it runs.
//
//   host: "h2load <size>\r\n"
//   fw:   erases the slot, then prints "\nH2LOAD READY\n"
//   host: chunks of [len lo][len hi][data, len a multiple of 4, at most 256][crc lo][crc hi]
//         (CRC-16/MODBUS over the data); fw answers 'K' (written) or 'N' (resend)
//   host: a zero-length chunk ends the transfer
//   fw:   "\nH2LOAD DONE\n" and reboots into the bootloader, or "\nH2LOAD FAIL <reason>\n"
// ---------------------------------------------------------------------------

#define LOAD_CHUNK_MAX   256
#define LOAD_TIMEOUT_MS  3000

static uint16_t load_crc16(const uint8_t *data, uint32_t len)
{
  uint16_t crc = 0xFFFF;
  for (uint32_t i = 0; i < len; i++) {
    crc ^= data[i];
    for (uint8_t b = 0; b < 8; b++) {
      crc = (crc & 1) ? (uint16_t)((crc >> 1) ^ 0xA001) : (uint16_t)(crc >> 1);
    }
  }
  return crc;
}

// Read exactly n bytes from the console; false on timeout.
static bool load_read(uint8_t *out, uint32_t n)
{
  uint32_t start = sl_sleeptimer_get_tick_count();
  uint32_t got = 0;
  while (got < n) {
    if (rx_tail != rx_head) {
      out[got++] = rx_ring[rx_tail];
      rx_tail = (uint16_t)((rx_tail + 1) & (RX_RING - 1));
      start = sl_sleeptimer_get_tick_count();
    } else {
      halResetWatchdog();
      if (sl_sleeptimer_tick_to_ms(sl_sleeptimer_get_tick_count() - start) > LOAD_TIMEOUT_MS) {
        return false;
      }
    }
  }
  return true;
}

static void load_say(const char *text)
{
  con_write(NULL, text, strlen(text));
}

static void cmd_h2load(sl_cli_command_arg_t *arguments)
{
  static uint8_t chunk[LOAD_CHUNK_MAX];
  uint32_t size = sl_cli_get_argument_uint32(arguments, 0);
  uint32_t offset = 0;

  halResetWatchdog();
  if (bootloader_eraseStorageSlot(0) != BOOTLOADER_OK) {
    load_say("\nH2LOAD FAIL erase\n");
    return;
  }
  halResetWatchdog();
  rx_tail = rx_head;                       // drop anything typed before this point
  load_say("\nH2LOAD READY\n");

  for (;;) {
    uint8_t hdr[2], crc[2];
    if (!load_read(hdr, 2)) { load_say("\nH2LOAD FAIL timeout\n"); return; }
    uint16_t len = (uint16_t)(hdr[0] | (hdr[1] << 8));
    if (len == 0) break;
    if (len > LOAD_CHUNK_MAX || (len & 3)) { load_say("\nH2LOAD FAIL length\n"); return; }
    if (!load_read(chunk, len) || !load_read(crc, 2)) { load_say("\nH2LOAD FAIL timeout\n"); return; }
    if (load_crc16(chunk, len) != (uint16_t)(crc[0] | (crc[1] << 8))) {
      rx_tail = rx_head;
      load_say("N");
      continue;
    }
    if (bootloader_writeStorage(0, offset, chunk, len) != BOOTLOADER_OK) {
      load_say("\nH2LOAD FAIL write\n");
      return;
    }
    offset += len;
    halResetWatchdog();
    load_say("K");
  }

  if (offset < size) { load_say("\nH2LOAD FAIL short\n"); return; }
  if (bootloader_setImageToBootload(0) != BOOTLOADER_OK) { load_say("\nH2LOAD FAIL set\n"); return; }
  load_say("\nH2LOAD DONE\n");
  bootloader_rebootAndInstall();
}

static const sl_cli_command_info_t cmd_h2load_info =
  SL_CLI_COMMAND(cmd_h2load,
                 "Receive a GBL image over the console and install it",
                 "image size in bytes",
                 { SL_CLI_ARG_UINT32, SL_CLI_ARG_END, });

// "h2pin <port> <pin> <mode>": drive one processor pin, to find out what it is wired to.
// port 0-3 = A-D; mode 0 = released (disabled), 1 = driven low, 2 = driven high. The pin
// Pins used by SWD, the wall UART and this console are refused.
static void cmd_h2pin(sl_cli_command_arg_t *arguments)
{
  uint8_t port = sl_cli_get_argument_uint8(arguments, 0);
  uint8_t pin = sl_cli_get_argument_uint8(arguments, 1);
  uint8_t mode = sl_cli_get_argument_uint8(arguments, 2);
  bool reserved = (port == 0 && (pin == 1 || pin == 2 || pin == 5 || pin == 6 || pin == 7))
                  || (port == 1 && pin == 0);
  if (port > 3 || pin > 9 || mode > 2 || reserved) {
    sl_zigbee_app_debug_println("h2pin: refused");
    return;
  }
  if (mode == 0) {
    GPIO_PinModeSet((GPIO_Port_TypeDef)port, pin, gpioModeDisabled, 0);
  } else {
    GPIO_PinModeSet((GPIO_Port_TypeDef)port, pin, gpioModePushPull, mode == 2 ? 1 : 0);
  }
  sl_zigbee_app_debug_println("h2pin: P%c%d %s", 'A' + port, pin,
                               mode == 0 ? "released" : (mode == 1 ? "low" : "high"));
}

static const sl_cli_command_info_t cmd_h2pin_info =
  SL_CLI_COMMAND(cmd_h2pin,
                 "Drive a processor pin: port(0-3=A-D) pin mode(0 release, 1 low, 2 high)",
                 "port" SL_CLI_UNIT_SEPARATOR "pin" SL_CLI_UNIT_SEPARATOR "mode",
                 { SL_CLI_ARG_UINT8, SL_CLI_ARG_UINT8, SL_CLI_ARG_UINT8, SL_CLI_ARG_END, });

#if H2_HAS_RULES
// Rule program upload and test commands:
//   h2rb <bytes>      begin an upload
//   h2rd {hex}        append data
//   h2rc              verify, store and activate
//   h2rx              erase the stored program
//   h2ri              print state
//   h2ev <source> <type> <value>   inject an event
static void cmd_h2rb(sl_cli_command_arg_t *arguments)
{
  bool ok = h2_rules_upload_begin(sl_cli_get_argument_uint16(arguments, 0));
  sl_zigbee_app_debug_println("h2rb %s", ok ? "ok" : "refused");
}
static void cmd_h2rd(sl_cli_command_arg_t *arguments)
{
  size_t len = 0;
  uint8_t *data = sl_cli_get_argument_hex(arguments, 0, &len);
  bool ok = h2_rules_upload_data(data, (uint16_t)len);
  sl_zigbee_app_debug_println("h2rd %s %d", ok ? "ok" : "refused", (int)len);
}
static void cmd_h2rc(sl_cli_command_arg_t *arguments)
{
  (void)arguments;
  uint32_t detail = 0;
  uint8_t result = h2_rules_upload_commit(&detail);
  sl_zigbee_app_debug_println("h2rc result %d detail %lu", result, (unsigned long)detail);
}
static void cmd_h2rx(sl_cli_command_arg_t *arguments)
{
  (void)arguments;
  h2_rules_erase();
}
static void cmd_h2ri(sl_cli_command_arg_t *arguments)
{
  (void)arguments;
  h2_rules_print_info();
}
static void cmd_h2ev(sl_cli_command_arg_t *arguments)
{
  bool handled = h2_rules_event(sl_cli_get_argument_uint8(arguments, 0),
                                sl_cli_get_argument_uint8(arguments, 1),
                                sl_cli_get_argument_int32(arguments, 2));
  sl_zigbee_app_debug_println("h2ev handled=%d", handled);
}
static const sl_cli_command_info_t cmd_h2rb_info =
  SL_CLI_COMMAND(cmd_h2rb, "Begin a rule program upload", "bytes", { SL_CLI_ARG_UINT16, SL_CLI_ARG_END, });
static const sl_cli_command_info_t cmd_h2rd_info =
  SL_CLI_COMMAND(cmd_h2rd, "Append rule program data", "hex", { SL_CLI_ARG_HEX, SL_CLI_ARG_END, });
static const sl_cli_command_info_t cmd_h2rc_info =
  SL_CLI_COMMAND(cmd_h2rc, "Verify, store and activate the uploaded rule program", "", { SL_CLI_ARG_END, });
static const sl_cli_command_info_t cmd_h2rx_info =
  SL_CLI_COMMAND(cmd_h2rx, "Erase the rule program", "", { SL_CLI_ARG_END, });
static const sl_cli_command_info_t cmd_h2ri_info =
  SL_CLI_COMMAND(cmd_h2ri, "Rule engine state", "", { SL_CLI_ARG_END, });
static const sl_cli_command_info_t cmd_h2ev_info =
  SL_CLI_COMMAND(cmd_h2ev, "Inject a rule event", "source" SL_CLI_UNIT_SEPARATOR "type" SL_CLI_UNIT_SEPARATOR "value",
                 { SL_CLI_ARG_UINT8, SL_CLI_ARG_UINT8, SL_CLI_ARG_INT32, SL_CLI_ARG_END, });
#endif

static const sl_cli_command_entry_t h2_command_table[] = {
#if H2_HAS_RULES
  { "h2rb", &cmd_h2rb_info, false },
  { "h2rd", &cmd_h2rd_info, false },
  { "h2rc", &cmd_h2rc_info, false },
  { "h2rx", &cmd_h2rx_info, false },
  { "h2ri", &cmd_h2ri_info, false },
  { "h2ev", &cmd_h2ev_info, false },
#endif
  { "h2pin", &cmd_h2pin_info, false },
  { "h2load", &cmd_h2load_info, false },
  { NULL, NULL, false },
};

static sl_cli_command_group_t h2_command_group = {
  { NULL },
  false,
  h2_command_table
};

void h2_console_init(void)
{
  CMU_ClockEnable(cmuClock_GPIO, true);
  CMU_ClockEnable(cmuClock_EUSART0, true);

  GPIO_PinModeSet(CON_TX_PORT, CON_TX_PIN, gpioModePushPull, 1);
  GPIO_PinModeSet(CON_RX_PORT, CON_RX_PIN, gpioModeInputPull, 1);
  GPIO->EUSARTROUTE[0].TXROUTE = (CON_TX_PORT << _GPIO_EUSART_TXROUTE_PORT_SHIFT)
                               | (CON_TX_PIN << _GPIO_EUSART_TXROUTE_PIN_SHIFT);
  GPIO->EUSARTROUTE[0].RXROUTE = (CON_RX_PORT << _GPIO_EUSART_RXROUTE_PORT_SHIFT)
                               | (CON_RX_PIN << _GPIO_EUSART_RXROUTE_PIN_SHIFT);
  GPIO->EUSARTROUTE[0].ROUTEEN = GPIO_EUSART_ROUTEEN_TXPEN | GPIO_EUSART_ROUTEEN_RXPEN;

  EUSART_UartInit_TypeDef init = EUSART_UART_INIT_DEFAULT_HF;
  init.baudrate = 115200;
  EUSART_UartInitHf(EUSART0, &init);

  EUSART_IntClear(EUSART0, EUSART_IF_RXFL);
  EUSART_IntEnable(EUSART0, EUSART_IEN_RXFL);
  NVIC_ClearPendingIRQ(EUSART0_RX_IRQn);
  NVIC_EnableIRQ(EUSART0_RX_IRQn);

  // The high-frequency clock must stay on for the console to work.
  sl_power_manager_add_em_requirement(SL_POWER_MANAGER_EM1);

  sl_iostream_set_default(&console_stream);
  sl_cli_example_handle->iostream_handle = &console_stream;
  sl_cli_command_add_command_group(sl_cli_example_handle, &h2_command_group);

  sl_zigbee_app_debug_println("");
  sl_zigbee_app_debug_println("H2 bench console ready");
}

#else  // !H2_BENCH

void h2_console_init(void)
{
}

#endif
