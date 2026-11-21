#include "app/framework/include/af.h"
#include "nvm3_default.h"
#include "em_gpio.h"

#include "h2_safe.h"
#include "h2_led_config.h"

#define NVM3_KEY_SAFE      0x0210   // Opple uses 0x0100..0x011F, power 0x0200, dimmer 0x0201
#define SAFE_TICK_MS       250

typedef struct {
  uint32_t version;
  uint8_t  fails;
} safe_record_t;

static safe_record_t record;
static bool safe_mode;
static uint32_t ticks;
static sl_zigbee_af_event_t safe_tick_event;

static void save_record(void)
{
  nvm3_writeData(nvm3_defaultHandle, NVM3_KEY_SAFE, &record, sizeof(record));
}

bool h2_safe_boot(uint32_t firmware_version)
{
  safe_record_t stored;
  if (nvm3_readData(nvm3_defaultHandle, NVM3_KEY_SAFE, &stored, sizeof(stored)) != ECODE_NVM3_OK
      || stored.version != firmware_version) {
    stored.version = firmware_version;
    stored.fails = 0;
  }
  record = stored;
  if (record.fails < 255) {
    record.fails++;
  }
  safe_mode = record.fails > H2_SAFE_FAIL_LIMIT;
  save_record();
  return safe_mode;
}

bool h2_safe_mode_active(void)
{
  return safe_mode;
}

uint8_t h2_safe_fail_count(void)
{
  return record.fails;
}

static void safe_tick_handler(sl_zigbee_af_event_t *event)
{
  ticks++;
  uint32_t seconds = ticks * SAFE_TICK_MS / 1000;

  if (!safe_mode) {
    if (seconds >= H2_SAFE_HEALTHY_S) {
      record.fails = 0;          // this boot counts as healthy
      save_record();
      return;                    // stop ticking
    }
  } else {
    GPIO_PinOutToggle(H2_LED_UP_R_PORT, H2_LED_UP_R_PIN);
    if (seconds >= (uint32_t)H2_SAFE_EXIT_MIN * 60) {
      record.fails = 0;          // give normal mode another try
      save_record();
      halReboot();
    }
  }
  sl_zigbee_af_event_set_delay_ms(event, SAFE_TICK_MS);
}

void h2_safe_start(void)
{
  if (safe_mode) {
    GPIO_PinModeSet(H2_LED_UP_R_PORT, H2_LED_UP_R_PIN, gpioModePushPull, 0);
  }
  sl_zigbee_af_event_init(&safe_tick_event, safe_tick_handler);
  sl_zigbee_af_event_set_delay_ms(&safe_tick_event, SAFE_TICK_MS);
}
