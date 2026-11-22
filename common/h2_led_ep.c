#include "app/framework/include/af.h"

#include "h2_led_ep.h"
#include "h2_led.h"
#include "h2_variant.h"
#include "h2_led_config.h"
#include "nvm3_default.h"

#define ZCL_COLOR_ATTR_HUE   0x0000
#define ZCL_COLOR_ATTR_SAT   0x0001
#define ZCL_COLOR_ATTR_X     0x0003
#define ZCL_COLOR_ATTR_Y     0x0004
#define ZCL_COLOR_ATTR_MODE  0x0008
#define ZCL_COLOR_ATTR_EMODE 0x4001
#define COLOR_MODE_HUE_SAT   0
#define COLOR_MODE_XY        1

#define NVM3_KEY_LED_EP     0x0230
#define LED_EP_MAX          4
#define SAVE_DELAY_MS       2000     // after the last change; limits flash writes from sliders
#define RESTORE_DELAY_MS    1500     // after boot, when the attribute tables exist

typedef struct {
  uint8_t manual;
  uint8_t on;
  uint8_t level;
  uint8_t hue;
  uint8_t sat;
  uint8_t mode;       // colour mode last used by the hub, so read-back matches after a restart
  uint16_t x;
  uint16_t y;
} led_setting_t;

static led_setting_t settings[LED_EP_MAX];
static bool restoring;
static sl_zigbee_af_event_t save_event;
static sl_zigbee_af_event_t restore_event;

extern uint8_t h2_active_gang_count;

// LEDs that exist on this plate: one per gang, or two (up and down) on the switch.
uint8_t h2_led_ep_count(void)
{
#if H2_LED_HAS_DN
  return (uint8_t)(h2_active_gang_count * 2);
#else
  return h2_active_gang_count;
#endif
}

static bool led_from_endpoint(uint8_t endpoint, uint8_t *led)
{
  if (endpoint < H2_LED_EP_FIRST || endpoint >= H2_LED_EP_FIRST + h2_led_ep_count()) {
    return false;
  }
  *led = (uint8_t)(endpoint - H2_LED_EP_FIRST);
  return true;
}

static void led_position(uint8_t led, uint8_t *gang, h2_led_position_t *pos)
{
#if H2_LED_HAS_DN
  *gang = led / 2;
  *pos = (led & 1) ? H2_LED_DOWN : H2_LED_UP;
#else
  *gang = led;
  *pos = H2_LED_UP;
#endif
}

static uint8_t read_u8(uint8_t endpoint, uint16_t cluster, uint16_t attr, uint8_t fallback)
{
  uint8_t value = fallback;
  if (sl_zigbee_af_read_server_attribute(endpoint, cluster, attr, &value, sizeof(value))
      != SL_ZIGBEE_ZCL_STATUS_SUCCESS) {
    return fallback;
  }
  return value;
}

static void write_u8(uint8_t endpoint, uint16_t cluster, uint16_t attr, uint8_t value, uint8_t type)
{
  (void)sl_zigbee_af_write_server_attribute(endpoint, cluster, attr, &value, type);
}

// Hue 0-254 (0 = red, 85 = green, 169 = blue) and saturation 0-254 to red/blue 0-255.
// Blue -> magenta -> red is the real colour arc. Hues on the green side, which the LED
// cannot show, are spread linearly between red and blue so every hue gives some mix.
static void hue_sat_to_channels(uint8_t hue, uint8_t sat, uint8_t *red, uint8_t *blue)
{
  uint16_t r, b;
  if (hue < 169) {                     // red .. (green) .. blue
    b = (uint16_t)hue * 255 / 169;
    r = 255 - b;
  } else {                             // blue .. magenta .. red
    r = (uint16_t)(hue - 169) * 255 / (254 - 169);
    b = 255 - r;
  }
  // Normalise so the stronger channel is at full, then desaturate towards both on.
  uint16_t top = (r > b) ? r : b;
  if (top == 0) top = 1;
  r = r * 255 / top;
  b = b * 255 / top;
  r = r + (uint16_t)(255 - r) * (254 - sat) / 254;
  b = b + (uint16_t)(255 - b) * (254 - sat) / 254;
  *red = (uint8_t)r;
  *blue = (uint8_t)b;
}

static void write_u16(uint8_t endpoint, uint16_t cluster, uint16_t attr, uint16_t value)
{
  (void)sl_zigbee_af_write_server_attribute(endpoint, cluster, attr, (uint8_t *)&value,
                                            ZCL_INT16U_ATTRIBUTE_TYPE);
}

static uint16_t read_u16(uint8_t endpoint, uint16_t cluster, uint16_t attr)
{
  uint16_t value = 0;
  (void)sl_zigbee_af_read_server_attribute(endpoint, cluster, attr, (uint8_t *)&value, sizeof(value));
  return value;
}

static void set_color_mode(uint8_t endpoint, uint8_t mode)
{
  write_u8(endpoint, ZCL_COLOR_CONTROL_CLUSTER_ID, ZCL_COLOR_ATTR_MODE, mode, ZCL_ENUM8_ATTRIBUTE_TYPE);
  write_u8(endpoint, ZCL_COLOR_CONTROL_CLUSTER_ID, ZCL_COLOR_ATTR_EMODE, mode, ZCL_ENUM8_ATTRIBUTE_TYPE);
}

// CIE xy (0-65535 each, as in Move to Color) to hue and saturation 0-254. Some hubs (ZHA)
// only send xy. The colour is converted to RGB with the sRGB matrix and then to hue and
// saturation, so both command families end in the same red/blue mix.
static void xy_to_hue_sat(uint16_t cx, uint16_t cy, uint8_t *hue, uint8_t *sat)
{
  float x = (float)cx / 65535.0f, y = (float)cy / 65535.0f;
  if (y < 0.001f) y = 0.001f;
  float X = x / y, Z = (1.0f - x - y) / y;
  float r =  3.2406f * X - 1.5372f - 0.4986f * Z;
  float g = -0.9689f * X + 1.8758f + 0.0415f * Z;
  float b =  0.0557f * X - 0.2040f + 1.0570f * Z;
  if (r < 0) r = 0;
  if (g < 0) g = 0;
  if (b < 0) b = 0;
  float max = r > g ? (r > b ? r : b) : (g > b ? g : b);
  float min = r < g ? (r < b ? r : b) : (g < b ? g : b);
  float delta = max - min;
  if (max <= 0.0f || delta <= 0.0f) {
    *hue = 0;
    *sat = 0;
    return;
  }
  float h;                                   // 0..6
  if (max == r)      h = (g - b) / delta + (g < b ? 6.0f : 0.0f);
  else if (max == g) h = (b - r) / delta + 2.0f;
  else               h = (r - g) / delta + 4.0f;
  *hue = (uint8_t)(h * 254.0f / 6.0f + 0.5f);
  *sat = (uint8_t)(delta / max * 254.0f + 0.5f);
  if (g <= r && g <= b) {
    // On the red-blue side, which is all this LED can show, take the position between
    // the blue and red primaries directly. Hubs differ in the RGB space they convert
    // from, and the matrix alone puts magenta visibly off centre.
    float t = (x - 0.136f) / (0.701f - 0.136f);
    if (t < 0) t = 0;
    if (t > 1) t = 1;
    *hue = (uint8_t)(169.0f + t * 85.0f + 0.5f);
  }
}

static void apply_endpoint(uint8_t endpoint)
{
  uint8_t led;
  if (!led_from_endpoint(endpoint, &led)) return;
  uint8_t gang; h2_led_position_t pos;
  led_position(led, &gang, &pos);

  uint8_t on    = read_u8(endpoint, ZCL_ON_OFF_CLUSTER_ID, ZCL_ON_OFF_ATTRIBUTE_ID, 0);
  uint8_t level = read_u8(endpoint, ZCL_LEVEL_CONTROL_CLUSTER_ID, ZCL_CURRENT_LEVEL_ATTRIBUTE_ID, 254);
  uint8_t hue   = read_u8(endpoint, ZCL_COLOR_CONTROL_CLUSTER_ID, ZCL_COLOR_ATTR_HUE, 0);
  uint8_t sat   = read_u8(endpoint, ZCL_COLOR_CONTROL_CLUSTER_ID, ZCL_COLOR_ATTR_SAT, 254);

  if (level == 0) {
    // The level attribute starts at 0 after boot; a light that is on at level 0 would
    // look broken, so treat it as full and make the attribute say so.
    level = 254;
    write_u8(endpoint, ZCL_LEVEL_CONTROL_CLUSTER_ID, ZCL_CURRENT_LEVEL_ATTRIBUTE_ID, level,
             ZCL_INT8U_ATTRIBUTE_TYPE);
  }

  uint8_t red = 0, blue = 0;
  if (on) {
    hue_sat_to_channels(hue, sat, &red, &blue);
    red  = (uint8_t)((uint16_t)red  * level / 254);
    blue = (uint8_t)((uint16_t)blue * level / 254);
  }
  if (led < LED_EP_MAX) {
    led_setting_t now;
    memset(&now, 0, sizeof(now));              // padding too: the struct is compared and stored
    now.manual = 1; now.on = on; now.level = level; now.hue = hue; now.sat = sat;
    now.mode = read_u8(endpoint, ZCL_COLOR_CONTROL_CLUSTER_ID, ZCL_COLOR_ATTR_MODE, COLOR_MODE_HUE_SAT);
    now.x = read_u16(endpoint, ZCL_COLOR_CONTROL_CLUSTER_ID, ZCL_COLOR_ATTR_X);
    now.y = read_u16(endpoint, ZCL_COLOR_CONTROL_CLUSTER_ID, ZCL_COLOR_ATTR_Y);
    if (memcmp(&settings[led], &now, sizeof(now)) != 0) {
      settings[led] = now;
      if (!restoring) {
        sl_zigbee_af_event_set_delay_ms(&save_event, SAVE_DELAY_MS);
      }
    }
  }
  h2_led_override_set(gang, pos, red, blue);
  sl_zigbee_app_debug_println("LED %d: on=%d level=%d hue=%d sat=%d -> red %d blue %d",
                               led, on, level, hue, sat, red, blue);
}

void h2_led_ep_attribute_changed(uint8_t endpoint, uint16_t cluster_id)
{
  uint8_t led;
  if (!led_from_endpoint(endpoint, &led)) return;
  if (cluster_id == ZCL_ON_OFF_CLUSTER_ID
      || cluster_id == ZCL_LEVEL_CONTROL_CLUSTER_ID
      || cluster_id == ZCL_COLOR_CONTROL_CLUSTER_ID) {
    apply_endpoint(endpoint);
  }
}

bool h2_led_ep_command(sl_zigbee_af_cluster_command_t *cmd)
{
  uint8_t endpoint = cmd->apsFrame->destinationEndpoint;
  uint8_t led;
  if (!led_from_endpoint(endpoint, &led)
      || !cmd->clusterSpecific || cmd->mfgSpecific
      || cmd->direction != ZCL_DIRECTION_CLIENT_TO_SERVER) {
    return false;
  }
  const uint8_t *p = cmd->buffer + cmd->payloadStartIndex;
  uint16_t len = (uint16_t)(cmd->bufLen - cmd->payloadStartIndex);
  uint16_t cluster = cmd->apsFrame->clusterId;

  if (cluster == ZCL_LEVEL_CONTROL_CLUSTER_ID) {
    // Move to Level (0x00) and Move to Level with On/Off (0x04): level, transition time.
    // Transitions are not timed; the LED driver fades by itself.
    if ((cmd->commandId != 0x00 && cmd->commandId != 0x04) || len < 1) return false;
    uint8_t level = p[0];
    if (cmd->commandId == 0x04) {
      write_u8(endpoint, ZCL_ON_OFF_CLUSTER_ID, ZCL_ON_OFF_ATTRIBUTE_ID, level > 0 ? 1 : 0,
               ZCL_BOOLEAN_ATTRIBUTE_TYPE);
    }
    if (level > 0) {
      write_u8(endpoint, ZCL_LEVEL_CONTROL_CLUSTER_ID, ZCL_CURRENT_LEVEL_ATTRIBUTE_ID,
               level > 254 ? 254 : level, ZCL_INT8U_ATTRIBUTE_TYPE);
    }
  } else if (cluster == ZCL_COLOR_CONTROL_CLUSTER_ID) {
    if (cmd->commandId == 0x07 && len >= 4) {            // Move to Color (xy)
      uint16_t cx = (uint16_t)(p[0] | ((uint16_t)p[1] << 8));
      uint16_t cy = (uint16_t)(p[2] | ((uint16_t)p[3] << 8));
      uint8_t hue, sat;
      xy_to_hue_sat(cx, cy, &hue, &sat);
      write_u16(endpoint, cluster, ZCL_COLOR_ATTR_X, cx);
      write_u16(endpoint, cluster, ZCL_COLOR_ATTR_Y, cy);
      write_u8(endpoint, cluster, ZCL_COLOR_ATTR_HUE, hue, ZCL_INT8U_ATTRIBUTE_TYPE);
      write_u8(endpoint, cluster, ZCL_COLOR_ATTR_SAT, sat, ZCL_INT8U_ATTRIBUTE_TYPE);
      set_color_mode(endpoint, COLOR_MODE_XY);
    } else if (cmd->commandId == 0x00 && len >= 1) {     // Move to Hue
      set_color_mode(endpoint, COLOR_MODE_HUE_SAT);
      write_u8(endpoint, cluster, ZCL_COLOR_ATTR_HUE, p[0], ZCL_INT8U_ATTRIBUTE_TYPE);
    } else if (cmd->commandId == 0x03 && len >= 1) {     // Move to Saturation
      set_color_mode(endpoint, COLOR_MODE_HUE_SAT);
      write_u8(endpoint, cluster, ZCL_COLOR_ATTR_SAT, p[0], ZCL_INT8U_ATTRIBUTE_TYPE);
    } else if (cmd->commandId == 0x06 && len >= 2) {     // Move to Hue and Saturation
      set_color_mode(endpoint, COLOR_MODE_HUE_SAT);
      write_u8(endpoint, cluster, ZCL_COLOR_ATTR_HUE, p[0], ZCL_INT8U_ATTRIBUTE_TYPE);
      write_u8(endpoint, cluster, ZCL_COLOR_ATTR_SAT, p[1], ZCL_INT8U_ATTRIBUTE_TYPE);
    } else {
      return false;
    }
  } else {
    return false;      // On/Off commands go through the framework's On/Off handling
  }

  apply_endpoint(endpoint);
  sl_zigbee_af_send_default_response(cmd, SL_ZIGBEE_ZCL_STATUS_SUCCESS);
  return true;
}

void h2_led_ep_set_channels(uint8_t led, uint8_t red, uint8_t blue)
{
  if (led >= h2_led_ep_count()) return;
  uint8_t gang; h2_led_position_t pos;
  led_position(led, &gang, &pos);
  h2_led_override_set(gang, pos, red, blue);
}

void h2_led_ep_release(uint8_t led)
{
  if (led >= h2_led_ep_count()) return;
  uint8_t gang; h2_led_position_t pos;
  led_position(led, &gang, &pos);
  h2_led_override_clear(gang, pos);
  if (led < LED_EP_MAX && settings[led].manual) {
    settings[led].manual = 0;
    sl_zigbee_af_event_set_delay_ms(&save_event, SAVE_DELAY_MS);
  }
}

static void save_handler(sl_zigbee_af_event_t *event)
{
  (void)event;
  nvm3_writeData(nvm3_defaultHandle, NVM3_KEY_LED_EP, settings, sizeof(settings));
  sl_zigbee_app_debug_println("LED settings saved");
}

static void restore_handler(sl_zigbee_af_event_t *event)
{
  (void)event;
  led_setting_t stored[LED_EP_MAX];
  if (nvm3_readData(nvm3_defaultHandle, NVM3_KEY_LED_EP, stored, sizeof(stored)) != ECODE_NVM3_OK) {
    return;                       // nothing saved: every LED stays automatic
  }
  restoring = true;
  for (uint8_t led = 0; led < h2_led_ep_count() && led < LED_EP_MAX; led++) {
    if (!stored[led].manual) continue;
    uint8_t endpoint = (uint8_t)(H2_LED_EP_FIRST + led);
    write_u8(endpoint, ZCL_COLOR_CONTROL_CLUSTER_ID, ZCL_COLOR_ATTR_HUE, stored[led].hue, ZCL_INT8U_ATTRIBUTE_TYPE);
    write_u8(endpoint, ZCL_COLOR_CONTROL_CLUSTER_ID, ZCL_COLOR_ATTR_SAT, stored[led].sat, ZCL_INT8U_ATTRIBUTE_TYPE);
    write_u16(endpoint, ZCL_COLOR_CONTROL_CLUSTER_ID, ZCL_COLOR_ATTR_X, stored[led].x);
    write_u16(endpoint, ZCL_COLOR_CONTROL_CLUSTER_ID, ZCL_COLOR_ATTR_Y, stored[led].y);
    set_color_mode(endpoint, stored[led].mode <= COLOR_MODE_XY ? stored[led].mode : COLOR_MODE_HUE_SAT);
    write_u8(endpoint, ZCL_LEVEL_CONTROL_CLUSTER_ID, ZCL_CURRENT_LEVEL_ATTRIBUTE_ID, stored[led].level, ZCL_INT8U_ATTRIBUTE_TYPE);
    write_u8(endpoint, ZCL_ON_OFF_CLUSTER_ID, ZCL_ON_OFF_ATTRIBUTE_ID, stored[led].on, ZCL_BOOLEAN_ATTRIBUTE_TYPE);
    apply_endpoint(endpoint);
    sl_zigbee_app_debug_println("LED %d: restored saved setting", led);
  }
  restoring = false;
}

void h2_led_ep_init(void)
{
  sl_zigbee_af_event_init(&save_event, save_handler);
  sl_zigbee_af_event_init(&restore_event, restore_handler);
  sl_zigbee_af_event_set_delay_ms(&restore_event, RESTORE_DELAY_MS);
}

bool h2_led_ep_attr_get(uint16_t attr_id, uint32_t *value)
{
  if (attr_id != H2_LED_EP_ATTR_MANUAL) return false;
  uint32_t mask = 0;
  for (uint8_t led = 0; led < h2_led_ep_count(); led++) {
    uint8_t gang; h2_led_position_t pos;
    led_position(led, &gang, &pos);
    if (h2_led_override_active(gang, pos)) mask |= (1UL << led);
  }
  *value = mask;
  return true;
}

bool h2_led_ep_attr_set(uint16_t attr_id, uint32_t value)
{
  if (attr_id != H2_LED_EP_ATTR_MANUAL) return false;
  for (uint8_t led = 0; led < h2_led_ep_count(); led++) {
    if (value & (1UL << led)) {
      apply_endpoint((uint8_t)(H2_LED_EP_FIRST + led));   // manual, from the endpoint's state
    } else {
      h2_led_ep_release(led);
    }
  }
  return true;
}
