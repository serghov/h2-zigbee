// Bedroom: a 2-button switch whose relay feeds three Zigbee ceiling bulbs. The relay must
// stay on so the bulbs always have mains; the buttons only talk to the bulbs. These rules
// never touch the relay: the buttons are taken over so the firmware does not switch it,
// and the switch's power-on setting ("On") brings it up after a power cut.
//
//   upper button   Day mode: full brightness, cool light. Again while in Day: off.
//   lower button   Night mode: 60 %, warm light. Again while in Night: off.
//   Pressing the other button while the bulbs are on switches mode.
//
//   upper LED      purple in Day mode        lower LED      purple in Night mode
//   Both dark when the bulbs are off.
//
// The switch remembers the mode itself; it cannot see the bulbs. If something else turns
// them off, the next press of the same button turns them "off" again (nothing visible)
// and the one after that turns them on. The other button always works at once.
//
// The bulbs are switched with commands that skip their fade (IKEA bulbs fade on the plain
// On and Off commands whatever their transition setting says).
#include "../h2_rules.h"

#define GROUP         16              // Zigbee group with the ceiling bulbs
#define UPPER         H2_SRC_BUTTON(0)
#define LOWER         H2_SRC_BUTTON(1)
#define LED_UPPER     0
#define LED_LOWER     1

#define DAY_LEVEL     254             // 100 %
#define DAY_MIREDS    250             // 4000 K
#define NIGHT_LEVEL   152             // 60 %
#define NIGHT_MIREDS  454             // 2200 K

#define VAR_MODE      0               // MODE_*
#define MODE_OFF      0
#define MODE_DAY      1
#define MODE_NIGHT    2

// Level Control, Move to Level with On/Off, transition time 0: on at once at this level.
static inline void bulbs_on(long level)
{
  u8 p[3];
  p[0] = (u8)level;
  p[1] = 0;                           // transition time, 16 bit
  p[2] = 0;
  zcl_group(GROUP, 0x0008, 0x04, p, 3);
}

// On/Off cluster, Off with Effect, effect 0 variant 1 = no fade.
static inline void bulbs_off(void)
{
  u8 p[2];
  p[0] = 0;
  p[1] = 1;
  zcl_group(GROUP, 0x0006, 0x40, p, 2);
}

// Colour Control, Move to Colour Temperature: mireds and transition time, both 16 bit.
static inline void bulbs_colour(long mireds)
{
  u8 p[4];
  p[0] = (u8)(mireds & 0xFF);
  p[1] = (u8)(mireds >> 8);
  p[2] = 0;                           // no transition
  p[3] = 0;
  zcl_group(GROUP, 0x0300, 0x0A, p, 4);
}

// led_set(led, red, blue), each 0..255; red + blue = purple.
static inline void show_mode(long mode)
{
  led_set(LED_UPPER, mode == MODE_DAY ? 255 : 0, mode == MODE_DAY ? 255 : 0);
  led_set(LED_LOWER, mode == MODE_NIGHT ? 255 : 0, mode == MODE_NIGHT ? 255 : 0);
}

int on_event(struct h2_event *ev)
{
  if (ev->type == H2_EV_BOOT) {
    show_mode(var_get(VAR_MODE));
    return 1;
  }
  if (ev->source != UPPER && ev->source != LOWER) {
    return 0;
  }
  if (ev->type != H2_EV_SINGLE) {
    return 1;                         // ours: the firmware must never switch the relay
  }

  long wanted = (ev->source == UPPER) ? MODE_DAY : MODE_NIGHT;
  long mode = var_get(VAR_MODE);
  if (mode == wanted) {
    bulbs_off();
    mode = MODE_OFF;
  } else {
    bulbs_on(wanted == MODE_DAY ? DAY_LEVEL : NIGHT_LEVEL);
    bulbs_colour(wanted == MODE_DAY ? DAY_MIREDS : NIGHT_MIREDS);
    mode = wanted;
  }
  var_set(VAR_MODE, mode);
  show_mode(mode);
  return 1;
}
