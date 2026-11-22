// Rules for a 2-button switch that drives a room light on its relay and a Zigbee bulb
// (or several) in group 1.
//
//   upper button   toggles the relay; the bulb follows it: on in cool light with the
//                  relay, off with it
//   lower button   bulb only: warm light, and on the next click off
//
//   upper LED      purple while the room light and the bulb are both on
//   lower LED      red while the bulb is in warm light
//
// The bulb is switched with commands that skip its fade: IKEA bulbs fade on the plain
// On and Off commands whatever their transition setting says.
//
// Both buttons are taken over (PRESS returns 1), so the firmware's own press behaviour
// is off for them.
#include "../h2_rules.h"

#define GROUP        1
#define UPPER        H2_SRC_BUTTON(0)
#define LOWER        H2_SRC_BUTTON(1)
#define LED_UPPER    0
#define LED_LOWER    1
#define BRIGHTNESS   254              // level the bulb turns on at (1..254)
#define COOL_MIREDS  250              // 4000 K, the coolest this bulb goes
#define WARM_MIREDS  454              // 2200 K, the warmest this bulb goes
#define VAR_WARM     0                // 1 while the lower button has the bulb in warm light
#define VAR_BULB     1                // 1 while the bulb is on

// On at once: Level Control, Move to Level with On/Off, transition time 0.
static inline void bulb_on(void)
{
  u8 p[3];
  p[0] = BRIGHTNESS;
  p[1] = 0;                           // transition time, 16 bit
  p[2] = 0;
  zcl_group(GROUP, 0x0008, 0x04, p, 3);
  var_set(VAR_BULB, 1);
}

// Off at once: On/Off cluster, Off with Effect, effect 0 variant 1 = no fade. The bulb
// keeps its brightness for whoever turns it on next.
static inline void bulb_off(void)
{
  u8 p[2];
  p[0] = 0;
  p[1] = 1;
  zcl_group(GROUP, 0x0006, 0x40, p, 2);
  var_set(VAR_BULB, 0);
}

// Colour Control cluster, Move to Colour Temperature: mireds, then transition time in
// tenths of a second, both 16 bit, low byte first.
static inline void bulb_colour(long mireds)
{
  u8 p[4];
  p[0] = (u8)(mireds & 0xFF);
  p[1] = (u8)(mireds >> 8);
  p[2] = 0;                           // no transition
  p[3] = 0;
  zcl_group(GROUP, 0x0300, 0x0A, p, 4);
}

// led_set(led, red, blue), each 0..255.
static inline void show_modes(void)
{
  long both = relay_get(0) && var_get(VAR_BULB);
  led_set(LED_UPPER, both ? 255 : 0, both ? 255 : 0);       // purple or dark
  led_set(LED_LOWER, var_get(VAR_WARM) ? 255 : 0, 0);       // red or dark
}

int on_event(struct h2_event *ev)
{
  if (ev->type == H2_EV_BOOT) {
    show_modes();                     // after a restart: nothing is known to be on
    return 1;
  }
  if (ev->source != UPPER && ev->source != LOWER) {
    return 0;
  }
  if (ev->type != H2_EV_SINGLE) {
    return 1;                         // ours, but only clicks do anything
  }

  if (ev->source == UPPER) {
    relay_set(0, H2_TOGGLE);
    if (relay_get(0)) {
      bulb_on();
      bulb_colour(COOL_MIREDS);
    } else {
      bulb_off();
    }
    var_set(VAR_WARM, 0);
  } else if (var_get(VAR_WARM)) {
    bulb_off();
    var_set(VAR_WARM, 0);
  } else {
    bulb_on();
    bulb_colour(WARM_MIREDS);
    var_set(VAR_WARM, 1);
  }
  show_modes();
  return 1;
}
