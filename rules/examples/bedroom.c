// Bedroom: a 2-button switch whose relay feeds three Zigbee ceiling bulbs (group 16).
// The relay stays on so the bulbs always have mains; the buttons only talk to the bulbs.
//
//   upper button   Day: full brightness, cool. Again while in Day: off.
//   lower button   Night: 60 %, warm. Again while in Night: off.
//   The other button while the bulbs are on switches mode.
//   upper LED purple in Day, lower LED purple in Night, both dark when off.
//
// The mode follows the bulbs: if something else turns them off, on, or changes their
// colour, the LEDs and the next press go by what the bulbs report. The mode is public
// variable 0 (0 off, 1 Day, 2 Night): the hub can read it, and writing it switches mode.
#include "../lib/lights_tradfri.h"
#include "../lib/sync.h"

#ifndef GROUP
#define GROUP        16
#endif
#define UPPER        H2_SRC_BUTTON(0)
#define LOWER        H2_SRC_BUTTON(1)

#define MODE_OFF     0
#define MODE_DAY     1
#define MODE_NIGHT   2
#define DAY_LEVEL    PERCENT(100)
#define DAY_COLOUR   KELVIN(4000)
#define NIGHT_LEVEL  PERCENT(60)
#define NIGHT_COLOUR KELVIN(2200)
#define DAY_IF_BELOW KELVIN(3000)     // a reported colour cooler than this counts as Day

#define VAR_MODE     0                // public
#define VAR_ON_MASK  1                // one bit per bulb that is on
#define VAR_MIREDS   2                // last colour temperature a bulb reported

// red + blue = purple
H2_INLINE void show(long mode)
{
  led_set(0, mode == MODE_DAY ? 255 : 0, mode == MODE_DAY ? 255 : 0);
  led_set(1, mode == MODE_NIGHT ? 255 : 0, mode == MODE_NIGHT ? 255 : 0);
}

H2_INLINE void set_mode(long mode)
{
  var_set(VAR_MODE, mode);            // reported to the hub when it changes
  show(mode);
}

H2_INLINE void command(long mode)
{
  if (mode == MODE_DAY)        lights_on(GROUP, DAY_LEVEL, DAY_COLOUR);
  else if (mode == MODE_NIGHT) lights_on(GROUP, NIGHT_LEVEL, NIGHT_COLOUR);
  else                         lights_off(GROUP);
}

H2_INLINE long mode_of_colour(void)
{
  long mireds = var_get(VAR_MIREDS);
  return (mireds && mireds < DAY_IF_BELOW) ? MODE_DAY : MODE_NIGHT;
}

int on_event(struct h2_event *ev)
{
  if (ev->type == H2_EV_BOOT) {
    relay_set(0, H2_ON);              // the bulbs need mains
    var_public(1 << VAR_MODE);
    sync_start(GROUP, 1);
    show(var_get(VAR_MODE));
    return 1;
  }

  // News from the bulbs: follow it, send nothing.
  long news = sync_report(ev, VAR_ON_MASK, VAR_MIREDS);
  if (news) {
    long mode = var_get(VAR_MODE);
    if (!sync_any_on(VAR_ON_MASK))                 set_mode(MODE_OFF);
    else if (news == 2 || mode == MODE_OFF)        set_mode(mode_of_colour());
    return 1;
  }

  // The hub wrote the mode: do what a button press would.
  if (ev->source == H2_SRC_SYSTEM && ev->type == H2_EV_VAR && ev->value == VAR_MODE) {
    long mode = var_get(VAR_MODE);
    if (mode < MODE_OFF || mode > MODE_NIGHT) mode = MODE_OFF;
    command(mode);
    set_mode(mode);
    return 1;
  }

  if (ev->source != UPPER && ev->source != LOWER) return 0;
  if (ev->type != H2_EV_SINGLE) return 1;          // ours: the firmware must not switch the relay

  long wanted = (ev->source == UPPER) ? MODE_DAY : MODE_NIGHT;
  long mode = (var_get(VAR_MODE) == wanted) ? MODE_OFF : wanted;
  command(mode);
  set_mode(mode);                                   // at once; the bulbs' reports confirm it
  return 1;
}
