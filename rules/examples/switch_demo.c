// Example rules for the 2- and 4-button switch.
//
// Buttons are numbered gang * 2 + side: 0 = left/only up, 1 = left/only down,
// 2 = right up, 3 = right down. LEDs use the same numbers.
//
//   button 0   left as built in (returning 0 for its PRESS keeps the firmware's behaviour)
//   button 1   taken over: click toggles relay 0 and recalls scene 1 (on) or 2 (off) on
//              group 1; a double click recalls scene 3; holding blinks its LED until release
//
// A program takes a button over by returning 1 for that button's PRESS event. From then
// on the firmware does nothing of its own for that gesture.
#include "../h2_rules.h"

#define GROUP 1

int on_event(struct h2_event *ev)
{
  if (ev->source == H2_SRC_BUTTON(1)) {
    switch (ev->type) {
      case H2_EV_PRESS:
        return 1;                              // this button is ours
      case H2_EV_SINGLE:
        relay_set(0, H2_TOGGLE);
        scene_recall(GROUP, relay_get(0) ? 1 : 2);
        return 1;
      case H2_EV_DOUBLE:
        relay_set(0, H2_ON);
        scene_recall(GROUP, 3);
        return 1;
      case H2_EV_HOLD:
        var_set(1, 0);
        timer_start(0, 300);
        return 1;
      case H2_EV_HOLD_RELEASE:
        timer_stop(0);
        led_release(1);
        return 1;
    }
  }
  if (ev->source == H2_SRC_TIMER && ev->value == 0) {
    long phase = var_get(1) ^ 1;
    var_set(1, phase);
    led_set(1, phase ? 255 : 0, phase ? 0 : 255);
    timer_start(0, 300);
    return 1;
  }
  return 0;
}
