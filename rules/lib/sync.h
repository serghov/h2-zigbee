// Keeping a switch in step with lamps that other things also control.
//
// The lamps of a group tell the switch when they change (the firmware arranges that the
// first time they answer). These helpers keep "which lamps are on" in one variable and
// the last reported colour temperature in another, so a rule can show the real state and
// act on it. Reports are news about the state: nothing here sends a command.
#ifndef H2_LIB_SYNC_H
#define H2_LIB_SYNC_H

#include "../h2_rules.h"
#include "zcl.h"

// Call on H2_EV_BOOT: say what is of interest and ask the group for its current state.
H2_INLINE void sync_start(long group, long with_colour)
{
  watch(CL_ON_OFF, ATTR_ON_OFF);
  group_read(group, CL_ON_OFF, ATTR_ON_OFF);
  if (with_colour) {
    watch(CL_COLOUR, ATTR_COLOUR_TEMP);
    group_read(group, CL_COLOUR, ATTR_COLOUR_TEMP);
  }
}

// Call for every event. Returns 0 if the event is not a lamp report, 1 if a lamp's on/off
// state was recorded, 2 if a colour temperature was recorded.
//   var_on_mask: variable holding one bit per lamp that is on
//   var_mireds:  variable holding the last colour temperature reported (or -1 for none)
H2_INLINE long sync_report(struct h2_event *ev, long var_on_mask, long var_mireds)
{
  if (!H2_IS_REMOTE(ev->source)) return 0;
  if (ev->type == H2_EV_LOST) {         // the lamp is gone: it no longer counts as on
    var_set(var_on_mask, var_get(var_on_mask) & ~(1 << (ev->source - H2_SRC_REMOTE(0))));
    return 1;
  }
  if (ev->type != H2_EV_REPORT) return 0;
  if (ev->cluster == CL_ON_OFF && ev->attr == ATTR_ON_OFF) {
    long bit = 1 << (ev->source - H2_SRC_REMOTE(0));
    long mask = var_get(var_on_mask);
    var_set(var_on_mask, ev->value ? (mask | bit) : (mask & ~bit));
    return 1;
  }
  if (var_mireds >= 0 && ev->cluster == CL_COLOUR && ev->attr == ATTR_COLOUR_TEMP) {
    var_set(var_mireds, ev->value);
    return 2;
  }
  return 0;
}

H2_INLINE long sync_any_on(long var_on_mask)
{
  return var_get(var_on_mask) != 0;
}

#endif
