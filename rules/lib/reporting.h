// How promptly lamps report their changes.
//
// A lamp sends a changed value no sooner than its "minimum interval" after its previous
// report of the same attribute. Hubs set that interval when the lamp is paired: Home
// Assistant (ZHA) uses 0 s for on/off, 1 s for brightness and 30 s for colour, so a second
// colour change inside 30 s reaches the switch late. The setting is one per attribute and
// shared by everything the lamp reports to, so the last writer wins: a hub that
// reconfigures or re-pairs the lamp puts its own value back. Send this at start-up and
// again now and then.
#ifndef H2_LIB_REPORTING_H
#define H2_LIB_REPORTING_H

#include "../h2_rules.h"
#include "zcl.h"

#define ZCL_CONFIGURE_REPORTING  0x06
#define ZCL_TYPE_UINT16          0x21

// Ask every lamp of a group to report a 16-bit attribute (such as colour temperature)
// at most min_seconds after a change, and at least every max_seconds.
// Do not use a minimum of 0: the lamp would report every step of a fade.
H2_INLINE void report_within(long group, long cluster, long attr, long min_seconds, long max_seconds)
{
  u8 p[10];
  p[0] = 0x00;                         // the lamp sends reports (not: expects them)
  p[1] = (u8)(attr & 0xFF);
  p[2] = (u8)(attr >> 8);
  p[3] = ZCL_TYPE_UINT16;
  p[4] = (u8)(min_seconds & 0xFF);
  p[5] = (u8)(min_seconds >> 8);
  p[6] = (u8)(max_seconds & 0xFF);
  p[7] = (u8)(max_seconds >> 8);
  p[8] = 1;                            // report any change of 1 or more
  p[9] = 0;
  zcl_send(H2_TO_GROUP(group), cluster, H2_ZCL_GENERAL | ZCL_CONFIGURE_REPORTING, p, 10);
}

#endif
