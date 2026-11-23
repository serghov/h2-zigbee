// Commands for a group of IKEA TRADFRI bulbs, with the sequences these bulbs need.
//
// Findings behind this file (RESEARCH.md, 2026-11-23, TRADFRI E27 WS globe 1055lm):
//  - "Move to Level with On/Off" alone can leave a bulb dark while it reports "on":
//    always follow it with an explicit On.
//  - After "Off with Effect" the bulbs did not come back on until power-cycled: use the
//    plain Off. The bulb then fades out over about half a second by itself.
//  - Send the colour after the bulb is on, with no transition time.
#ifndef H2_LIB_LIGHTS_H
#define H2_LIB_LIGHTS_H

#include "../h2_rules.h"
#include "zcl.h"

// On at this brightness (1..254) and colour temperature (mireds; 0 = leave the colour).
H2_INLINE void lights_on(long group, long level, long mireds)
{
  u8 p[4];
  p[0] = (u8)level;
  p[1] = 0;                            // transition time, 16 bit: none
  p[2] = 0;
  zcl_group(group, CL_LEVEL, CMD_LEVEL_ON_OFF, p, 3);
  zcl_group(group, CL_ON_OFF, CMD_ON, 0, 0);
  if (mireds) {
    p[0] = (u8)(mireds & 0xFF);
    p[1] = (u8)(mireds >> 8);
    p[2] = 0;                          // transition time, 16 bit: none
    p[3] = 0;
    zcl_group(group, CL_COLOUR, CMD_COLOUR_TEMP, p, 4);
  }
}

H2_INLINE void lights_off(long group)
{
  zcl_group(group, CL_ON_OFF, CMD_OFF, 0, 0);
}

#endif
