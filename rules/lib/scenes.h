// Scenes kept in the lamps themselves. A press then needs one message, Recall Scene, and
// each lamp applies on/off, brightness and colour in one step: nothing can arrive half
// done or out of order, however fast the presses follow each other.
#ifndef H2_LIB_SCENES_H
#define H2_LIB_SCENES_H

#include "../h2_rules.h"
#include "zcl.h"

#define CL_SCENES            0x0005
#define CMD_SCENE_STORE      0x04
#define CMD_SCENE_RECALL     0x05

// Have every member of the group keep its present state (on/off, brightness, colour) as
// this scene. Bring the lamps to the wanted state first and give them a moment.
// (IKEA lamps do not keep the colour of a scene that is sent to them ready-made with
// "Add Scene"; they do keep it this way. RESEARCH.md, 2026-11-22 and 2026-11-24.)
H2_INLINE void scene_keep(long group, long scene)
{
  u8 p[3];
  p[0] = (u8)group;
  p[1] = (u8)(group >> 8);
  p[2] = (u8)scene;
  zcl_group(group, CL_SCENES, CMD_SCENE_STORE, p, 3);
}

#endif
