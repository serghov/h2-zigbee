// Names for the Zigbee clusters, commands and attributes that rule files use.
#ifndef H2_LIB_ZCL_H
#define H2_LIB_ZCL_H

#define CL_ON_OFF            0x0006
#define CL_LEVEL             0x0008
#define CL_COLOUR            0x0300

#define CMD_OFF              0x00      // On/Off cluster
#define CMD_ON               0x01
#define CMD_TOGGLE           0x02
#define CMD_LEVEL_ON_OFF     0x04      // Level cluster: Move to Level with On/Off
#define CMD_COLOUR_TEMP      0x0A      // Colour cluster: Move to Colour Temperature

#define ATTR_ON_OFF          0x0000    // On/Off cluster: 0 or 1
#define ATTR_LEVEL           0x0000    // Level cluster: 1..254
#define ATTR_COLOUR_TEMP     0x0007    // Colour cluster: mireds (1,000,000 / kelvin)

#define KELVIN(k)            (1000000 / (k))   // colour temperature in mireds
#define PERCENT(p)           ((p) * 254 / 100) // brightness level

#endif
