#ifndef H2_VARIANT_H
#define H2_VARIANT_H

// Variant: H2 Switch (1-gang and 2-gang, runtime-detected)
#define H2_SWITCH_GANG_COUNT  2   // compile-time max (arrays sized to this)
#define H2_HAS_RELAY          1
#define H2_HAS_DIMMER         0

// 1 if the Zigbee configuration has an LED light endpoint per indicator LED (h2_led_ep.h)
#define H2_HAS_LED_ENDPOINTS   0

#endif // H2_VARIANT_H
