// PARAMS.h
// MIT License
// by Lucas Placentino

// Eufy Cam Controller - ESP32

// ---- PARAMS ----
#ifndef PARAMS_h
#define PARAMS_h

// #define TIME_TO_SLEEP 6000 // Time ESP32 will go to sleep (in seconds)
#define BTN_PIN 4      // make sure the GPIO pin is one that is supported for waking up the ESP from deep sleep
#define BLUE_LED_PIN 2 // blue LED, state ON
#define RED_LED_PIN 15 // red LED, state OFF
#define YELLOW_LED_PIN 12 // green LED, state unknown

#define TZ "GMT+01:00" // timezone
#define COUNTRY "BE"

// from https://github.com/bropat/eufy-security-client/blob/master/src/http/api.ts
#define APP_VERSION "" // ex: "v4.6.0_1630"
#define OS_VERSION ""  // ex: "31"
#define PHONE_MODEL "" // ex: "ONEPLUS A3003"
#define OPENUDID ""    // ex: "5e4621b0152c0d00"
#define MNC ""         // ex: "01" Proximus (Belgium) (Mobile Network Code)
#define MCC ""         // ex: "206" Belgium (Mobile Country Code)
#define SN ""          // phone? serial number TODO:
#define MODEL_TYPE "PHONE"

// ----- server -----

#define SERVER "mysecurity.eufylife.com" // or "security-app.eufylife.com" or "security-app-eu.eufylife.com" or ?
#define PORT 443
#define ENDPOINT "/v1/app/get_devs_list" // TODO: get correct endpoints

#endif