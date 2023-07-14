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
#define TZ_OFFSET -1   // timezone offset
#define COUNTRY "BE"
#define NTP_SERVER "pool.ntp.org"

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

#define SERVER "security-app-eu.eufylife.com" // or "mysecurity.eufylife.com" or "security-app.eufylife.com" or ?
#define PORT 443
#define ENDPOINT "/v1/app/get_devs_list" // TODO: get correct endpoints
#define LOGIN_ENDPOINT "/v2/passport/login_sec"
#define VERIFY_CODE_ENDPOINT "/v1/sms/send/verify_code"
#define LIST_TRUST_DEVICE_ENDPOINT "/v1/app/trust_device/list"
#define ADD_TRUST_DEVICE_ENDPOINT "/v1/app/trust_device/add"
#define SET_PARAMETERS_ENDPOINT "/v1/app/upload_devs_params"
#define GET_CIPHERS_ENDPOINT "/v1/app/cipher/get_ciphers"
#define GET_PUBLIC_KEY_ENDPOINT "v1/app/public_key/query"
#define GET_PASSPORT_PROFILE_ENDPOINT "/v2/passport/profile"

#endif
