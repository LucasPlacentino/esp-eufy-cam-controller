// MIT License
// by Lucas Placentino
// Eufy Cam Controller - ESP32

/*
from https://github.com/FuzzyMistborn/python-eufy-security/blob/dev/openapi.yaml

servers:
  - url: https://mysecurity.eufylife.com/api/v1
    description: WebApp
  - url: https://security-app.eufylife.com/v1
    description: Android entrypoint (US)
  - url: https://security-app-eu.eufylife.com/v1
    description: Android entrypoint for EU
  - url: https://security-app-pr.eufylife.com/v1
    description: Android entrypoint for PR
  - url: https://security-app-ci.eufylife.com/v1
    description: Continuous Integration?
  - url: https://security-app-qa.eufylife.com/v1
    description: Quality Assurance?
  - url: https://security-app-sqa.eufylife.com/v1
    description: Short Quality Assurance?

endpoints:
/hub/get_p2p_connectinfo
/app/...
/passport/login

*/

#include <Preferences.h>
#include SECRETS.h
//#define TIME_TO_SLEEP 6000 // Time ESP32 will go to sleep (in seconds)
#define BTN_PIN 4 //make sure the GPIO pin is one that is supported for waking up the ESP from deep sleep
#define TZ "Europe/Brussels" //timezone

struct camera
{
    unsigned int id,
    String name,
    String ip
};

//example
camera cam1 =
{
    1,
    "Indoor Cam 1",
    "192.168.0.141"
};

cameras = [cam1];

Preferences preferences;
RTC_DATA_ATTR int wake_count = 0;

bool wifi_setup()
{
    //
    WiFi.mode(WIFI_STA);
    WiFi.begin(WIFI_SSID, WIFI_PASS);
    
    Serial.println(F("Connecting to WiFi"));
    while (WiFi.status() != WL_CONNECTED)
    {
        delay(500);
        Serial.print(F("."));
    }
    Serial.print(F("Connected to the WiFi network: "));
    Serial.println(WIFI_SSID);
    
    Serial.print(F("IP: "));
    Serial.println(WiFi.localIP());
}

bool wakeup()
{
    println(F("Waking up from deep sleep..."));
    
    esp_wifi_start();
    
    if (esp_sleep_get_wakeup_cause() == ESP_SLEEP_WAKEUP_EXT0)
    {
        for (int i=0; i<sizeof(cameras)/sizeof(cameras[0]); i++)
        {
            char id_str[16];
            bool cam_state = getBool(itoa(cameras[i].id, id_str, 10), false);
            println("Turning camera %s (id:%s) %s (ip: %s)\n", cameras[i].name, id_str, cam_state ? "off" : "on", ip);
            api_call(!cam_state, cameras[i].id); // enable or disable each camera
        }
    }
}

void deep_sleep()
{
    //go into deep sleep
    
    esp_wifi_stop(); //?
    //esp_sleep_disable_wakeup_source(ESP_SLEEP_WAKEUP_TIMER);
    //esp_sleep_enable_timer_wakeup(TIME_TO_SLEEP * 1000000);
    esp_sleep_enable_ext0_wakeup(BTN_PIN, 0);
    rtc_gpio_isolate(BTN_PIN); // needed ?
    esp_deep_sleep_start();
    //esp_light_sleep_start();
}

bool api_call()
{
    //
}

void setup()
{
    //setup
    Serial.begin(9600);
    //delay(100);
    preferences.begin("cam-states", false);
  
    if (wake_count == 0) //Run this only the first boot
    {
        println(F("Starting..."));
        ++wake_count;
        
        for (int i=0; i<sizeof(cameras)/sizeof(cameras[0]); i++)
        {
            char id_str[16];
            bool cam_state = getBool(itoa(cameras[i].id, id_str, 10), false);
            println("Init camera (id: %s) state as %s", id_str, cam_state ? "ON (true)" : "OFF (false)");
        }
        preferences.end();
        
        deep_sleep();
    } else
    {
        //++wake_count;
        wakeup();
        preferences.end();
    }
}

void loop()
{
    delay(1000);
    println(F("Should never get here in the loop"));
}

/*
# from https://github.com/FuzzyMistborn/python-eufy-security/blob/dev/eufy_security/types.py
# (or https://github.com/FuzzyMistborn/python-eufy-security/blob/2836db3bad5cd6bc6773c32cc7a35fcc4727b0f2/eufy_security/params.py)

"""
Device Types:
31 - Indoor Camera 2k (pan-tilt)
"""

class ParamType(Enum):
    """Define the types.

    List retrieved from from com.oceanwing.battery.cam.binder.model.CameraParams
    """

    STATUS_LED = 6014

    CHIME_STATE = 2015
    DETECT_EXPOSURE = 2023
    #DETECT_MODE = 2004
    DETECT_MODE = 6045  # PERSON/PET/OTHER   Look at DetectionMode enum in detection.py
    DETECT_MOTION_SENSITIVE = 2005
    DETECT_SCENARIO = 2028
    DETECT_SENSITIVITY = 6041  # Sensitivity slider (Lowest-Highest)  Look at DetectionSensitivity enum in detection.py
    #DETECT_SWITCH = 2027
    DETECT_SWITCH = 6040  # Turn ON/OFF
    DETECT_ZONE = 2006
    DOORBELL_AUDIO_RECODE = 2042
    DOORBELL_BRIGHTNESS = 2032
    DOORBELL_DISTORTION = 2033
    DOORBELL_HDR = 2029
    DOORBELL_IR_MODE = 2030
    DOORBELL_LED_NIGHT_MODE = 2039
    DOORBELL_MOTION_ADVANCE_OPTION = 2041
    DOORBELL_MOTION_NOTIFICATION = 2035
    DOORBELL_NOTIFICATION_JUMP_MODE = 2038
    DOORBELL_NOTIFICATION_OPEN = 2036
    DOORBELL_RECORD_QUALITY = 2034
    DOORBELL_RING_RECORD = 2040
    DOORBELL_SNOOZE_START_TIME = 2037
    DOORBELL_VIDEO_QUALITY = 2031
    NIGHT_VISUAL = 2002
    OPEN_DEVICE = 2001 # <============ device ON or OFF
    RINGING_VOLUME = 2022
    SDCARD = 2010
    UN_DETECT_ZONE = 2007
    VOLUME = 2003

    # Inferred from source
    SNOOZE_MODE = 1271  # The value is base64 encoded
    WATERMARK_MODE = 1214  # 1 - hide, 2 - show
    DEVICE_UPGRADE_NOW = 1134
    CAMERA_UPGRADE_NOW = 1133
    DEFAULT_SCHEDULE_MODE = 1257, EnumConverter(ScheduleMode)
    GUARD_MODE = 1224, EnumConverter(GuardMode)

    FLOODLIGHT_MANUAL_SWITCH = 1400
    FLOODLIGHT_MANUAL_BRIGHTNESS = 1401  # The range is 22-100
    FLOODLIGHT_MOTION_BRIGHTNESS = 1412  # The range is 22-100
    FLOODLIGHT_SCHEDULE_BRIGHTNESS = 1413  # The range is 22-100
    FLOODLIGHT_MOTION_SENSITIVTY = 1272  # The range is 1-5

    CAMERA_SPEAKER_VOLUME = 1230
    CAMERA_RECORD_ENABLE_AUDIO = 1366, BoolConverter
    CAMERA_RECORD_RETRIGGER_INTERVAL = 1250  # In seconds
    CAMERA_RECORD_CLIP_LENGTH = 1249  # In seconds

    CAMERA_IR_CUT = 1013
    CAMERA_PIR = 1011, BoolConverter
    CAMERA_WIFI_RSSI = 1142

    CAMERA_MOTION_ZONES = 1204, JsonBase64Converter

    # Set only params?
    PUSH_MSG_MODE = 1252  # 0 is human detection, 2 is all motions, others???

    PRIVATE_MODE = 99904, BoolConverter
    CUSTOM_RTSP_URL = 999991, StringConverter

    def __new__(cls, value, converter=NumberConverter):
        """Create a new ParamType."""
        obj = object.__new__(cls)
        obj._value_ = value
        obj._converter_ = converter
        return obj

    def loads(self, value):
        """Read a parameter JSON string."""
        return self._converter_.loads(value)

    def dumps(self, value):
        """Write a parameter JSON string."""
        return self._converter_.dumps(value)

    @staticmethod
    def lookup(name_or_value):
        """Look up a param type by its number or name."""
        if isinstance(name_or_value, ParamType):
            return name_or_value
        if type(name_or_value) == str:
            return ParamType[name_or_value]
        else:
            return ParamType(name_or_value)

    # --------------

    def read_value(self, value):
        """Read a parameter JSON string."""
        if value:
            if self is ParamType.SNOOZE_MODE:
                value = base64.b64decode(value, validate=True).decode()
            return json.loads(value)
        return None

    def write_value(self, value):
        """Write a parameter JSON string."""
        value = json.dumps(value)
        if self is ParamType.SNOOZE_MODE:
            value = base64.b64encode(value.encode()).decode()
        return value

*/



/*

"""Define a successful response to POST /api/v1/passport/login."""
    {
        "code": 0,
        "msg": "Succeed.",
        "data": {
            "user_id": "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
            "email": TEST_EMAIL,
            "nick_name": "",
            "auth_token": TEST_ACCESS_TOKEN,
            "token_expires_at": int((datetime.now() + timedelta(days=1)).timestamp()),
            "avatar": "",
            "invitation_code": "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
            "inviter_code": "",
            "mac_addr": "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
            "domain": "security-app.eufylife.com",
            "ab_code": "US",
            "geo_key": "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
            "privilege": 0,
            "params": [
                {"param_type": 10000, "param_value": "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"}
            ],
        },
    }

*/
