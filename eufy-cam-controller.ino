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

//* check:
//
//? device type INDOOR_PT_CAMERA = 31
//
//? PropertyName.DeviceEnabled CommandType.CMD_DEVS_SWITCH = 1035
//
//? https://github.com/bropat/eufy-security-client/blob/master/src/http/station.ts#L3557
//
//? CommandType.CMD_INDOOR_ENABLE_PRIVACY_MODE 6090

#include <Preferences.h>
#include <WiFiClientSecure.h>
#include <ArduinoJson.h>
#include <WiFiUdp.h>
#include <NTPClient.h>
#include SECRETS.h

// TODO ? https://github.com/bropat/eufy-security-client/blob/master/src/http/const.ts

struct camera
{
    unsigned int id,
        char *ip[15],
        String name,
};

// example
camera cam1 =
    {
        1,
        "192.168.0.141",
        "Indoor Cam 1"

};

cameras = [cam1];

Preferences preferences;
WiFiClientSecure client;
client.setCACert_P(rootCACertificate, sizeof(rootCACertificate));
// Define NTP Client to get time
WiFiUDP ntpUDP;
// NTPClient timeClient(ntpUDP, NTP_SERVER, NTP_OFFSET);
NTPClient timeClient(ntpUDP, NTP_SERVER);
const size_t capacity = JSON_OBJECT_SIZE(2); // Set the capacity according to your JSON structure
RTC_DATA_ATTR int wake_count = 0;
RTC_DATA_ATTR char *token;
RTC_DATA_ATTR char *user_id;
RTC_DATA_ATTR char *username;
RTC_DATA_ATTR char *email;
RTC_DATA_ATTR char *password;
RTC_DATA_ATTR char *nick_name;
String device_public_keys[];
char *clientPrivateKey; //?
RTC_DATA_ATTR char *serverPublicKey;
RTC_DATA_ATTR bool device_trusted;

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
        bool api_success = false;
        /*
        char id_str[16];
        bool cam_state = getBool(itoa(cameras[i].id, id_str, 10), false);
        */
        bool cam_state = getBool(("state"), false);
        bool new_cam_state = !cam_state;
        for (int i = 0; i < sizeof(cameras) / sizeof(cameras[0]); i++)
        {
            camera cam = cameras[i];
            println("Turning camera %s (id:%d) %s (ip: %s)\n", cam.name, cam.id, new_cam_state ? "on" : "off", cam.ip);
            bool api_success_cam = api_call(new_cam_state, cam.id); // enable or disable each camera
            if (api_success_cam)
            {
                Serial.println("Camera %s (id: %d) state changed successfully to %s", cam.name, cam.id, new_cam_state ? "on" : "off");
            }
            else
            {
                Serial.println("===Camera %s (id: %d) state change FAILED===", cam.name, cam.id);
            }
            api_success &= api_success_cam;
        }
        if (api_success)
        {
            Serial.println("Cameras state changed successfully to %s", new_cam_state ? "on" : "off");
            if (new_cam_state)
            {
                digitalWrite(BLUE_LED_PIN, LOW); // turn ON LED
                digitalWrite(RED_LED_PIN, HIGH);
                digitalWrite(YELLOW_LED_PIN, HIGH);
            }
            else
            {
                digitalWrite(RED_LED_PIN, LOW); // turn ON LED
                digitalWrite(BLUE_LED_PIN, HIGH);
                digitalWrite(YELLOW_LED_PIN, HIGH);
            }
        }
        else
        {
            Serial.println("Cameras new state unknown, some cameras may be ON and some may be OFF");
            digitalWrite(YELLOW_LED_PIN, LOW); // turn ON LED
            digitalWrite(RED_LED_PIN, HIGH);
            digitalWrite(BLUE_LED_PIN, HIGH);
        }
        cam_state != cam_state; // toggle state for next wakeup
    }
}

void deep_sleep()
{
    // go into deep sleep

    esp_wifi_stop(); //?
    // esp_sleep_disable_wakeup_source(ESP_SLEEP_WAKEUP_TIMER);
    // esp_sleep_enable_timer_wakeup(TIME_TO_SLEEP * 1000000);
    esp_sleep_enable_ext0_wakeup(BTN_PIN, 0);
    rtc_gpio_isolate(BTN_PIN); // needed ?
    esp_deep_sleep_start();
    // esp_light_sleep_start();
}

String encrypt_API_data(String data, Buffer key) // TODO: Buffer type
{
    String cipher = create_cipher_iv("aes-256-cbc", key, key.slice(0,16)); //TODO:
    return (
        cipher.update(data, "utf8", "base64") +
        cipher.final("base64")
    ); //TODO:
}

Buffer decrypt_API_data_d(String data, Buffer key) // TODO: Buffer type
{
    String cipher = create_cipher_iv("aes-256-cbc", key, key.slice(0,16)); //TODO:
    return Buffer.concat([
        cipher.update(data, "base64") +
        cipher.final()]
    ); //TODO:
}

String decrypt_API_data(String data, bool json = true)
{
    if (data)
    {
        String decrypted_data = "";
        //TODO: try - catch ?
        try {
            decrypted_data = decrypt_API_data_d(data, compute_secret(serverPublicKey)); //TODO: compute_secret()
            // serverPublicKey is in hex
        } catch (const std::exception &e)
        {
            Serial.println("Failed to decrypt data, error: " + e.what());
            serverPublicKey = SERVER_PUBLIC_KEY;
            //TODO invalidate token
        }
        if (decrypted_data)
        {
            if (json)
            {
                //TODO: parse json of decrypted_data.toString()
            }
            return decrypted_data; // String
        }
        if (json)
        {
            return "{}"; //?
        }
    }
    return NULL
}

/*
PassportProfileResponse get_passport_profile()
{
    //TODO
}
*/

bool send_verify_code()
{
    //TODO:

    bool res = false;
    // make request
    DynamicJsonDocument jsonDoc(capacity);
    jsonDoc["message_type"] = verify_code_type_email; //TODO:
    jsonDoc["transaction"] = get_time(); // get time, milliseconds since epoch

    String jsonPayload;
    serializeJson(jsonDoc, jsonPayload);

    if (client.connect(SERVER, PORT))
    {
        client.println("POST " + VERIFY_CODE_ENDPOINT + " HTTP/1.1");
        // send Headers
        send_login_headers(jsonPayload.length());
        // send Payload
        client.println(jsonPayload);

        while (client.connected() || client.available())
        {
            if (client.available())
            {
                // Process the response
                char response = client.read();
                Serial.println(response);
                if (strstr(response, "200 OK") != NULL)
                {
                    //TODO:
                    Serial.println("Requested verification code for 2FA");
                    res = true;
                } else
                {
                    Serial.println("Failed to request verification code for 2FA");
                    res = false;
                }
            }
        }
        client.stop();
    }
    return res;
}

String list_trust_device()
{
    //TODO:
}

bool add_trust_device(String verify_code)
{
    bool res = false;
    // make request
    DynamicJsonDocument jsonDoc(capacity);
    jsonDoc["verify_code"] = verify_code; // TODO:
    jsonDoc["transaction"] = get_time();              // get time, milliseconds since epoch

    String jsonPayload;
    serializeJson(jsonDoc, jsonPayload);

    if (client.connect(SERVER, PORT))
    {
        client.println("POST " + ADD_TRUST_DEVICE_ENDPOINT + " HTTP/1.1");
        // send Headers
        send_login_headers(jsonPayload.length());
        // send Payload
        client.println(jsonPayload);

        while (client.connected() || client.available())
        {
            if (client.available())
            {
                // Process the response
                char response = client.read();
                Serial.println(response);
                if (strstr(response, "200 OK") != NULL)
                {
                    // TODO:
                    Serial.println("2FA successful");
                    device_trusted = true;
                    res = true;
                }
                else
                {
                    Serial.println("2FA Failed");
                    res = false;
                }
            }
        }
        client.stop();
    }
    return res;
}

void send_headers(int jsonPayloadLength)
{
    // Serial
    Serial.println("Host: " + SERVER);
    Serial.println("Content-Type: application/json");
    Serial.println("Connection: close");
    Serial.print("Content-Length: ");
    Serial.println(jsonPayloadLength);
    Serial.println("X-Auth-Token" + token);
    Serial.println("App_version: " + APP_VERSION);
    Serial.println("Os_type: android");
    Serial.println("Os_version: " + OS_VERSION);
    Serial.println("Phone_model: " + PHONE_MODEL);
    Serial.println("Country: " + COUNTRY);
    Serial.println("Language: en");
    Serial.println("Openudid: " + OPENUDID);
    // "uid: ""
    Serial.println("Net_type: wifi");
    Serial.println("Mnc: " + MNC);
    Serial.println("Mcc: " + MCC);
    Serial.println("Sn: " + SN);
    Serial.println("Model_type: " + MODEL_TYPE);
    Serial.println("Timezone: " + TZ);
    Serial.println("Cache-Control: no-cache");
    Serial.println();

    // client
    client.println("Host: " + SERVER);
    client.println("Content-Type: application/json");
    client.println("Connection: close");
    client.print("Content-Length: ");
    client.println(jsonPayloadLength);
    client.println("X-Auth-Token" + token);
    client.println("App_version: " + APP_VERSION);
    client.println("Os_type: android");
    client.println("Os_version: " + OS_VERSION);
    client.println("Phone_model: " + PHONE_MODEL);
    client.println("Country: " + COUNTRY);
    client.println("Language: en");
    client.println("Openudid: " + OPENUDID);
    // "uid: ""
    client.println("Net_type: wifi");
    client.println("Mnc: " + MNC);
    client.println("Mcc: " + MCC);
    client.println("Sn: " + SN);
    client.println("Model_type: " + MODEL_TYPE);
    client.println("Timezone: " + TZ);
    client.println("Cache-Control: no-cache");
    client.println();
}

String get_time()
{
    // updates NTP
    timeClient.update();
    unsigned long epochTime;
    epochTime = timeClient.getEpochTime();
    Serial.println("Epoch Time: %s", epochTime);
    return epochTime;
}

void send_login_headers(int jsonPayloadLength)
{
    client.println("Host: " + SERVER);
    client.println("Content-Type: application/json");
    client.println("Connection: close");
    client.print("Content-Length: ");
    client.println(jsonPayloadLength);
}

String get_public_key(String deviceSN, PublicKeyType type) //TODO: PublicKeyType enum
{
    String res = false;
    if (device_public_keys[deviceSN] != NULL && type == PublicKeyType.LOCK)
    {
        return device_public_keys[deviceSN];
    } else
    {
        // make request
        if (client.connect(SERVER, PORT))
        {
            client.println("POST " + GET_PUBLIC_KEY_ENDPOINT + "?device_sn=" + deviceSN + "&type=" + type +" HTTP/1.1");
            // send Headers
            send_headers(jsonPayload.length()); //? TODO: ?

            while (client.connected() || client.available())
            {
                if (client.available())
                {
                    // Process the response
                    char response = client.read();
                    Serial.println(response);
                    if (strstr(response, "200 OK") != NULL)
                    {
                        Serial.println(F("Successfully get public key"));
                        if (type == PublicKeyType.LOCK)
                        {
                            device_public_keys[deviceSN] = response.data.public_key; //TODO: extract public_key from response
                        }
                        res = response.data.public_key; //TODO: extract public_key from response
                    } else
                    {
                        Serial.println(F("Failed to get public key"));
                        res = "";
                    }
                }
            }
        }
        client.stop();
    }
    return res;
}

bool api_login()
{
    bool res = false;
    Serial.println(F("API Login..."));

    // TODO: token = preferences.getString("token", "");

    char *new_token;

    // make request
    DynamicJsonDocument jsonDoc(capacity);
    jsonDoc["ab"] = COUNTRY;
    jsonDoc["client_secret_info"] = [ {
        "public_key" : publicKey
    } ]; // TODO: publicKey in hex
    jsonDoc["enc"] = 0;
    jsonDoc["email"] = username;
    jsonDoc["password"] = encrypt_API_data(password); //TODO: with SERVER_PUBLIC_KEY(in hex)
    jsonDoc["time_zone"] = TZ_OFFSET;
    jsonDoc["transaction"] = get_time(); // get time, milliseconds since epoch

    //if verify_code or captcha:
    jsonDoc["verify_code"] = "value1";
    jsonDoc["captcha_id"] = "";
    jsonDoc["answer"] = "";

    String jsonPayload;
    serializeJson(jsonDoc, jsonPayload);

    if (client.connect(SERVER, PORT))
    {
        client.println("POST " + LOGIN_ENDPOINT + " HTTP/1.1");
        // send Headers
        send_login_headers(jsonPayload.length());
        // send Payload
        client.println(jsonPayload);

        while (client.connected() || client.available())
        {
            if (client.available())
            {
                // Process the response
                char response = client.read();
                Serial.println(response);
                if (strstr(response, "200 OK") != NULL)
                {
                    Serial.println(F("=> API Login successful: 200 OK"));
                    //...
                    res = true;
                } else
                {
                    Serial.println(F("API Login failed"));
                    //...
                    res = false
                }
            }
        }
        client.stop();
    }
    // handle response
    if (res)
    {
        token = new_token;
        Serial.println(F("API Login successful"));
        return true;
    }
    else
    {
        Serial.println(F("API Login failed"));
        return false;
    }
}

Cipher get_ciphers[](int cipherIDs[], String userID)
{

    String res = "";
    DynamicJsonDocument jsonDoc(capacity);
    jsonDoc["cipher_ids"] = cipherIDs;
    jsonDoc["user_id"] = userID;
    jsonDoc["transaction"] = get_time(); // get time, milliseconds since epoch

    String jsonPayload;
    serializeJson(jsonDoc, jsonPayload);

    if (client.connect(SERVER, PORT))
    {
        // POST request
        client.println("POST " + GET_CIPHERS_ENDPOINT + " HTTP/1.1");
        // send Headers
        send_headers(jsonPayload.length()); //? TODO:
        // send Payload
        client.println(jsonPayload);

        while (client.connected() || client.available())
        {
            if (client.available())
            {
                // Process the response
                char response = client.read();
                Serial.println(response);
                if (strstr(response, "200 OK") != NULL)
                {
                    Cipher ciphers[];
                    Serial.println(F("Successfully get ciphers"));
                    //TODO: extract list of ciphers from response


                    res = ciphers;
                } else
                {
                    Serial.println(F("Failed to get ciphers"));
                    res = NULL;
                }
            }
        }
        client.stop();
    }
    return res;
}

//? needed ?
String get_cipher(String cipherID, String userID)
{
    return get_ciphers([cipherID], userID)[cipherID];
}

bool api_call(bool new_state, int cam_id)
{
    // TODO:

    DynamicJsonDocument jsonDoc(capacity);
    jsonDoc["key1"] = "value1";
    jsonDoc["key2"] = "value2";

    String jsonPayload;
    serializeJson(jsonDoc, jsonPayload);

    if (client.connect(SERVER, PORT))
    {
        // POST request
        Serial.println("POST " + ENDPOINT + " HTTP/1.1");
        client.println("POST " + ENDPOINT + " HTTP/1.1");
        // send Headers
        send_headers(jsonPayload.length());
        // send Payload
        Serial.println(jsonPayload);
        client.println(jsonPayload);

        while (client.connected() || client.available())
        {
            if (client.available())
            {
                // Process the response
                char response = client.read();
                Serial.println(response);
                if (strstr(response, "200 OK") != NULL)
                {
                    Serial.println(F("=> API call successful: 200 OK"));
                    //...

                    res = true;
                } else if (strstr(response, "401" != NULL)
                {
                    Serial.println(F("=> API call failed: 401 Unauthorized"));
                    Serial.println(F("---Invalidate token and get new one---"));

                    api_login();

                    //TODO: retry but not too many times or too fast
                    // retry
                    api_call(new_state, cam_id);
                    break; break; break;
                } else
                {
                    Serial.println(F("API call failed"));
                    //...

                    res = false;
                }
            }
        }
        client.stop();
    }
}

bool set_parameters(String deviceSN, String stationSN, int param_type, int param_value)
{
    // make request
    DynamicJsonDocument jsonDoc(capacity);
    jsonDoc["device_sn"] = deviceSN;
    jsonDoc["stations_sn"] = stationSN;
    jsonDoc["params"] = [
        {
            "param_type": param_type,
            "param_value": param_value
        }
    ];

    String jsonPayload;
    serializeJson(jsonDoc, jsonPayload);

    if (client.connect(SERVER, PORT))
    {
        client.println("POST " + SET_PARAMETERS_ENDPOINT + " HTTP/1.1");
        // send Headers
        send_headers(jsonPayload.length()); //? TODO:
        // send Payload
        client.println(jsonPayload);

        while (client.connected() || client.available())
        {
            if (client.available())
            {
                // Process the response
                char response = client.read();
                Serial.println(response);
                if (strstr(response, "200 OK") != NULL)
                {
                    // TODO:
                    Serial.println("Succesfully set new parameters");
                    return true;
                }
                else
                {
                    Serial.println("Failed to set new parameters");
                    return false;
                }
            }
        }
        client.stop();
    }
    //?
    return false;
}

void refresh_device_data() // and station ?
{
    //TODO ...
}

void setup()
{
    // setup
    Serial.begin(9600);
    // delay(100);
    // start NTP
    timeClient.begin();
    preferences.begin("cam-states", false);

    if (wake_count == 0) // Run this only the first boot
    {
        Serial.println(F("Starting..."));
        ++wake_count;

        /* // if we want to set states on a per camera basis (TODO needs to change other things as well):
        for (int i = 0; i < sizeof(cameras) / sizeof(cameras[0]); i++)
        {
            char id_str[16];
            bool cam_state = getBool(itoa(cameras[i].id, id_str, 10), false);
            Serial.println("Init camera (id: %s) state as %s", id_str, cam_state ? "ON (true)" : "OFF (false)");
        }
        */
        bool cam_state = getBool(("state"), false);
        Serial.println("Init cameras state as %s", cam_state ? "ON (true)" : "OFF (false)");

        api_login(); // get token

        preferences.end();

        deep_sleep();
    }
    else
    {
        //++wake_count; // not needed?
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
from https://github.com/FuzzyMistborn/python-eufy-security/blob/dev/eufy_security/api.py

async def async_authenticate(self) -> None:
    """Authenticate and get an access token."""
    auth_resp = await self.request(
        "post",
        "passport/login",
        json={"email": self._email, "password": self._password},
    )
    data = auth_resp["data"]

    self._retry_on_401 = False
    self._token = data["auth_token"]
    self._token_expiration = datetime.fromtimestamp(data["token_expires_at"])
    domain = data.get("domain")
    if domain:
        self._api_base = f"https://{domain}/v1"
        _LOGGER.info("Switching to another API_BASE: %s", self._api_base)


async def async_update_device_info(self) -> None:
    """Get the latest device info."""
    devices_resp = await self.request("post", "app/get_devs_list")
    self.devices.update(devices_resp["data"])

    stations_resp = await self.request("post", "app/get_hub_list")
    self.stations.update(stations_resp["data"])


async def async_set_params(self, device: Device, data: dict) -> None:
    """Set device parameters."""
    params = Params()
    params.update(data)
    serialized_params = [param.param_info for param in params]

    if device.is_station:
        await self.request(
            "post",
            "app/upload_hub_params",
            json={
                "station_sn": device.station_serial,
                "params": serialized_params,
            },
        )
    else:
        await self.request(
            "post",
            "app/upload_devs_params",
            json={
                "device_sn": device.serial,
                "station_sn": device.station_serial,
                "params": serialized_params,
            },
        )

*/

/*
from https://github.com/JanLoebel/eufy-node-client/blob/master/src/p2p/cloud-lookup.service.ts

CloudLookup (for p2p):

export interface Address {
  host: string;
  port: number;
}

private addresses: Array<Address> = [
{ host: '54.223.148.206', port: 32100 },
{ host: '18.197.212.165', port: 32100 },
{ host: '13.251.222.7', port: 32100 },

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
