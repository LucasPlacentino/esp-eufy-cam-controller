// MIT License
// by Lucas Placentino
// Eufy Cam Controller - ESP32

#include <Preferences.h>
#include SECRETS.h
#define TIME_TO_SLEEP 6000 // Time ESP32 will go to sleep (in seconds)

struct camera
{
    unsigned int id;
    bool active;
    String name;
    String ip;
}

//example
camera cam1 =
{
    1,
    true,
    "Indoor Cam 1",
    "192.168.0.141"
}

cameras = [cam1];

RTC_DATA_ATTR int wake_count = 0;

bool wifi_setup()
{
    //
}

bool wakeup()
{
    //
}

void deep_sleep()
{
    //
    esp_sleep_enable_timer_wakeup(TIME_TO_SLEEP * 1000000);
    esp_deep_sleep_start();
}

bool api_call()
{
    //
}

void setup()
{
    //setup
    delay(100);
  
    if(wake_count == 0) //Run this only the first boot
    {
        println("Starting...");
        ++wake_count;
    
    
        deep_sleep();
    } else
    {
        println("Waking up from deep sleep...");
        //++wake_count;
    
        if (esp_sleep_get_wakeup_cause() == ESP_SLEEP_WAKEUP_EXT0)
        {
            for (int i=0; i<sizeof cameras; i++)
            {
                println("Turning camera %s (id:%d) %s (ip: %s)\n", cameras[i].name, cameras[i].id, cameras[i].active ? "off" : "on", ip);
                api_call(!cameras[i].active, cameras[i].id); // enable or disable each camera
            }
        }
    }
}

void loop()
{
    //loop
}
