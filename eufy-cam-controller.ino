// MIT License
// by Lucas Placentino

// Eufy Cam Controller - ESP32

#include SECRETS.h

struct camera {
  unsigned int id;
  String name;
  String ip;
  bool active;

}

//example
camera cam1 = {
  1,
  "Indoor Cam 1",
  "192.168.0.141",
  true
}

bool wifi_setup() {
  //
}

bool wifi_wakeup() {
  //
}

void wifi_sleep() {
  //
}

bool api_call() {
  //
}

void setup() {
  //setup
}

void loop() {
  //loop
}
