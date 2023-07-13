# eufy-cam-controller
ESP32 controller for Eufy Cameras: enable/disable cameras, detection, etc from a simple hardware button.

### 💖 This wouldn't be possible without [bropat/eufy-security-client](https://github.com/bropat/eufy-security-client/), all credit for the reverse-engineered API is thanks to his project and its contributors.

## Set up
- Secrets, such as Wifi SSID and password, Eufy account etc, must be put in a `SECRETS.h` file. See [`SECRETS.h_template`](/SECRETS.h_template) for reference.
- Parameters are located in [`PARAMS.h`](/PARAMS.h).

## Author
[Lucas Placentino](https://github.com/LucasPlacentino)

## License
[MIT](/LICENSE)