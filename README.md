# cryptoQT

This project has the following technical objectives:

1. Implement E2E encrypted chat over MQTT using AES-256 GCM.
2. Implement ephemeral key exchange & compute a shared secret with ML-KEM
3. Must run on an ESP32. Pi Pico support is possible as well.
4. The device is a peripheral, adding both Wi-Fi and chat over a serial interface. This way it can be added to many other devices.
5. It should be small and cheap, to the point of being disposable.

Less technically, it lets you:

1. Plug it in to a device that doesn't have Internet access. Now it can connect to WiFi, but only for the purposes of engaging in E2E encrypted chat with exactly one other device. No other connectivity is permitted.
2. This simplifies endpoint security. Since it's only allowed & capable of doing one thing, and that one thing is completely on public channels, it's pretty easy to detect if it's doing anything else.
3. By implementing chat over public MQTT servers, there's no central provider.


There's no TLS support presently. I may add it later.

# Current Status

This is intended to be an interesting proof-of-concept, and an excuse to improve upon my sub-par C++. I need to test the latest refactor, that added a message buffer, which I am not sure even works.

Overall, I think it needs more work before I can recommend it for any serious use case.

