#include <PQCMicro.h> // https://github.com/PratulDeshpande/PQCMicro
#include <WiFi.h>
#include <MQTT.h> // https://github.com/256dpi/arduino-mqtt/tree/master
#include <Crypto.h> // https://github.com/rweather/arduinolibs/tree/master/libraries/Crypto
#include <GCM.h> // Same as above
#include <AES.h> // Same as above

GCM<AES256> aes_gcm;

// Global Config
String ssid = ""; // optional but recommended -- pre-set the network the device is allowed to connect to
String password = ""; // optional but recommended -- pre-set the network the device is allowed to connect to
String server = "voltage.vn";
int port = 4242;
// End Global Config

// Global Vars
WiFiClient client;
MQTTClient mymqtt(2048); // Post-quantum public keys are huge, 800 bytes. 1600 since we encode as hex!
PQCKyber local;
PQCKyber remote; // we set it's pubkey
String localIdentifier;
String remoteIdentifier;
String remoteIdentifierTemp; //Store remote indentifier before acceptance
String remotePubkeyHex;
String currentPayload = ""; // The current message being typed
bool connected = false;
String messageList[2] = {}; // We can store inbound messages here as a buffer in case they aren ot read fast enough. Store up to 3 messages this way. We have plenty of RAM so String is fine.
int stringCount = 0;
// End Global Vars


void addString(char* newStr) { // add a message to the array of messages unless we've hit the max of 3 
  if (stringCount < 3) {
    messageList[stringCount] = newStr; 
    stringCount++;                      
  } else {
    Serial.print(25); // Output error indicating we're out of space in the array.
  }
}

int applyPKCS7Padding(uint8_t* input, int inputLength, uint8_t* output) {
    int paddingValue = 16 - (inputLength % 16);
    int paddedLength = inputLength + paddingValue;

    // Copy original data to output buffer
    for (int i = 0; i < inputLength; i++) {
        output[i] = input[i];
    }
    
    // Append the padding bytes
    for (int i = inputLength; i < paddedLength; i++) {
        output[i] = paddingValue;
    }

    return paddedLength;
}


byte charToNibble(char c) {
  if (c >= '0' && c <= '9') return c - '0';
  if (c >= 'a' && c <= 'f') return c - 'a' + 10;
  if (c >= 'A' && c <= 'F') return c - 'A' + 10;
  return 0; 
}

// Function to convert the full string into a target byte array
void hexStringToBytes(const char* hex, byte* bytes) {
  while (*hex) {
    byte high = charToNibble(*hex++);
    byte low = charToNibble(*hex++);
    *bytes++ = (high << 4) | low; // Combine high and low 4-bit sections
  }
}

void mqtt_reconnect(){
  int conn_count = 0;
while (!mymqtt.connect(localIdentifier.c_str(), "entropy", "azathoth")) {
    delay(500);
    Serial.print(6); // ACK that we're alive, WiFi connect underway
    delay(500);
    conn_count++;
    if (conn_count > 30){
      conn_count=0;
      Serial.print(24); // CANCEL we could not connect. Skip rest of config, allowing new config to be set, or EOT to reset.
      break;
    }
  }
  mymqtt.subscribe("entropy/" + localIdentifier);
}

void connect() {
  WiFi.begin(ssid.c_str(), password.c_str());
  int conn_count = 0;
  while (WiFi.status() != WL_CONNECTED) {
    delay(500);
    Serial.print(6); // ACK that we're alive, WiFi connect underway
    delay(500);
    conn_count++;
    if (conn_count > 30){
      conn_count=0;
      Serial.print(24); // CANCEL we could not connect. Skip rest of config, allowing new config to be set, or EOT to reset.
      break;
    }
  }

  while (!mymqtt.connect(localIdentifier.c_str(), "entropy", "azathoth")) {
    delay(500);
    Serial.print(6); // ACK that we're alive, WiFi connect underway
    delay(500);
    conn_count++;
    if (conn_count > 30){
      conn_count=0;
      Serial.print(24); // CANCEL we could not connect. Skip rest of config, allowing new config to be set, or EOT to reset.
      break;
    }
  }
}

void messageReceived(String &topic, String &payload) {
  // Chat requests are always 1616 characters long, and the first 12 characters repeat once, so we slice those off and pass on the rest.
 if (payload.length() == 1616 && !remote.hasPublicKey()){//can ignore if remote public key is already set
   String prefix1 = payload.substring(0,16);
   String prefix2 = payload.substring(16,32); 
   if (prefix1 == prefix2 && remoteIdentifier.length() > 0 && remoteIdentifier == prefix1){
     // If we are waiting for a specific public key, and it arrives correctly formatted, we can just accept it. 
     remotePubkeyHex = payload.substring(16);
     remote.setPublicKeyHex(remotePubkeyHex.c_str());
    }
 else if (prefix1 == prefix2){
   remoteIdentifierTemp = prefix1;
   remotePubkeyHex = payload.substring(16);
   Serial.print(5); // send ENQ -- received pubkey, user must be notified and validate it.
   } 
} else if (payload.substring(3,19)==remoteIdentifier && payload.substring(0,3)=="ct_" && !connected){
   String remoteCipherText = payload.substring(19);
   size_t byteCount = strlen(remoteCipherText.c_str()) / 2;
   uint8_t outputBytes[byteCount];
   hexStringToBytes(remoteCipherText.c_str(), outputBytes);
   connected = true;
   const uint8_t* remoteCipherBytes = outputBytes; 
   if (!local.decapsulate(remoteCipherBytes)) {
    Serial.print(24);
    connected = false;
    return;
  }
} else if (connected && payload.substring(0,3)=="cm_" && payload.substring(3,19)==remoteIdentifier){
  String hexIV = payload.substring(19,51); // characters 19-51 are the hex representation of the initialization vector
  String hexTag = payload.substring(51,83); // characters 51-83 are the hex representation of the gcm tag
  String hexCipherText = payload.substring(83); // All other characters are the ciphertext
  size_t byteCount = strlen(hexCipherText.c_str()) / 2;
  uint8_t encryptedBytes[byteCount];
  hexStringToBytes(hexCipherText.c_str(), encryptedBytes);
  uint8_t tagBytes[16];
  hexStringToBytes(hexTag.c_str(), tagBytes);
  uint8_t thisIV[16];
  hexStringToBytes(hexIV.c_str(), thisIV);
  char plaintext[1024];
  aes_gcm.setKey(local.getSharedSecret(), sizeof(local.getSharedSecret()));
  aes_gcm.setIV(thisIV, sizeof(thisIV)); 
  aes_gcm.addAuthData(remoteIdentifier.c_str(), sizeof(remoteIdentifier.c_str()));
  aes_gcm.decrypt((uint8_t*)plaintext, encryptedBytes, sizeof(encryptedBytes));
  if (!aes_gcm.checkTag(tagBytes, sizeof(tagBytes))) {
    Serial.print(24); // invalid message received
} else {
  // Valid message received!
    addString(plaintext);
    Serial.print(7); // Bell character for new message.
}
} else {
  // pass on all other cases
}

   }

void setup() {
  delay(200); // without this delay, there's a chance the serial monitor in Arduino causes a double-reset that's a pain during development. But only on esp32S3!
  int conn_count = 0;
  bool failState = false;
  Serial.begin(115200); // init serial port
  Serial.print(19); // XOFF -- We're busy doing setup
  WiFi.mode(WIFI_STA);
  WiFi.disconnect();
  unsigned long t0 = millis();
  if (!local.generateKeys()) {
    Serial.print(24); // CANCEL we could not connect. Skip rest of config, allowing new config to be set, or EOT to reset.
    return;
  }
  delay(200);
  localIdentifier = local.getPublicKeyHex().substring(0, 16);
  mymqtt.begin("voltage.vn", 4242, client);
  mymqtt.onMessage(messageReceived);
  connect(); 
  mymqtt.subscribe("entropy/" + localIdentifier);
  Serial.print(17); // Acknowledge ready to receive
}

void loop() {
  while (Serial.available() == 0){ // Device is plugged in, and we need to maintain connection. So no need for sleep modes.
  mymqtt.loop(); // check for any messages on my channel (my identifier)
  delay(200); // Calling the mqtt loop too often is a waste of power
  }
  int command = Serial.read(); // We've received a command, what is it?
        // Command list. Some artistic license taken with the standard control characters.
        // 01--SOH: Start chat request, send the public key characters, hex-encoded. Must terminate with 03--ETX.
        // 02--STX: Start text transmission. Must terminate with 03--ETX
        // 04--EOT: End of Transmission. Restart immediately, regenerating keys.
        // 05--ENQ: Return pending messages. Will begin each message with 02--STX and end each with 03--ETX.
        // 06--ACK: Accept chat request (requires received chat request). Will send remote identifier starting with 02--STX and end with 03--ETX. The sends XON to confirm we are awaiting a decision. Sending ACK accepts, anything else refuses.
        // 20--DC4: Return local identifier. Starts with 02--STX and ends with 03--ETX.
        // 18--XOFF: Return remote identifier if exists. Starts with 02--STX and ends with 03--ETX.
        // 26--SUB: Substitute current config with new config. Must begin each config item with 02--STX and end each with 03--ETX. There are 4 config items: wifi SSID, wifi password, MQTT server, and MQTT port. You must specify all of them. It's more secure to leave these hardcoded, but you may update them.
  
  switch (command) {
    case 1:
      if (connected){
        Serial.print(24); // We're already connected to a remote target, we should not send more chat requests out. Use RESET instead.
        break;
      }
      {
        Serial.print(17); // Acknowledge ready to receive
        while (Serial.available() == 0){
            delay(200); // just do whatever, we're waiting on input and it should block MQTT in the meantime'
          }
      char serialBuffer[17];
      size_t bytesRead = Serial.readBytesUntil('\x03', serialBuffer, 16); // This is also blocking on purpose, nothing should interrupt identifier reception
      serialBuffer[bytesRead] = '\0';
      remoteIdentifier = String(serialBuffer); // Setting this here determines behavior on receiving a public key, whether we respond with public key and ciphertext, or just repond with a public key.
      //We just did a blocking operation, check if mqtt is still connected. TODO: does this affect subscriptions?
      mqtt_reconnect();
      mymqtt.publish("entropy/"+remoteIdentifier, localIdentifier + local.getPublicKeyHex()); // Publish to remote, using local pubkey. We do otherwise for testing.
      //return
      break;
    }
    case 2:
      {
         if (!connected){
        Serial.print(24); // We're already connected to a remote target, we should not send more chat requests out. Use RESET instead.
        break;
      }
      // receive text
        char plaintextTemp[512];
        Serial.print(17);
 //       while (Serial.available() == 0){
 //           delay(200); // just do whatever, we're waiting on input and it should block MQTT in the meantime'
//          }
  //         while (Serial.available() > 0) {
  //   char incomingChar = Serial.read();
    
  //   // Check for the terminator character (e.g., newline '\n')
  //   if (incomingChar == '\x03') {
  //     break;
  //   } else {
  //     // Dynamically grows as new characters are appended
  //     plaintexttemp += incomingChar; 
  //   }
  // }
  // const char* plaintext = plaintexttemp; // explicitly convert to const char*
  // size_t bytesRead = sizeof(plaintext);
      //size_t bytesRead = Serial.readBytesUntil('\x03', plaintextTemp, 512); // This is also blocking on purpose, nothing should interrupt text sending. We support max 1024 characters per message.
      //plaintextTemp[bytesRead] = '\0';
      //const char plaintext[] = "plaintextTemphhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhh";
      const char plaintext[] = "plaintextplaintext";
      size_t bytesRead = sizeof(plaintext); // used to always return 1, so paddedbuffer would always return 16. strlen() gives the string length.
      uint8_t tag[16]; // tag is 16 bytes
      uint8_t thisIV[16];
      esp_fill_random(thisIV, 16);
      size_t paddedLen = bytesRead + (16 - (bytesRead % 16)); //This works now
      uint8_t paddedBuffer[paddedLen];
      applyPKCS7Padding((uint8_t*)plaintext, paddedLen, paddedBuffer);
      aes_gcm.setKey(local.getSharedSecret(), 32);
      aes_gcm.setIV(thisIV, 16); 
      aes_gcm.addAuthData(localIdentifier.c_str(), localIdentifier.length()); // Convert localIdentifier to c_String so we can use it here
      byte ciphertext[paddedLen]; // something fishy here, gcm.encrypt expects a pointer to output, but we pass a literal, thatm ight make it fail for anythingm ore than a few bytes.
      Serial.print(sizeof(ciphertext));
      Serial.print(sizeof(paddedBuffer));
      Serial.print(paddedLen);
      delay(100);
      aes_gcm.encrypt(ciphertext, paddedBuffer, paddedLen); //this fails when length is above 16 characters!!!
      Serial.print("OK!!!");
      aes_gcm.computeTag(tag, sizeof(tag));
      // Convert ciphertext to hex string
      size_t ciphertextSize = sizeof(ciphertext);
      char hexCiphertext[ciphertextSize * 2 + 1]; // Two characters per byte, plus null-terminator
      for (size_t i = 0; i < ciphertextSize; i++) {
        snprintf(&hexCiphertext[i * 2], 3, "%02X", ciphertext[i]);  // Uppercase hex
      }
      // Convert tag to hex string
      size_t tagSize = sizeof(tag);
      char hexTag[tagSize * 2 + 1]; // Two characters per byte, plus null-terminator, 32-byte tag
      for (size_t i = 0; i < tagSize; i++) {
        snprintf(&hexTag[i * 2], 3, "%02X", tag[i]);  // Uppercase hex
      }
      // Convert IV to hex string
      size_t IVSize = sizeof(thisIV);
      char hexIV[IVSize * 2 + 1]; // Two characters per byte, plus null-terminator, 16-byte initialization vector
       for (size_t i = 0; i < IVSize; i++) {
        snprintf(&hexIV[i * 2], 3, "%02X", thisIV[i]);  // Uppercase hex
      }
      mqtt_reconnect();
      mymqtt.publish("entropy/"+remoteIdentifier, "cm_" + localIdentifier + hexIV + hexTag + hexCiphertext);
      // delay(100);  there was an occasional restart that this seemed to help prevent, it no longer seems to occur, so removing it.
      break;
      }
    case 4:
      {
      ESP.restart(); // Stoically accept death.
      break;
      }
    case 5:
      {
        if (stringCount == 0){
          break; // No messages to return
        } else {
          Serial.print(2); // Indicate start of text
          Serial.print(String(messageList[stringCount-1])); // Return message
          Serial.print(3); // Indicate end of text
          messageList[stringCount-1] = ""; // Delete message
          stringCount--;
        }
      break;
      }
    case 6:
      { 
        if (connected){
        Serial.print(24); // We're already connected to a remote target, we should not be trying to accept more chat requests.
        break;
      }
          Serial.print(2);
          Serial.print(remoteIdentifierTemp.substring(0,16));
          Serial.print(3);
          Serial.print(17); // Awaiting decision
          while (Serial.available() == 0){
            delay(200); // just do whatever, we don't check mqtt so remote pubkey cannot change unexpectedly via callback.
          }
          int decision = Serial.read();
          if (decision == 6){ // Send ACK to accept, anything else cancels.
            if (remoteIdentifier.length() == 0){ // In this case, we have received a public key, so we compute a shared secret ciphertext, send the public key and ciphertext, and store our local copy of the shared secret.
              if (!local.encapsulate(remote.getPublicKey())) {
              Serial.print(24); // CANCEL something went wrong with encapsulation, invalid public key, clear it.
              remoteIdentifierTemp = String(); // Clear, invalid
              remotePubkeyHex = String(); // Clear, invalid
              return;
              }
          remote.setPublicKeyHex(remotePubkeyHex.c_str()); // As long as encapsulation succeeds, we need to set the remote public key the user has accepted.
          connected = true; //Also set global connected flag as we have computed the local shared secret and are ready to send messages.
          mqtt_reconnect();
              //Send pubkey first, then wait a second, ciphertext.
              mymqtt.publish("entropy/"+remoteIdentifierTemp, localIdentifier + local.getPublicKeyHex()); // If we have not yet set the remote identifier, it means that we did not send a pubkey yet. So we must reply to the request with ours.
              delay(1200);
              //It also means we need to send the ciphertext over
              mymqtt.publish("entropy/"+remoteIdentifierTemp, "ct_" + localIdentifier + local.getCiphertextHex());
              //Since we have both public keys and have computed the shared secret, se can store it.
            } else { // In this case, we actually don't have to do anything extra. It's someone replying to our request with a public key. The ciphertext will come through in a moment. 
              // We should never actually get here in normal operation, the public key we're wating for should be auto-detected and dropped on non-match.
    mqtt_reconnect();

            }


            remoteIdentifier = remoteIdentifierTemp;  // Has been confirmed by user
            remoteIdentifierTemp = String(); // Clear it out to recover memory.
            
            
  } else {
    remoteIdentifierTemp = String(); // clear these out, we've rejected the pubkey based on the identifier
    remotePubkeyHex = String();  // clear these out, we've rejected the pubkey based on the identifier
    }
      

     // mymqtt.publish("/"+remoteIdentifier, localIdentifier);
      // calculate shared secret from the pubkey
      break;
      }
    case 7:
    {
      Serial.print(2);
      Serial.print(localIdentifier);
      Serial.print(3);
      break;
    }
    case 8:
    {
      Serial.print(2);
      Serial.print(remoteIdentifier);
      Serial.print(3);
      break;
    }
    case 9:
      {
      // TODO implement some way for host machine to set config
      break;
      }
    default:
      {
         Serial.print(24); // Error, unknown command.
         break; // invalid command, return to state 0
      }
  }


}
