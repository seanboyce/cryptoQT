#include <PQCMicro.h> // https://github.com/PratulDeshpande/PQCMicro
#include <WiFi.h>
#include <MQTT.h> // https://github.com/256dpi/arduino-mqtt/tree/master
#include <Crypto.h> // https://github.com/rweather/arduinolibs/tree/master/libraries/Crypto
#include <GCM.h> // Same as above
#include <AES.h> // Same as above
#include <SHA256.h>

GCM<AES256> aes_gcm;
SHA256 MySHA256; //calling it SHA256 or hmac_SHA256 were both taken.

// Global Config. This needs to be loaded in on boot. Can be hardcoded. A config file from the UI app is also reasonable.
char localPermanentID[] = "9700J1OFr7E37Ku9BshKS4QMVEceaMD4"; //tr -dc A-Za-z0-9 </dev/urandom | head -c 32; echo
char remotePermanentID[] = "JAz2oy88yALzVZZatNpB3Bm42FltgFw8";
char* ssid;
char* password;
char* server;
int port;
char* serverUser;
char* serverPass;
char* channelPrefix;


// End Global Config

// Global Vars
String myHMAC;
char timeStamp[32]; //First 7 digits of the current Linux timestamp. Either auto-entered by interface or user entered.
WiFiClient client;
MQTTClient mymqtt(2048); // Post-quantum public keys are huge, 800 bytes. 1600 since we encode as hex!
PQCKyber local;
PQCKyber remote; // we set it's pubkey
String localIdentifier;
String remoteIdentifier;
String remotePubkeyHex;
String currentPayload = ""; // The current message being typed
bool connected = false;
String messageList[3] = {}; // We can store inbound messages here as a buffer in case they aren ot read fast enough. Store up to 3 messages this way. We have plenty of RAM so String is fine.
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
while (!mymqtt.connect(localIdentifier.c_str(), serverUser, serverPass)) {
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
  WiFi.begin(ssid, password);
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
  // Chat requests are always 1664 characters long. The first 64 chars are a hmac.
 if (payload.length() == 1664 && !remote.hasPublicKey()){//can ignore if remote public key is already set
   String prefix1 = payload.substring(0,64);
   String message = payload.substring(64);
     // If we are waiting for a specific public key, and it arrives correctly formatted, we can just accept it. 
     char hashData[1696];
     message.toCharArray(hashData, 1696);
     strcat(hashData,remotePermanentID);
     strcat(hashData,remoteIdentifier.c_str());
     const char *input = hashData;
     uint8_t hash[32];
     MySHA256.reset();
     MySHA256.update(input, strlen(input));
     MySHA256.finalize(hash, sizeof(hash));
     size_t hashSize = sizeof(hash);
     char ID_cstring[hashSize * 2 + 1]; // Two characters per byte, plus null-terminator
     for (size_t i = 0; i < hashSize; i++) {
        snprintf(&ID_cstring[i * 2], 3, "%02X", hash[i]);  // Uppercase hex
        }
        if (strcmp(ID_cstring, prefix1.c_str()) == 0){
        remote.setPublicKeyHex(payload.substring(64).c_str()); // only if OK do we set the remote public key
        Serial.println("Public key accepted");
        }

} else if (payload.length() == 3200){
  // Chat request responses are always (32+800+768)*2=3200 characters long. The first 64 chars are a hmac, then the public key, then the ciphertext. Sending it in one message removes a window for shenanigans.
   String prefix1 = payload.substring(0,64);
   String message = payload.substring(64);
   char hashData[3200];
     message.toCharArray(hashData, 3200);
     strcat(hashData,remotePermanentID);
     strcat(hashData,remoteIdentifier.c_str());
     const char *input = hashData;
     uint8_t hash[32];
     MySHA256.reset();
     MySHA256.update(input, strlen(input));
     MySHA256.finalize(hash, sizeof(hash));
     size_t hashSize = sizeof(hash);
     char ID_cstring[hashSize * 2 + 1]; // Two characters per byte, plus null-terminator
     for (size_t i = 0; i < hashSize; i++) {
        snprintf(&ID_cstring[i * 2], 3, "%02X", hash[i]);  // Uppercase hex
        }
        if (strcmp(ID_cstring, prefix1.c_str()) == 0){
        remote.setPublicKeyHex(payload.substring(64,1664).c_str()); // only if OK do we set the remote public key
        Serial.println("Public key accepted");
        String remoteCipherText = payload.substring(1664);
        size_t byteCount = strlen(remoteCipherText.c_str()) / 2;
        uint8_t outputBytes[byteCount];
        hexStringToBytes(remoteCipherText.c_str(), outputBytes);
        if (!local.decapsulate(remoteCipherBytes)) {
          Serial.print(24);
          connected = false;
          return;
        }
        }
        }
} else if (connected && payload.substring(0,3)=="cm_"){ //prefixing the messages is just a convenience. The GCM tag handles authentication here.
  String hexIV = payload.substring(3,35); // characters 19-51 are the hex representation of the initialization vector
  String hexTag = payload.substring(35,67); // characters 51-83 are the hex representation of the gcm tag
  String hexCipherText = payload.substring(67); // All other characters are the ciphertext
  size_t byteCount = strlen(hexCipherText.c_str()) / 2;
  uint8_t encryptedBytes[byteCount];
  hexStringToBytes(hexCipherText.c_str(), encryptedBytes);
  uint8_t tagBytes[16];
  hexStringToBytes(hexTag.c_str(), tagBytes);
  uint8_t thisIV[16];
  hexStringToBytes(hexIV.c_str(), thisIV);
  char plaintext[1024];
  aes_gcm.setKey(local.getSharedSecret(), 32);
  aes_gcm.setIV(thisIV, sizeof(thisIV)); 
  aes_gcm.addAuthData(remoteIdentifier.c_str(), remoteIdentifier.length());
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
  // TODO set CPU frequency to 80Mhz (we are I/O bound not processing bound) and try enabling WiFi sleep mode.
  setCpuFrequencyMhz(80);
  WiFi.setSleep(true); 
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
  
// We compute two deterministic channels from the first 7 digits of the timestamp and each shared secret. While these cannot be predicted before they are used, we should not trust them either.
// They can be re-used if the connection is broken, but if re-used within 17 minutes of the initial connection, it will be possible for an external observer to know that the same two devices contacted each other again.
// If used in a new window, it should not be possible to determine this without knowing both secret keys (partial metadata can be gleaned from one secret key).
// This feature just allows the two devices to connect to each other, and does not affect transmission security which uses ephemeral keys.
// Thre are 4 steps to this process:
// 1. Calculate the communication channels based on the secrets & timestamp.
// 2. Calculate a HMAC from my ephemeral public key and my secret, proving the public key is in fact from me.
// 3. Exchange keys via MQTT, can be automated without user input now.
// 4. can chat now. 

// As part of this, we'll remove case 6, and also we should probably automate case 1. If local channel ID > remote channelID, init comms.
char configBuffer[512];
        Serial.print(17);
        while (Serial.available() == 0){
            delay(200); // just do whatever, we're waiting on config input
          }
      size_t bytesRead = Serial.readBytesUntil('\x04', configBuffer, 512); // max 1024 characters of config. Items are separated by \x03 and terminated by \x04 
      configBuffer[bytesRead] = '\0';
      char* token = strtok(configBuffer, "\x03");
      if (token != NULL) {
        ssid = token; 
      } else {
        Serial.print(24);
      }
      token = strtok(NULL, "\x03");
      if (token != NULL) {
        password = token; 
      } else {
        Serial.print(24);
      }
      token = strtok(NULL, "\x03");
      if (token != NULL) {
        server = token; 
      } else {
        Serial.print(24);
      }
      token = strtok(NULL, "\x03");
      if (token != NULL) {
        port = atoi(token); 
      } else {
        Serial.print(24);
      }
      token = strtok(NULL, "\x03");
      if (token != NULL) {
        serverUser = token; 
      } else {
        Serial.print(24);
      }
      token = strtok(NULL, "\x03");
      if (token != NULL) {
        serverPass = token; 
      } else {
        Serial.print(24);
      }
      token = strtok(NULL, "\x03");
      if (token != NULL) {
        channelPrefix = token; 
      } else {
        Serial.print(24);
      }


  char hashData[1696]; //worst-case is public key hex [1600] plus permanentID [32] plus channelID hex [64] 
  memset(hashData, 0, sizeof(hashData));
  strcpy(hashData, localPermanentID);
  strcat(hashData, timeStamp);
  const char *input = hashData;
  uint8_t hash[32];
  MySHA256.reset();
  MySHA256.update(input, strlen(input));
  MySHA256.finalize(hash, sizeof(hash));
  size_t hashSize = sizeof(hash);
  char ID_cstring[hashSize * 2 + 1]; // Two characters per byte, plus null-terminator
  for (size_t i = 0; i < hashSize; i++) {
      snprintf(&ID_cstring[i * 2], 3, "%02X", hash[i]);  // Uppercase hex
      }
  localIdentifier = String(ID_cstring);

// OK, now compute the remote channel
  memset(hashData, 0, sizeof(hashData));
  strcpy(hashData, remotePermanentID);
  strcat(hashData, timeStamp);
  const char *input2 = hashData;
  MySHA256.reset();
  MySHA256.update(input2, strlen(input2));
  MySHA256.finalize(hash, sizeof(hash));
  hashSize = sizeof(hash);
  for (size_t i = 0; i < hashSize; i++) {
      snprintf(&ID_cstring[i * 2], 3, "%02X", hash[i]);  // Uppercase hex
      }
  remoteIdentifier = String(ID_cstring);
  
  //Finally, calculate the hash of my public key plus my permananent ID & channel. This will be used to identify myself when exchanging public keys. The channel is added to prevent replay.
  memset(hashData, 0, sizeof(hashData));
  strcpy(hashData, local.getPublicKeyHex().c_str());
  strcat(hashData, localPermanentID);
  strcat(hashData, localIdentifier.c_str());
  MySHA256.reset();
  MySHA256.update(input, strlen(input));
  MySHA256.finalize(hash, sizeof(hash));
  hashSize = sizeof(hash);
  for (size_t i = 0; i < hashSize; i++) {
      snprintf(&ID_cstring[i * 2], 3, "%02X", hash[i]);  // Uppercase hex
      }
  myHMAC = String(ID_cstring);
  mymqtt.begin(server, port, client);
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
      
      mqtt_reconnect();
      mymqtt.publish("entropy/"+remoteIdentifier, myHMAC + local.getPublicKeyHex()); // Publish to remote, using local pubkey.
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
        char plaintext[1024];
        Serial.print(17);
        while (Serial.available() == 0){
            delay(200); // just do whatever, we're waiting on input and it should block MQTT in the meantime'
          }
      size_t bytesRead = Serial.readBytesUntil('\x03', plaintext, 1024); // This is also blocking on purpose, nothing should interrupt text sending. We support max 1024 characters per message.
      plaintext[bytesRead] = '\0';
      uint8_t tag[16]; // tag is 16 bytes
      uint8_t thisIV[16];
      esp_fill_random(thisIV, 16);
      size_t paddedLen = bytesRead + (16 - (bytesRead % 16)); //This works now
      uint8_t paddedBuffer[paddedLen];
      applyPKCS7Padding((uint8_t*)plaintext, bytesRead, paddedBuffer);
      aes_gcm.setKey(local.getSharedSecret(), 32);
      aes_gcm.setIV(thisIV, 16); 
      aes_gcm.addAuthData(localIdentifier.c_str(), localIdentifier.length()); // Convert localIdentifier to c_String so we can use it here
      byte ciphertext[paddedLen]; // something fishy here, gcm.encrypt expects a pointer to output, but we pass a literal, thatm ight make it fail for anythingm ore than a few bytes.
      Serial.print(sizeof(ciphertext));
      Serial.print(sizeof(paddedBuffer));
      Serial.print(paddedLen);
      delay(100);
      aes_gcm.encrypt(ciphertext, paddedBuffer, paddedLen); //this fails when length is above 16 characters!!!
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
      mymqtt.publish("entropy/"+remoteIdentifier, "cm_" + String(hexIV) + hexTag + hexCiphertext);
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
          //Serial.print(remoteIdentifierTemp.substring(0,16));
          Serial.print(3);
          Serial.print(17); // Awaiting decision
          while (Serial.available() == 0){
            delay(200); // just do whatever, we don't check mqtt so remote pubkey cannot change unexpectedly via callback.
          }
          int decision = Serial.read();
          if (decision == 6){ // Send ACK to accept, anything else cancels.
            if (remoteIdentifier.length() == 0){ // In this case, we have received a public key, so we compute a shared secret ciphertext, send the public key and ciphertext, and store our local copy of the shared secret.
              remote.setPublicKeyHex(remotePubkeyHex.c_str());
              if (!local.encapsulate(remote.getPublicKey())) {
              Serial.print(24); // CANCEL something went wrong with encapsulation, invalid public key, clear it.
              //remoteIdentifierTemp = String(); // Clear, invalid
              remotePubkeyHex = String(); // Clear, invalid
              return;
              }
          connected = true; //Also set global connected flag as we have computed the local shared secret and are ready to send messages.
          mqtt_reconnect();
              //Send pubkey first, then wait a second, ciphertext.
              mymqtt.publish("entropy/"+remoteIdentifier, localIdentifier + local.getPublicKeyHex()); // If we have not yet set the remote identifier, it means that we did not send a pubkey yet. So we must reply to the request with ours.
              delay(1200);
              //It also means we need to send the ciphertext over
              mymqtt.publish("entropy/"+remoteIdentifier, "ct_" + local.getCiphertextHex());
              //Since we have both public keys and have computed the shared secret, se can store it.
            } else { // In this case, we actually don't have to do anything extra. It's someone replying to our request with a public key. The ciphertext will come through in a moment. 
              // We should never actually get here in normal operation, the public key we're wating for should be auto-detected and dropped on non-match.
    mqtt_reconnect();

            }

            
            
  } else {
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
