#include <iostream>
#include <vector>
#include <fstream>
#include <climits>
#include <bitset>
#include <iomanip>

#include "cryptopp/cryptlib.h"
#include "cryptopp/files.h"
#include "cryptopp/hex.h"
#include "cryptopp/sha.h"
#include "cryptopp/hmac.h"
#include "cryptopp/osrng.h"
#include "cryptopp/gcm.h"
#include "cryptopp/aes.h"
#include "cryptopp/filters.h"

#include <tomcrypt.h>

#define DEVICE_KEY_LEN 32
#define DEVICE_MASTER_KEY_LEN 32
#define DEVICE_ID_LEN 32
#define IV_LEN 12
#define TAG_LEN 16

using namespace CryptoPP;

struct EncryptedMessage {
  unsigned char iv[IV_LEN];
  unsigned char device_id[DEVICE_ID_LEN];
  unsigned char * ciphertext;
  size_t ciphertext_len;

  EncryptedMessage() {
    ciphertext = NULL;
  }
  ~EncryptedMessage() {
    if (ciphertext != NULL) delete [] ciphertext;
  }
};

class DeviceCrypto {
  public:
    // Creates an object in encrypt mode, used by devices
    DeviceCrypto(unsigned const char * device_master_key, unsigned const char * device_id);
    
    // Creates an object in decrypt mode, used by server
    DeviceCrypto(unsigned const char * device_master_key);

    // Uses tomcrypt to generate random bytes
    static void generate_random_bytes(unsigned char * buf, unsigned long len);

    // Higher level function to encrypt a message. Uses device_id and device_key
    void encrypt(std::string message, EncryptedMessage* enc);

    // Higher level function to decrypt a message. Uses saved device_master_key
    std::string decrypt(EncryptedMessage * m);

  private:
    enum CryptoMode {
      ENCRYPT, DECRYPT
    } crypto_mode;

    unsigned char device_id[DEVICE_ID_LEN];
    unsigned char device_key[DEVICE_KEY_LEN];
    unsigned char device_master_key[DEVICE_KEY_LEN];

    // Uses crypto++ hmac to generate a device key
    void generate_device_key(
      const unsigned char * device_master_key,
      const unsigned char * device_id,
      unsigned char * device_key);


    // Uses tomcrypt to encrypt a plaintext
    void encrypt_gcm(
        const unsigned char * key,           // Encryption key
        unsigned char * plaintext,           // Plaintext to encrypt
        unsigned char * ciphertext,          // Resulting ciphertext
        unsigned char * tag,                 // Resulting tag, for authentication
        unsigned char * iv,                  // IV
        size_t plaintext_len);

    // Uses crypto++ to decrypt a ciphertext
    std::string decrypt_gcm(
      unsigned char * key,
      unsigned char * iv,
      unsigned char * ciphertext,
      size_t ciphertext_len);
};