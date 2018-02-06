#include "device_crypto.h"

using namespace CryptoPP;

DeviceCrypto::DeviceCrypto(
  unsigned const char * device_key, 
  unsigned const char * device_id) {
    memcpy(this->device_key, device_key, DEVICE_KEY_LEN);
    memcpy(this->device_id, device_id, DEVICE_ID_LEN);
    this->crypto_mode = ENCRYPT;
}

DeviceCrypto::DeviceCrypto(unsigned const char * device_master_key) {
  memcpy(this->device_master_key, device_master_key, DEVICE_MASTER_KEY_LEN);
  this->crypto_mode = DECRYPT;
}

// Uses tomcrypt to generate random bytes
void DeviceCrypto::generate_random_bytes(unsigned char * buf, unsigned long len) {
   int x = rng_get_bytes(buf, len, NULL);
   
   if (x != len) {
      throw "Error generating random bytes";
   }
}

// Uses crypto++ hmac to generate a device key
void DeviceCrypto::generate_device_key(
  const unsigned char * device_master_key,
  const unsigned char * device_id,
  unsigned char * device_key) {

    // Device key len should not be set to anything above what we generate with HMAC
    if (DEVICE_KEY_LEN > SHA256::DIGESTSIZE) {
      throw "Device key length is too high, must be below" + SHA256::DIGESTSIZE;
    }

    // Initialize the HMAC
    HMAC<SHA256> hmac(device_master_key, DEVICE_MASTER_KEY_LEN);
    hmac.Update(device_id, DEVICE_ID_LEN);

    // Output the HMAC output, and copy the first DEVICE_KEY_LEN bytes into the key
    unsigned char digest_output[SHA256::DIGESTSIZE];
    hmac.Final(digest_output);
    memcpy(device_key, digest_output, DEVICE_KEY_LEN);
}

void DeviceCrypto::encrypt(std::string message, EncryptedMessage * enc) {
  if (this->crypto_mode != ENCRYPT) {
    throw "Must be in encrypt mode to encrypt";
  }
  generate_random_bytes(enc->iv, IV_LEN);;
  // Convert to unsigned char *
  unsigned char plaintext[message.length()];
  strcpy((char *)plaintext, message.c_str());
   
  enc->ciphertext = new unsigned char[sizeof(plaintext) + TAG_LEN];
  enc->ciphertext_len = sizeof(plaintext) + TAG_LEN;
  memcpy(enc->device_id, this->device_id, DEVICE_ID_LEN);
  
  encrypt_gcm(
    this->device_key, 
    plaintext, 
    enc->ciphertext, 
    enc->ciphertext + sizeof(plaintext), 
    enc->iv, 
    sizeof(plaintext));
}

std::string DeviceCrypto::decrypt(EncryptedMessage * m) {
  if (this->crypto_mode != DECRYPT) {
    throw "Must be in decrypt mode to decrypt";
  }
  unsigned char device_key[DEVICE_KEY_LEN];
  generate_device_key(
    this->device_master_key, 
    m->device_id, 
    device_key);

  return decrypt_gcm(device_key, m->iv, m->ciphertext, m->ciphertext_len);
}

// Uses tomcrypt to encrypt a plaintext
void DeviceCrypto::encrypt_gcm(
  const unsigned char * key,           // Encryption key
  unsigned char * plaintext,           // Plaintext to encrypt
  unsigned char * ciphertext,          // Resulting ciphertext
  unsigned char * tag,                 // Resulting tag, for authentication
  unsigned char * iv,                  // IV
  size_t plaintext_len) {              // Length of plaintext and ciphertext

    gcm_state     gcm;
    int           err;
    unsigned long tag_len = TAG_LEN;

    register_cipher(&aes_desc);
    
    if ((err =
      gcm_init(&gcm, find_cipher("aes"), key, DEVICE_KEY_LEN)) != CRYPT_OK) {
        throw "Error initializing GCM cipher, code: " + err;
    }  
    /* reset the state */ if ((err = gcm_reset(&gcm)) != CRYPT_OK) {
        throw "Error resetting GCM cipher, code: " + err;
    }
    /* Add the IV */
    if ((err = gcm_add_iv(&gcm, iv, IV_LEN)) != CRYPT_OK) {
        throw "Error adding IV, code: " + err;
    }
    /* process the plaintext */
    if ((err =
      gcm_process(&gcm, plaintext, plaintext_len, ciphertext, GCM_ENCRYPT)) != CRYPT_OK) {
        throw "Error encrypting, code: " + err;
    }
    /* Finish up and get the MAC tag */
    if ((err = gcm_done(&gcm, tag, &tag_len)) != CRYPT_OK) {
        throw "Error finalizing, code: " + err;
    }
}

std::string DeviceCrypto::decrypt_gcm(
  unsigned char * key,
  unsigned char * iv,
  unsigned char * ciphertext,
  size_t ciphertext_len) {
    std::string recovered;
    GCM< AES >::Decryption d;
    d.SetKeyWithIV( key, DEVICE_KEY_LEN, iv, IV_LEN);

    AuthenticatedDecryptionFilter df(d,
        new StringSink(recovered),
            AuthenticatedDecryptionFilter::DEFAULT_FLAGS,
            TAG_LEN
        );
      
    StringSource(ciphertext, ciphertext_len, true, new Redirector(df));

    if (!df.GetLastResult()) {
      throw "Tag validation failed";
    }

    return recovered;
}

