#define CATCH_CONFIG_MAIN  // This tells Catch to provide a main()
#include "catch.hpp"

#include "device_crypto.h"
#include "util.h"

TEST_CASE("Should encrypt and decrypt a string") {
    unsigned char device_id[DEVICE_ID_LEN];
    DeviceCrypto::generate_random_bytes(device_id, DEVICE_ID_LEN);

    unsigned char device_master_key[DEVICE_MASTER_KEY_LEN];
    DeviceCrypto::generate_random_bytes(device_master_key, DEVICE_MASTER_KEY_LEN);

    SECTION("Basic decrypt/encrypt") {
      unsigned char device_key[DEVICE_KEY_LEN];
      DeviceCrypto::generate_device_key(device_master_key, device_id, device_key);

      DeviceCrypto encryptor(device_key, device_id);
      std::string plaintext = "This is what I want to encrypt, will it work or not?";
      std::cout << "Plaintext: " << plaintext << std::endl;

      EncryptedMessage * m = new EncryptedMessage();
      encryptor.encrypt(plaintext, m);

      print_buf("device_master_key", device_master_key, sizeof(device_master_key));
      print_buf("device_id", device_id, sizeof(device_id));
      print_buf("ciphertext", m->ciphertext, sizeof(m->ciphertext));
      print_buf("tag", m->ciphertext + (m->ciphertext_len - TAG_LEN), TAG_LEN);
      print_buf("iv", m->iv, sizeof(m->iv));

      DeviceCrypto decryptor(device_master_key);

      std::string decrypted = decryptor.decrypt(m);
      std::cout << "Decrypted: " << decrypted << std::endl;
      REQUIRE(decrypted.compare(plaintext) == 0);
      delete m;
    }

    SECTION("Encrypt multiple times") {
      unsigned char device_key[DEVICE_KEY_LEN];
      DeviceCrypto::generate_device_key(device_master_key, device_id, device_key);
      DeviceCrypto encryptor(device_key, device_id);
      std::string plaintext = "Plaintext to encrypt";
      std::string plaintext2 = "Plaintext to encrypt2";
      std::string plaintext3 = "Plaintext to encrypt3";

      EncryptedMessage * m = new EncryptedMessage();
      encryptor.encrypt(plaintext, m);
      EncryptedMessage * m2 = new EncryptedMessage();
      encryptor.encrypt(plaintext2, m2);
      EncryptedMessage * m3 = new EncryptedMessage();
      encryptor.encrypt(plaintext3, m3);

      DeviceCrypto decryptor(device_master_key);

      std::string decrypted = decryptor.decrypt(m);
      std::string decrypted2 = decryptor.decrypt(m2);
      std::string decrypted3 = decryptor.decrypt(m3);

      REQUIRE(decrypted.compare(plaintext) == 0);
      REQUIRE(decrypted2.compare(plaintext2) == 0);
      REQUIRE(decrypted3.compare(plaintext3) == 0);
      delete m;
      delete m2;
      delete m3;
    }

    SECTION("Encrypt empty string") {
      unsigned char device_key[DEVICE_KEY_LEN];
      DeviceCrypto::generate_device_key(device_master_key, device_id, device_key);
      DeviceCrypto encryptor(device_key, device_id);
      std::string plaintext = "";

      EncryptedMessage * m = new EncryptedMessage();
      encryptor.encrypt(plaintext, m);
      DeviceCrypto decryptor(device_master_key);

      std::string decrypted = decryptor.decrypt(m);

      REQUIRE(decrypted.compare(plaintext) == 0);
      delete m;
    }

    SECTION("Fail with invalid tag") {
      unsigned char device_key[DEVICE_KEY_LEN];
      DeviceCrypto::generate_device_key(device_master_key, device_id, device_key);
      DeviceCrypto encryptor(device_key, device_id);
      std::string plaintext = "";
      EncryptedMessage * m = new EncryptedMessage();
      encryptor.encrypt(plaintext, m);

      DeviceCrypto decryptor(device_master_key);

      // Flip a bit to test bad tag
      m->ciphertext[m->ciphertext_len - 1] = m->ciphertext[m->ciphertext_len] ^= 1;
      REQUIRE_THROWS(decryptor.decrypt(m));
      delete m;
    }
    
    SECTION("Fail with invalid ciphertext") {
      unsigned char device_key[DEVICE_KEY_LEN];
      DeviceCrypto::generate_device_key(device_master_key, device_id, device_key);
      DeviceCrypto encryptor(device_key, device_id);
      std::string plaintext = "";
      EncryptedMessage * m = new EncryptedMessage();
      encryptor.encrypt(plaintext, m);

      DeviceCrypto decryptor(device_master_key);

      // Flip a bit to test bad ciphertext
      m->ciphertext[0] = m->ciphertext[0] ^= 1;
      REQUIRE_THROWS(decryptor.decrypt(m));
    }

    SECTION("Fail with invalid ciphertext length") {
      unsigned char device_key[DEVICE_KEY_LEN];
      DeviceCrypto::generate_device_key(device_master_key, device_id, device_key);
      DeviceCrypto encryptor(device_key, device_id);
      std::string plaintext = "";

      EncryptedMessage * m = new EncryptedMessage();
      encryptor.encrypt(plaintext, m);
      DeviceCrypto decryptor(device_master_key);

      // Change ciphertext length
      m->ciphertext_len += 1;
      REQUIRE_THROWS(decryptor.decrypt(m));
    }

    SECTION("Fail if encrypt in decrypt mode") {
      DeviceCrypto decryptor(device_master_key);
      std::string plaintext = "";

      REQUIRE_THROWS(decryptor.encrypt(plaintext, new EncryptedMessage()));
    }

    SECTION("Fail if decrypt in encrypt mode") {
      unsigned char device_key[DEVICE_KEY_LEN];
      DeviceCrypto::generate_device_key(device_master_key, device_id, device_key);
      DeviceCrypto encryptor(device_key, device_id);
      std::string plaintext = "";
      EncryptedMessage * m = new EncryptedMessage();
      encryptor.encrypt(plaintext, m);
      DeviceCrypto decryptor(device_master_key);

      REQUIRE_THROWS(encryptor.decrypt(m));
    }
 }

