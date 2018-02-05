#define VAR1 100

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

#include <tomcrypt.h>

using namespace CryptoPP;


void generate_device_key(
  const byte * device_master_key,
  const byte * device_id,
  size_t dmk_size, 
  size_t did_size,
  byte * device_key) {
    HMAC<SHA256> hmac(device_master_key, dmk_size);
    hmac.Update(device_id, did_size);

    std::cout << HMAC<SHA256>::StaticAlgorithmName() << std::endl;
    hmac.Final(device_key);
}

void encrypt(
  const byte * device_key,
  const byte * message,
  const byte * ciphertext) {
    AutoSeededRandomPool rnd;

    // Generate a random IV
    byte iv[AES::BLOCKSIZE];
    rnd.GenerateBlock(iv, AES::BLOCKSIZE);

    std::string plaintext = "Hello bob!";
    int messageLen = (int)plaintext.length() + 1;

}

int main() {
    const byte m[] = {
      0x5,0x8,0xC,0xE,0x1,0xE,0x6,0x0,0x1,0x1,
      0x1,0x1,0x1,0x1,0x1,0x1,0x6,0x4,0x6,0x1,
      0x7,0x4,0x6,0x1,0x0,0x0,0x0,0x0
    };

    const byte k[] = {
      0x1,0x1,0x1,0x1,0x1,0x1,0x1,0x1,0x1,0x1,
      0x1,0x1,0x1,0x1,0x1,0x1,0x1,0x1,
      0x1,0x1,0x1,0x1,0x1,0x1,0x1,0x2,0x7
    };

    
    byte device_key[SHA256::DIGESTSIZE];

    generate_device_key(k, m, sizeof(k), sizeof(m), device_key);

    std::cout << "AES Blocksize:" << AES::BLOCKSIZE << std::endl;

    /* now given a 20 byte key what keysize does Twofish want to use? */
    int keysize = 64;
    int err = 0;
    if ((err = twofish_keysize(&keysize)) != CRYPT_OK) {
      printf("Error getting key size: %s\n", error_to_string(err));
    
    }
    printf("Twofish suggested a key size of %d\n", keysize);

    HexEncoder hex(new FileSink(std::cout));
    std::cout << "Message: ";
    hex.Put(m, sizeof(m));
    hex.MessageEnd();
    std::cout << std::endl;

    std::cout << "Digest: ";
    hex.Put(device_key, sizeof(device_key));
    hex.MessageEnd();
    std::cout << std::endl;
}

