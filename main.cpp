#define VAR1 100

#include <iostream>
#include <vector>
#include <fstream>
#include <climits>
#include <bitset>
#include <iomanip>

#include "cryptlib.h"
#include "cryptopp600/files.h"
#include "cryptopp600/hex.h"
#include "cryptopp600/sha.h"
#include "cryptopp600/hmac.h"
#include "cryptopp600/osrng.h"

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

