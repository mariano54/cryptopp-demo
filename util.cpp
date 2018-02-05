#include "util.h"

using namespace CryptoPP;
void print_buf(std::string name, unsigned char buf[], size_t size) {
    HexEncoder hex(new FileSink(std::cout));
    std::cout << name << ": ";
    hex.Put(buf, size);
    std::cout << std::endl;
}
