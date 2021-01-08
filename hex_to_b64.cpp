#include "sodium.h"

#include <algorithm>
#include <cassert>
#include <iostream>
#include <string>
#include <vector>

auto hex_to_base64(const std::vector<std::byte> &hex)
    -> std::vector<std::byte> {
  std::vector<std::byte> bin, b64;
  std::size_t bin_len = 0;

  bin.resize(hex.size());
  if (sodium_hex2bin(reinterpret_cast<unsigned char *const>(bin.data()),
                     bin.size(),
                     reinterpret_cast<const char *const>(hex.data()),
                     hex.size(), nullptr, &bin_len, nullptr) != 0) {
    assert(false);
  }
  bin.resize(bin_len);

  b64.resize(
      sodium_base64_encoded_len(bin.size(), sodium_base64_VARIANT_ORIGINAL));
  sodium_bin2base64(reinterpret_cast<char *const>(b64.data()),
                    b64.size(), reinterpret_cast<unsigned char *const>(bin.data()),
                    bin.size(), sodium_base64_VARIANT_ORIGINAL);

  b64.resize(size(b64)-1);
  return b64;
}

int main(int argc, const char *argv[]) {
  if (argc < 2) {
    std::cerr << "usage: hex_to_b64 <hex_string>\n";
    return 1;
  }

  std::string hex(argv[1]);
  std::vector<std::byte> hex_bytes(size(hex));
  std::transform(begin(hex), end(hex), begin(hex_bytes),
                 [](auto b) { return static_cast<std::byte>(b); });

  auto b64_bytes = hex_to_base64(hex_bytes);
  std::string b64(size(b64_bytes), 0);
  std::transform(begin(b64_bytes), end(b64_bytes), begin(b64),
                 [](auto b) { return static_cast<char>(b); });

  std::cout << b64 << std::endl;
  return 0;
}
