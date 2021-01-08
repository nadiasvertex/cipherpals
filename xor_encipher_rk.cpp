#include "sodium.h"

#include <algorithm>
#include <cassert>
#include <iostream>
#include <string>
#include <vector>

auto hex_to_bin(const std::string &hex) -> std::vector<std::byte> {
  std::vector<std::byte> bin;
  std::size_t bin_len = 0;

  bin.resize(hex.size());
  if (sodium_hex2bin(reinterpret_cast<unsigned char *const>(bin.data()),
                     bin.size(),
                     reinterpret_cast<const char *const>(hex.data()),
                     hex.size(), nullptr, &bin_len, nullptr) != 0) {
    assert(false);
  }
  bin.resize(bin_len);
  return bin;
}

auto bin_to_hex(const std::vector<std::byte> &bin) -> std::string {
  std::vector<std::byte> hex;
  hex.resize(bin.size() * 2 + 1);
  sodium_bin2hex(reinterpret_cast<char *const>(hex.data()), hex.size(),
                 reinterpret_cast<const unsigned char *const>(bin.data()),
                 bin.size());
  return std::string(reinterpret_cast<std::string::value_type *>(hex.data()));
}

auto vector_to_string(const std::vector<std::byte> &in) -> std::string {
  std::string out(size(in), 0);
  std::transform(begin(in), end(in), begin(out),
                 [](auto b) { return static_cast<char>(b); });
  return out;
}

auto string_to_vector(const std::string &in) -> std::vector<std::byte> {
  std::vector<std::byte> out(size(in));
  std::transform(begin(in), end(in), begin(out),
                 [](auto b) { return static_cast<std::byte>(b); });
  return out;
}

int main(int argc, const char *argv[]) {
  if (argc < 2) {
    std::cerr << "usage: xor_encipher_rk <key>\n";
    return 1;
  }

  std::string key(argv[1]);
  std::string plain_text;

  auto kv = string_to_vector(key);
  for (std::string line; std::getline(std::cin, line);) {
    plain_text += line;
    plain_text += "\r";
  }

  plain_text.resize(size(plain_text)-1);

  auto ptv = string_to_vector(plain_text);
  std::vector ctv(ptv);
  std::transform(begin(ptv), end(ptv), begin(ctv),
                 [&kv, key_index = 0](auto b) mutable {
                   auto i = key_index % size(kv);
                   ++key_index;
                   return b ^ kv[i];
                 });

  std::cout << bin_to_hex(ctv) << std::endl;
  return 0;
}
