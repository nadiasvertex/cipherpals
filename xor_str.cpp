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
  std::cout << size(in) << std::endl;
  std::cout << out << std::endl;
  std::transform(begin(in), end(in), begin(out),
                 [](auto b) { return static_cast<char>(b); });
  std::cout << out << std::endl;
  return out;
}

auto string_to_vector(const std::string &in) -> std::vector<std::byte> {
  std::vector<std::byte> out(size(in));
  std::transform(begin(in), end(in), begin(out),
                 [](auto b) { return static_cast<std::byte>(b); });
  return out;
}

int main(int argc, const char *argv[]) {
  if (argc < 3) {
    std::cerr << "usage: xor_str <hex_string> <hex_string>\n";
    return 1;
  }

  std::string hex1(argv[1]);
  std::string hex2(argv[2]);

  auto v1 = hex_to_bin(hex1);
  auto v2 = hex_to_bin(hex2);
  std::vector<std::byte> v3(size(v1));
  std::transform(begin(v1), end(v1), begin(v2), begin(v3),
                 [](auto a, auto b) { return a ^ b; });
  std::cout << bin_to_hex(v3) << std::endl;
  return 0;
}
