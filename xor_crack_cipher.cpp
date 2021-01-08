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

auto decrypt(const std::vector<std::byte> &in, std::byte key)
    -> std::vector<std::byte> {
  std::vector out(in);
  std::transform(begin(out), end(out), begin(out),
                 [key](auto b) { return b ^ key; });
  return out;
}

auto score(const std::vector<std::byte> &frequency, const std::vector<std::byte> &text)
    -> int {
  int fscore = 0;
  int weight = size(frequency);
  for (const auto &c : frequency) {
    fscore += std::count(begin(text), end(text), c) * weight;
    weight--;
  }
  return fscore;
}

int main(int argc, const char *argv[]) {
  if (argc < 2) {
    std::cerr << "usage: xor_cipher <hex_string>\n";
    return 1;
  }

  std::string hex1(argv[1]);
  auto v1 = hex_to_bin(hex1);

  auto frequency = string_to_vector(std::string("etaoinsrhldcumfpgwybvkxjqz"));

  std::vector<std::vector<std::byte>> ds;
  for (auto i = 0; i < 256; ++i) {
    ds.emplace_back(decrypt(v1, std::byte(i)));
  }

  std::vector<int> scores(size(ds));
  std::transform(
      begin(ds), end(ds), begin(scores),
      [&frequency](const auto &text) { return score(frequency, text); });

  auto pos = std::max_element(begin(scores), end(scores));
  auto index = std::distance(begin(scores), pos);

  std::cout << vector_to_string(ds[index]) << std::endl;

  return 0;
}
