#include <sodium.h>

#include <openssl/conf.h>
#include <openssl/err.h>
#include <openssl/evp.h>

#include <algorithm>
#include <cassert>
#include <fstream>
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

auto b64_to_bin(const std::string &b64) -> std::vector<std::byte> {
  std::vector<std::byte> bin(size(b64));
  std::size_t bin_len = 0;
  sodium_base642bin(reinterpret_cast<unsigned char *const>(bin.data()),
                    bin.size(), reinterpret_cast<const char *const>(b64.data()),
                    b64.size(), nullptr, &bin_len, nullptr,
                    sodium_base64_VARIANT_ORIGINAL);
  bin.resize(bin_len);
  return bin;
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
  std::vector<std::vector<std::byte>> cipher_texts, blocks, unique_blocks;
  std::vector<int> block_count;

  if (argc == 2) {
    std::ifstream in(argv[1]);

    for (std::string line; std::getline(in, line);) {
      cipher_texts.emplace_back(hex_to_bin(line));
    }

  } else {
    for (std::string line; std::getline(std::cin, line);) {
      cipher_texts.emplace_back(hex_to_bin(line));
    }
  }

  for (const auto &cipher_text : cipher_texts) {
    for (auto pos = begin(cipher_text); pos != end(cipher_text);) {
      auto next_pos = std::next(pos, 16);
      blocks.emplace_back(std::vector(pos, next_pos));
      pos = next_pos;
    }
  }

  unique_blocks = blocks;
  std::sort(begin(unique_blocks), end(unique_blocks));
  unique_blocks.erase(std::unique(begin(unique_blocks), end(unique_blocks)),
                      end(unique_blocks));

  for (const auto &block : unique_blocks) {
    block_count.emplace_back(std::count(begin(blocks), end(blocks), block));
  }

  for (auto i = 0; i < size(block_count); ++i) {
    if (block_count[i] < 2) {
      continue;
    }

    const auto &block = unique_blocks[i];
    for (const auto &cipher_text : cipher_texts) {
      if (std::search(begin(cipher_text), end(cipher_text), begin(block),
                      end(block)) != end(cipher_text)) {
        std::cout << bin_to_hex(cipher_text) << std::endl;
      }
    }
  }

  return 0;
}
