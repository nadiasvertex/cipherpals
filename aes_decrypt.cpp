#include <sodium.h>

#include <openssl/conf.h>
#include <openssl/err.h>
#include <openssl/evp.h>

#include <algorithm>
#include <cassert>
#include <iostream>
#include <fstream>
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

auto aes_128_ecb_decrypt(const std::vector<std::byte> &cipher_text,
                         const std::string &key, const std::string &iv)
    -> std::string {
  EVP_CIPHER_CTX *ctx;
  int len = 0;
  if (!(ctx = EVP_CIPHER_CTX_new())) {
    ERR_print_errors_fp(stderr);
    abort();
  }

  if (1 != EVP_DecryptInit(ctx, EVP_aes_128_ecb(),
                           reinterpret_cast<const unsigned char *>(key.data()),
                           reinterpret_cast<const unsigned char *>(iv.data()))) {
    ERR_print_errors_fp(stderr);
    abort();
  }

  std::string plain_text(1<<20, 0);
  int plain_text_len = 0; 
  if (1 != EVP_DecryptUpdate(ctx,
                           reinterpret_cast<unsigned char *>(plain_text.data()),
                           &len,
                           reinterpret_cast<const unsigned char *>(cipher_text.data()),
			   size(cipher_text))) {
    ERR_print_errors_fp(stderr);
    abort();
  }
  
  plain_text_len = len;

  if (1 != EVP_DecryptFinal(ctx,
                           reinterpret_cast<unsigned char *>(plain_text.data()) + plain_text_len,
                           &len)) {
    ERR_print_errors_fp(stderr);
    abort();
  }
 
  plain_text_len += len;

  EVP_CIPHER_CTX_free(ctx);
 
  plain_text.resize(plain_text_len);
  return plain_text;
}

int main(int argc, const char *argv[]) {
  if (argc < 2) {
    std::cerr << "usage: aes_decrypt <key>\n";
    return 1;
  }

  std::string key(argv[1]);
  std::string b64_text;
  
  if (argc == 3) {
	  std::ifstream in(argv[2]);
	  
  for (std::string line; std::getline(in, line);) {
    b64_text += line;
  }

   
  } else {
  for (std::string line; std::getline(std::cin, line);) {
    b64_text += line;
  }
  }
  

  auto kv = string_to_vector(key);

  auto cipher_bin = b64_to_bin(b64_text);
  auto plain_text = aes_128_ecb_decrypt(cipher_bin, key, key);

  std::cout << plain_text << std::endl;

  return 0;
}
