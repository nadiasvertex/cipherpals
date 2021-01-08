#!/bin/bash

clang++-11 -g -std=c++20 -stdlib=libc++ -lsodium -o hex_to_b64 hex_to_b64.cpp
clang++-11 -g -std=c++20 -stdlib=libc++ -lsodium -o xor_str xor_str.cpp
clang++-11 -g -std=c++20 -stdlib=libc++ -lsodium -o xor_crack_cipher xor_crack_cipher.cpp
clang++-11 -g -std=c++20 -stdlib=libc++ -lsodium -o xor_encipher_rk xor_encipher_rk.cpp
clang++-11 -g -std=c++20 -stdlib=libc++ -lsodium -lcrypto -o aes_decrypt aes_decrypt.cpp
clang++-11 -g -std=c++20 -stdlib=libc++ -lsodium -o aes_detect_ecb aes_detect_ecb.cpp

