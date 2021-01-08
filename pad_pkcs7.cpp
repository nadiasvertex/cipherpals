#include <algorithm>
#include <iostream>
#include <string>
#include <vector>

auto pad_pkcs7(std::string& data, int block_size) {
  auto padding_size = block_size - size(data);
  data.append(padding_size, std::string::value_type(padding_size));
}

int main(int argc, const char *argv[]) {

  if (argc != 3 ) {
	  std::cout << "usage: pad_pkcs7 block_length <string>\n";
  }

  std::string data(argv[2]);
  auto block_size = std::stoul(std::string(argv[1]));
  pad_pkcs7(data, block_size);
  
  std::cout << "padding size: " << std::to_string(int(data.back())) << std::endl;

  return 0;
}
