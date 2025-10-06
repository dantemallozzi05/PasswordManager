#pragma once
#include <string>
#include <vector>

namespace Crypto {


	struct KdfParams {
		unsigned long long opslimit = 3; // interactive cost
		size_t memlimit = 64 * 1024 * 1024; //64 MB
		std::vector<unsigned char> salt; // SALTBYTES (16)

	};

	bool deriveKey(const std::string& master, const KdfParams& kdf, std::vector<unsigned char>& outKey);

	bool encrypt(const std::vector<unsigned char>& key, const std::vector<unsigned char> nonce24, const std::string& plaintext, std::string& outCiphertext864);

	bool decrypt(const std::vector<unsigned char>& key, const std::vector<unsigned char>& nonce24, const std::string& ciphertext864, std::string& outPlainText);

	std::vector<unsigned char> randomBytes(size_t n);
	void secureZero(void* p, size_t n);
	std::string b64encode(const std::vector<unsigned char>& v);
	std::vector<unsigned char> b64decode(const std::string& s);


}