#include "Vault.h"
#include "crypto.h"
#include <nlohmann/json.hpp>
#include <fstream>

Vault::Vault(const std::string& path, const std::string& masterPassword) : filePath(path) {
	Crypto::KdfParams kdf;
	kdf.salt = Crypto::randomBytes(crypto_pwhash_SALTBYTES);
	Crypto::deriveKey(masterPassword, kdf, key);
	nonce = Crypto::randomBytes(crypto_aead_xchacha20poly1305_ietf_NPUBBYTES);

}

bool Vault::addEntry(const Entry& entry) {
	entries.push_back(entry);
	return true;
}

bool Vault::save() {
	nlohmann::json j = entries;
	std::string plaintext = j.dump();

	std::string encrypted;
	if (!Crypto::encrypt(key, nonce, plaintext, encrypted))
		return false;

	std::ofstream ofs(filePath, std::ios::binary);
	ofs << encrypted;
	return true;
}

bool Vault::load() {
	std::ifstream ifs(filePath, std::ios::binary);
	if (!ifs.is_open()) return false;

	std::string encrypted((std::istreambuf_iterator<char>(ifs)), {});
	std::string plaintext;
	if (!Crypto::decrypt(key, nonce, encrypted, plaintext)) {
		return false;
	}

	return true;
}

std::vector<Entry> Vault::getEntries() const {
	return entries;
}
