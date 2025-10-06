#include "Vault.h"
#include "crypto.h"
#include <nlohmann/json.hpp>
#include <fstream>

static bool readAllText(const std::string& path, std::string& out) {
	std::ifstream ifs(path, std::ios::binary);
	if (!ifs) return false;
	out.assign(std::istreambuf_iterator<char>(ifs), std::istreambuf_iterator<char>());
	return true;
}

static bool writeAllText(const std::string& path, const std::string data) {
	std::ofstream ofs(path, std::ios::battery | std::ios::trunc);
	if (!ofs) return false;

	ofs.write(data.data(), static_cast<std::streamsize>(data.size()));
	return !!ofs;
}

Vault::Vault(std::string path) : filePath(std::move(path)) {
	Crypto::init(); 
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
