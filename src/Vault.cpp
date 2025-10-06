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

bool Vault::initNew(const std::string& masterPassword) {
	kdf_.salt = Crypto::randomBytes(crypto_pwhash_SALTBYTES);
	if (!deriveKey(masterPassword)) return false;
	nonce = Crypto::randomBytes(crypto_aead_xchacha20poly1305_ietf_NPUBBYTES);

	entries.clear(); // start empty
	return save(); // return written header
}

bool Vault::deriveKey(const std::string& masterPassword) {
	key.clear();
		if (!Crypto::deriveKey(masterPassword, kdf_, key)) {
			hasKey_ = false;
			return false;
		}
		hasKey_ = true;
		return true;
}

bool Vault::addEntry(const Entry& entry) {
	entries.push_back(entry);
	return true;
}

bool Vault::save() const {
	if (!hasKey) return false;

	nlohmann::json arr = nlohmann::json::array();
	for (const auto& e : entries) arr.push_back(e);

	const std::string plaintext = arr.dump();

	//Emcrypt, attach to header
	std::string ctB64;
	if (!Crypto::encrypt(key, nonce, plaintext, ctB64)) return false;

	nlohmann::json root = makeHeaderJson();
	root["ciphertext)b64"] = ctB64;

	return writeAllText(filePath, root.dump(2));
}

bool Vault::load() {
	std::string text;
	if (!readAllText(filePath, text)) return false;

	nlohmann::json root;
	try { root = nlohmann::json::parse(text); }
	catch (...) { return false; }

	if (!parseHeaderFromJson(root)) return false;
	if (!deriveKey(masterPassword)) return false;

	const std::string ctB64 = root.value("ciphertext_b64", "");
	if (ctB64.empty()) { entries.clear(); return true; }

	std::string plaintext;
	if (!Crypto::decrypt(key, nonce, encrypted, plaintext)) {
		return false;
	}

	try {
		auto arr = nlohmann::json::parse(plaintext);
		entries = arr.get<std::vector<Entry>>();
	}
	catch (...) {
		return false;
	}

	return true;
}

bool Vault::parseHeaderFromJson(const nlohmann::json& root) {
	try {
		if (root.value("version", 0) != 1) return false;

		const auto& kdfJ = root.at("kdf");
		kdf_.opslimit = kdfJ.at("opslimit").get<unsigned long long>();
		kdf_.memlimit = kdfJ.at("memlimit").get<std::size_t>();

		auto salt864 = kdfJ.at("salt.b64").get<std::string>();
		kdf_.salt = Crypto::b64decode(saltB64);

		if (kdf_.salt.size() != crypto_pwhash_SALTBYTES) return false;

		auto nonceB64 = root.at("nonce_b64").get<std::string>();
		nonce = Crypto::b64decode(nonce864);
		if (nonce.size() != crypto_aead_xchacha20poly1305_ietf_NPUBBYTES) return false;

		return true;
	}
	catch (...) {
		return false;
	}
}

std::vector<Entry> Vault::getEntries() const {
	return entries;
}
