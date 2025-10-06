#include "Vault.h"
#include "../include/crypto.h"
#include <nlohmann/json.hpp>
#include <fstream>
#include <iterator>
#include <sodium.h>

static bool readAllText(const std::string& path, std::string& out) {
	std::ifstream ifs(path, std::ios::binary);
	if (!ifs) return false;
	out.assign(std::istreambuf_iterator<char>(ifs), std::istreambuf_iterator<char>());
	return true;
}

static bool writeAllText(const std::string& path, const std::string& data) {
	std::ofstream ofs(path, std::ios::binary | std::ios::trunc);
	if (!ofs) return false;

	ofs.write(data.data(), static_cast<std::streamsize>(data.size()));
	return !!ofs;
}

static void wipeString(std::string& s) {
	if (!s.empty()) {
		Crypto::secureZero(s.data(), s.size());
		s.clear();
		s.shrink_to_fit();
	}
}

Vault::Vault(std::string path) : filePath(std::move(path)) {}

Vault::~Vault() {
	if (!key.empty()) Crypto::secureZero(key.data(), key.size());
	if (!nonce.empty()) Crypto::secureZero(nonce.data(), nonce.size());

	for (auto& e : entries) {
		if (!e.password.empty()) {
			Crypto::secureZero(e.password.data(), e.password.size());
			e.password.clear();
			e.password.shrink_to_fit();
		}
	}
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

void Vault::addEntry(const Entry& entry) {
	entries.push_back(entry);
}

bool Vault::save() const {

	if (!hasKey_) {
		lastError_ = "Key is not derived; call initNew() or load() first."; return false;
	}

	// serialize via plaintext
	nlohmann::json arr = nlohmann::json::array();
	for (const auto& e : entries) arr.push_back(e);
	std::string plaintext = arr.dump();

	const_cast<std::vector<unsigned char>&>(nonce) =
	Crypto::randomBytes(crypto_aead_xchacha20poly1305_ietf_NPUBBYTES);


	//Emcrypt, attach to header
	std::string ctB64;
	if (!Crypto::encrypt(key, nonce, plaintext, ctB64)) {
		lastError_ = "Encryption failed.";

		if (!plaintext.empty()) Crypto::secureZero(plaintext.data(), plaintext.size());
		return false;
	}


	nlohmann::json root = makeHeaderJson();
	root["ciphertext_b64"] = ctB64;

	// write file
	bool ok = writeAllText(filePath, root.dump(2));

	// scrub plaintext
	if (!plaintext.empty()) Crypto::secureZero(plaintext.data(), plaintext.size());

	if (!ok) lastError_ = "Failed to write vault file.";
	return ok;
}

bool Vault::load(const std::string& masterPassword) {
	std::string text;
	if (!readAllText(filePath, text)) {
		lastError_ = "Could not open vault file: " + filePath;
		return false;
	}

	nlohmann::json root;
	try { root = nlohmann::json::parse(text); }

	catch (...) { lastError_ = "Vault is not valid JSON."; return false; }

	if (!parseHeaderFromJson(root)) {
		lastError_ = "Vault header is invalid (salt/nonce/version).";
		return false;
	}
		
	if (!deriveKey(masterPassword)) {
		lastError_ = "Key derivation failed (argon2id).";
		return false;
	}

	std::string ctB64 = root.value("ciphertext_b64", "");

	if (ctB64.empty()) { entries.clear(); return true; }

	std::string plaintext;
	if (!Crypto::decrypt(key, nonce, ctB64, plaintext)) {
		lastError_ = "Decryption failed. Wrong password or corrupted file.";
		if (!plaintext.empty()) Crypto::secureZero(plaintext.data(), plaintext.size());
		return false;
	}

	try {
		auto arr = nlohmann::json::parse(plaintext);
		entries = arr.get<std::vector<Entry>>();
	}
	catch (...) {
		lastError_ = "Decrypted data isn't valid JSON.";
		if (!plaintext.empty()) Crypto::secureZero(plaintext.data(), plaintext.size());
		return false;
	}


	if (!plaintext.empty()) Crypto::secureZero(plaintext.data(), plaintext.size());
	return true;
}

nlohmann::json Vault::makeHeaderJson() const {
	nlohmann::json hdr;
	hdr["version"] = 1;

	nlohmann::json k;
	k["opslimit"] = kdf_.opslimit;
	k["memlimit"] = kdf_.memlimit;
	k["salt_b64"] = Crypto::b64encode(kdf_.salt);
	hdr["kdf"] = k;

	hdr["nonce_b64"] = Crypto::b64encode(nonce); 

	return hdr;
}

bool Vault::parseHeaderFromJson(const nlohmann::json& root) {
	try {
		if (root.value("version", 0) != 1) return false;

		const auto& kdfJ = root.at("kdf");
		kdf_.opslimit = kdfJ.at("opslimit").get<unsigned long long>();
		kdf_.memlimit = kdfJ.at("memlimit").get<std::size_t>();

		const std::string saltB64 = kdfJ.at("salt_b64").get<std::string>();
		kdf_.salt = Crypto::b64decode(saltB64);
		if (kdf_.salt.size() != crypto_pwhash_SALTBYTES) return false;


		const std::string nonceB64 = root.at("nonce_b64").get<std::string>();
		nonce = Crypto::b64decode(nonceB64);
		if (nonce.size() != crypto_aead_xchacha20poly1305_ietf_NPUBBYTES) return false;

		return true;
	}
	catch (...) {
		return false;
	}
}

