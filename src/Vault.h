#pragma once
#include <string>
#include <vector>
#include <optional>
#include "../include/crypto.h"
#include <nlohmann/json.hpp>

// represents saved credential entry
struct Entry {
	std::string site;
	std::string username;
	std::string password;
};

inline void to_json(nlohmann::json& j, const Entry& e) {
	j = {
		{"site", e.site},
		{"username", e.username},
		{"password", e.password}
	};
}

inline void from_json(const nlohmann::json& j, Entry& e) {
	j.at("site").get_to(e.site);
	j.at("username").get_to(e.username);
	j.at("password").get_to(e.password);
}


class Vault {

private:

	std::string filePath;
	std::vector<Entry> entries;
	Crypto::KdfParams kdf_;
	std::vector<unsigned char> key;
	std::vector<unsigned char> nonce;
	bool hasKey_ = false;
	std::string lastError_; // stores most recent error msg
	

	// re-derive key with current kdf and provided master. 
	bool deriveKey(const std::string& masterPassword);

	// helpers to deserialized the vault header / body
	nlohmann::json makeHeaderJson() const;
	bool parseHeaderFromJson(const nlohmann::json& root);

public:

	explicit Vault(std::string path);
	~Vault();

	// create new empty vault with fresh salt, derives a key and writes file
	bool initNew(const std::string& masterPassword);

	// loads existing vault, parses header, derives by key w/ provided password,
	// decrypts and fills entries 
	bool load(const std::string& masterPassword);

	// save current entries
	bool save() const;

	// simple CRUD helpers
	void addEntry(const Entry& entry);
	const std::vector<Entry>& list() const { return entries; }

	const std::vector<Entry>& getEntries() const { return entries; }

	const std::string& getLastError() const { return lastError_; }

};
