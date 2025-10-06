#pragma once
#include <string>
#include <vector>
#include "crypto.h"

struct Entry {
	std::string site;
	std::string username;
	std::string password;
};

class Vault {
public:
	Vault();
	void addEntry(const std::string& filePath, const std::string& masterPassword);
	bool addEntry(const Entry& entry);
	bool load();
	bool save();
	std::vector<Entry> getEntries() const;

private:
	std::string filePath;
	std::vector<Entry> entries;
	std::vector<unsigned char> key;
	std::vector<unsigned char> nonce;
	int numEntries;

};
