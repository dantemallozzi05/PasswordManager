#pragma once
#include <string>

class Vault {
public:
	Vault();
	void addEntry(const std::string& site);

private:
	int numEntries;

};
