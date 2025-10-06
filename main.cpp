#include "src/Vault.h"
#include <iostream>
#include <string>
#include <vector>

static std::string prompt(const std::string& label) {
	std::cout << label;
	std::string s;
	std::getline(std::cin, s);
	return s;
}

static void printUsage(const char* exe) {
	std::cout << "Usage: \n"
		<< "  " << exe << " init <vault.json>\n"
		<< "  " << exe << " add  <vault.json>\n"
		<< "  " << exe << " list <vault.json>\n";
}

int main(int argc, char** argv) {
	if (argc < 3) { printUsage(argv[0]); return 1; }

	const std::string cmd = argv[1];
	const std::string path = argv[2];

	// initialize brnd new vault
	if (cmd == "list") {
		const std::string master = prompt("Master password: ");

		Vault v(path);
		if (!v.load(master)) {
			std::cerr << "Failed to load / decrypt vault. Wrong password, or corrupt file.\n";
			return 1;
		}

		const auto& items = v.list();
		if (items.empty()) {
			std::cout << "(no entries)\n";
			return 0;
		}

		std::cout << "Entries (" << items.size() << "):\n";
		for (const auto& it : items) {
			std::cout << "- site: " << it.site
				<< " | user: " << it.username
				<< " | pass: " << it.password << "\n";
		}
		return 0;
	}

	printUsage(argv[0]);
	return 1;
}