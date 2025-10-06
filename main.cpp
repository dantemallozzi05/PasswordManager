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
	std::cout << "Usage: pm \n"
		<< "  " << exe << " init <vault.json>\n"
		<< "  " << exe << " add  <vault.json>\n"
		<< "  " << exe << " list <vault.json>\n";
}

int main(int argc, char** argv) {
	if (argc < 3) { printUsage(argv[0]); return 1; }

	const std::string cmd = argv[1];
	const std::string path = argv[2];

	if (cmd == "init") {
		Vault v(path); // new vault at desired filepath

		std::string master = prompt("Create master password: ");

		if (!v.initNew(master)) { std::cerr << v.getLastError() << std::endl; return 1; }
		std::cout << "Vault successfully created." << std::endl;
		return 0;
	}

	if (cmd == "add") {
		Vault v(path);
		std::string master = prompt("Enter master password: ");

		if (!v.load(master)) { std::cerr << v.getLastError() << std::endl; return 1; }

		// Prompt user to enter site name, their username and password.
		// Add to vault
		Entry e{ prompt("Site: "), prompt("Username: "), prompt("Password: ") };
		v.addEntry(e);

		if (!v.save()) { std::cerr << v.getLastError() << std::endl; return 1; }
		std::cout << "Entry successfully saved.";
		return 0;
	}
	// List vault entries
	if (cmd == "list") {
		
		Vault v(path);

		std::string master = prompt("Enter master password: ");

		if (!v.load(master)) { std::cerr << v.getLastError() << std::endl; return 1; }
		for (auto& e : v.getEntries()) {
			std::cout << e.site << " | " << e.username << " | " << e.password << std::endl;
		}
		
		return 0;

	}
	std::cerr << "Unknown command." << std::endl;
	return 1;
	
}