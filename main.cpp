#include "src/Vault.h"
#include "include/crypto.h"
#include <iostream>
#include <limits>
#include <string>
#include <vector>
#include <filesystem>


static std::string promptPathWithDefault(const std::string& label, const std::string& def) {
	std::cout << label;
	std::string s;
	std::getline(std::cin, s);
	std::string chosen = s.empty() ? def : s;
	std::filesystem::path p = std::filesystem::absolute(chosen);
	std::cout << "Using path: " << p.string() << std::endl;
	return p.string();                       // <-- RETURN IT
}


static std::string prompt(const std::string& label) {
	std::cout << label;
	std::string s;
	std::getline(std::cin, s);
	return s;
}

// Handle CLI for Windows v. UNIX
#if defined(_WIN32)
#define NOMINMAX
#include <Windows.h>
static std::string promptSecret(const char* label) {
	std::cout << label;
	HANDLE h = GetStdHandle(STD_INPUT_HANDLE);

	DWORD mode = 0;
	GetConsoleMode(h, &mode);

	SetConsoleMode(h, mode & ~ENABLE_ECHO_INPUT);
	std::string s; 
	std::getline(std::cin, s);

	SetConsoleMode(h, mode);
	std::cout << std::endl;
	return s;
}
#else
static std::string promptSecret(const char* label) {
	return prompt(label);
}
#endif

static void printUsage(const char* exe) {
	std::cout << "Usage: pm \n"
		<< "  " << exe << " init <vault.json>\n"
		<< "  " << exe << " add  <vault.json>\n"
		<< "  " << exe << " list <vault.json>\n";
}

static int cmd_init(const std::string& path) {
	Vault v(path);

	std::string master = promptSecret("Create master password: ");

	if (!v.initNew(master)) {
		std::cerr << v.getLastError() << std::endl;
		
		if (!master.empty()) Crypto::secureZero(master.data(), master.size());
		return 1;
	}

	if (!master.empty()) Crypto::secureZero(master.data(), master.size());

	std::cout << "Vault successfully created at " << path << std::endl;
	return 0;
}

// cmd add functionality
static int cmd_add(const std::string& path) {
	Vault v(path);

	// prompt user for master password
	std::string master = promptSecret("Enter master password: ");

	if (!v.load(master)) { std::cerr << v.getLastError() << std::endl; return 1; }
	if (!master.empty()) Crypto::secureZero(const_cast<char*>(master.data()), master.size());

	Entry e;
	e.site = prompt("Site: ");
	e.username = prompt("Username: ");
	e.password = promptSecret("Password: ");

	v.addEntry(e);
	if (!v.save()) { std::cerr << v.getLastError() << std::endl; return 1; }
	return 0;
}

static int cmd_list(const std::string& path) {
	Vault v(path);

	std::string master = promptSecret("Enter master password: ");
	if (!v.load(master)) { std::cerr << v.getLastError() << std::endl; return -1; }
	if (!master.empty()) Crypto::secureZero(const_cast<char*>(master.data()), master.size());

	const auto& items = v.getEntries();

	if (items.empty()) { std::cout << "(no entries)" << std::endl; return 0; }

	for (const auto& e : items) {
		std::cout << e.site << " | " << e.username << " | " << e.password << std::endl;
	}
	return 0;
}

static int menu() {
	std::cout << "=== Password Vault ===" << std::endl
		<< "1) Initialize Vault" << std::endl
		<< "2) Add entry" << std::endl
		<< "3) List entries" << std::endl
		<< "Choice: ";

	int c = 0;
	if (!(std::cin >> c)) return 1;
	std::cin.ignore(static_cast<std::streamsize>(std::numeric_limits<std::streamsize>::max()), '\n');

	std::string path = prompt("Vault path (default: vault.json): ");
	if (path.empty()) path = "vault.json";

	if (c == 1) return cmd_init(path);
	if (c == 2) return cmd_add(path);
	if (c == 3) return cmd_list(path);

	std::cerr << "Unknown choice";
	return 1;
}


int main(int argc, char** argv) {
	if (argc >= 2) {
		std::string cmd = argv[1];
		std::string path = (argc >= 3) ? argv[2] : "vault.json";

		if (cmd == "init") return cmd_init(path);
		if (cmd == "add") return cmd_add(path);
		if (cmd == "list") return cmd_list(path);

		printUsage(argv[0]);
		return 1;
	}
	return menu();

}