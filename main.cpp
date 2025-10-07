#include "src/Vault.h"
#include "include/crypto.h"
#include <iostream>
#include <cstdlib>
#include <limits>
#include <string>
#include <vector>
#include <filesystem>

#if defined(_WIN32)
#include <conio.h>
#endif


static std::string promptPathWithDefault(const std::string& label, const std::string& def) {
	std::cout << label;
	std::string s;
	std::getline(std::cin, s);
	std::string chosen = s.empty() ? def : s;
	std::filesystem::path p = std::filesystem::absolute(chosen);
	std::cout << "Using path: " << p.string() << std::endl;
	return p.string();                       // <-- RETURN IT
}

static void clearScreen() {
#if defined(_WIN32)
	std::system("cls");
#else
	std::system("clear");
#endif
}

static void userConfirm() {
	std::cout << std::endl << "Press any key to return to menu...";
#if defined(_WIN32)
	(void)_getch();
#else 
	std::string dummy;
	std::getline(std::cin, dummy);
#endif
	clearScreen();
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
		<< "  " << exe << " list <vault.json>\n"
		<< "  " << exe << " del  <vault.json>\n";
}

static int cmd_init(const std::string& path) {
	Vault v(path);

	std::string master = promptSecret("Create master password: ");

	if (!v.initNew(master)) {
		std::cerr << v.getLastError() << std::endl;
		
		if (!master.empty()) Crypto::secureZero(master.data(), master.size());
		userConfirm();
		return 1;
	}

	if (!master.empty()) Crypto::secureZero(master.data(), master.size());

	std::cout << "Vault successfully created at " << path << std::endl;
	userConfirm();
	return 0;
}

// cmd add functionality
static int cmd_add(const std::string& path) {
	Vault v(path);

	// prompt user for master password
	std::string master = promptSecret("Enter master password: ");

	if (!v.load(master)) { std::cerr << v.getLastError() << std::endl; userConfirm(); return 1; }
	if (!master.empty()) Crypto::secureZero(const_cast<char*>(master.data()), master.size());

	Entry e;
	e.site = prompt("Site: ");
	e.username = prompt("Username: ");
	e.password = promptSecret("Password: ");

	v.addEntry(e);
	if (!v.save()) { std::cerr << v.getLastError() << std::endl; userConfirm(); return 1; }
	userConfirm();
	return 0;
}

static int cmd_list(const std::string& path) {
	Vault v(path);

	std::string master = promptSecret("Enter master password: ");
	if (!v.load(master)) { std::cerr << v.getLastError() << std::endl; userConfirm(); return -1; }
	if (!master.empty()) Crypto::secureZero(const_cast<char*>(master.data()), master.size());

	const auto& items = v.getEntries();

	if (items.empty()) { std::cout << "(no entries)" << std::endl; userConfirm(); return 0; }

	for (const auto& e : items) {
		std::cout << e.site << " | " << e.username << " | " << e.password << std::endl;
	}

	userConfirm();
	return 0;
}

static int cmd_del(const std::string& path) {
	if (!std::filesystem::exists(path)) {
		std::cerr << "No vault exists at " << path << ". Try Initializing first." << std::endl;
		userConfirm();
		return 1;
	}

	Vault v(path);
	std::string master = promptSecret("Enter master password: ");

	if (!v.load(master)) { std::cerr << v.getLastError() << std::endl; return 1; }
	if (!master.empty()) Crypto::secureZero(master.data(), master.size());

	std::string site = prompt("Site to delete (exact match): ");
	const size_t removed = v.removeBySite(site);

	if (removed == 0) {
		std::cout << "No entries matched " << site << std::endl;
		userConfirm();
		return 0;
	}

	if (!v.save()) { std::cerr << v.getLastError() << std::endl; userConfirm(); return 1; }
	std::cout << "Successfully deleted " << removed << "entr" << (removed == 1 ? "y" : "ies") << std::endl;
	userConfirm();
	return 0;
}

static int menu() {
	for (;;) {
		std::cout << "=== PASSWORD VAULT ===" << std::endl
			<< "1) Initialize Vault" << std::endl
			<< "2) Add Entry" << std::endl
			<< "3) List Entries" << std::endl
			<< "4) Delete Entry" << std::endl
			<< "Q) Quit Application" << std::endl
			<< "Choice: ";

		std::string choice;

		if (!std::getline(std::cin, choice)) return 1;

		if (choice == "q" || choice == "Q") {
			std::cout << "Goodbye";
			return 0;
		}

		std::string path = promptPathWithDefault("Vault path (default: vault.json): ", "vault.json");

		if (choice == "1") {
			cmd_init(path);
		}
		else if (choice == "2") {
			cmd_add(path);
		} 
		else if (choice == "3") {
			cmd_list(path);
		}
		else if (choice == "4") {
			cmd_del(path);
		}
		else {
			std::cerr << "Unknown Choice" << std::endl;
		}
		std::cout << std::endl;
	}
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