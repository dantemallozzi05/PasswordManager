#include "crypto.h"
#include <sodium.h>
#include <cstring>
#include <stdexcept>

namespace {

	bool ensure_sodium_init() {
		static bool inited = false;
		if (!inited) {
			if (sodium_init() < 0) return false;
			inited = true;
		}
		return true;
	}

}

namespace Crypto {


	std::vector<unsigned char> randomBytes(size_t n) {
		if (!ensure_sodium_init()) return {};
		std::vector<unsigned char> v(n);
		randombytes_buf(v.data(), v.size());
		return v;
	}

	void secureZero(void* p, size_t n) {
		if (p && n) sodium_memzero(p, n);
	}

	std::string b64encode(const std::vector<unsigned char>& v) {
		if (!ensure_sodium_init()) return {};
		std::string out; 
		out.resize(sodium_base64_ENCODED_LEN(v.size(), sodium_base64_VARIANT_ORIGINAL));
		sodium_bin2base64(out.data(), out.size(), v.data(), v.size(), sodium_base64_VARIANT_ORIGINAL);

		out.resize(std::strlen(out.c_str()));
		return out;
	}
}
