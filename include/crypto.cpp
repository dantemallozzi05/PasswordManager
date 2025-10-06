#include "crypto.h"
#include <sodium.h>
#include <cstring>
#include <stdexcept>

namespace {
	// Confirm installation of libsodium
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

	// Vector of random bytes with libsodium secure RNG.
	std::vector<unsigned char> randomBytes(size_t n) {
		if (!ensure_sodium_init()) return {};
		std::vector<unsigned char> v(n);
		randombytes_buf(v.data(), v.size());
		return v;
	}

	// Securely zero memory to prevent data leaks.
	void secureZero(void* p, size_t n) {
		if (p && n) sodium_memzero(p, n);
	}

	// Encode a byte vector into a Base64 string.
	std::string b64encode(const std::vector<unsigned char>& v) {
		if (!ensure_sodium_init()) return {};
		std::string out; 
		out.resize(sodium_base64_ENCODED_LEN(v.size(), sodium_base64_VARIANT_ORIGINAL));
		
		// convert binary data to Base64 representation
		sodium_bin2base64(out.data(), out.size(), v.data(), v.size(), sodium_base64_VARIANT_ORIGINAL);

		// trim any unused trailing null characters
		out.resize(std::strlen(out.c_str()));
		return out;
	}

	// decode Base64 string back into byte vector.
	std::vector<unsigned char> b64decode(const std::string& s) {
		if (!ensure_sodium_init()) return {};

		std::vector<unsigned char> out(s.size(), 0);

		size_t out_len = 0;
		// convert Base64 string to raw binary data
		if (sodium_base642bin(out.data(), out.size(), s.c_str(), s.size(), nullptr, &out_len, nullptr, sodium_base64_VARIANT_ORIGINAL) != 0) {
			return {};
		}
		out.resize(out_len);
		return out;
	}

	// derive keye for encryption, from master password with Argon2id.
	bool deriveKey(const std::string& master, const KdfParams& kdf, std::vector<unsigned char>& outKey) {
		if (!ensure_sodium_init()) return false;
		if (kdf.salt.size() != crypto_pwhash_SALTBYTES) return false;

		outKey.assign(crypto_aead_xchacha20poly1305_ietf_KEYBYTES, 0);
		// argon2id password hashing to derive encryption key
		if (crypto_pwhash(outKey.data(), outKey.size(), master.data(), master.size(), kdf.salt.data(), kdf.opslimit, kdf.memlimit, crypto_pwhash_ALG_ARGON2ID13) != 0) {
			return false; // fails if invalid memory
		}
		return true;

	}
	// encrypt plaintext using XChaCha20-Poly1305 AEAD.
	bool encrypt(const std::vector<unsigned char>& key, const std::vector<unsigned char> nonce24, const std::string& plaintext, std::string& outCiphertext864) {
		if (!ensure_sodium_init()) return false;
		if (key.size() != crypto_aead_xchacha20poly1305_ietf_KEYBYTES) return false;

		if (nonce24.size() != crypto_aead_xchacha20poly1305_ietf_NPUBBYTES) return false;

		const unsigned char* msg = reinterpret_cast<const unsigned char*>(plaintext.data());
		const unsigned long long mlen = static_cast<unsigned long long>(plaintext.size());

		std::vector<unsigned char> ct(mlen + crypto_aead_xchacha20poly1305_ietf_ABYTES);

		unsigned long long clen = 0;

		// encrypt message with Authenticated Encryption with Associated Data (AEAD).
		if (crypto_aead_xchacha20poly1305_ietf_encrypt(
			ct.data(), &clen, msg, mlen, nullptr, 0, nullptr, nonce24.data(), key.data()) != 0) {
			return false;
		}

		ct.resize(static_cast<size_t>(clen));

		// encode ciphertext to Base64 for storage.
		outCiphertext864 = b64encode(ct);
		return !outCiphertext864.empty();
	}

	// decrypts ciphertext using XChaCha20-Poly1305 AEAD
	bool decrypt(const std::vector<unsigned char>& key, const std::vector<unsigned char>& nonce24, const std::string& ciphertext864, std::string& outPlainText) {
		if (!ensure_sodium_init()) return false;

		if (key.size() != crypto_aead_xchacha20poly1305_ietf_KEYBYTES) return false;
		if (nonce24.size() != crypto_aead_xchacha20poly1305_ietf_NPUBBYTES) return false;

		auto ct = b64decode(ciphertext864);
		if (ct.empty()) return false;

		std::vector<unsigned char> pt(ct.size(), 0);
		unsigned long long plen = 0;

		// Decrypts ciphertext and verifies authenticity.
		if (crypto_aead_xchacha20poly1305_ietf_decrypt(
			pt.data(), &plen,
			nullptr, ct.data(),
			static_cast<unsigned long long>(ct.size()),
			nullptr, 0, nonce24.data(),
			key.data()) != 0) {
			return false; // if authentication fails
		}

		pt.resize(static_cast<size_t>(plen));

		// convert decrypted bytes back to plaintext string.
		outPlainText.assign(reinterpret_cast<const char*>(pt.data()), pt.size());

		// seurely erase plaintext buffer from memory.
		secureZero(pt.data(), pt.size());
		return true;

	}
}
