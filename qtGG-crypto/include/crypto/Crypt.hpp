#pragma once
#include <span>
#include <string_view>
#include <vector>

namespace Crypt {
    /// @return 128 character long string.
    std::string sha512(std::string_view s);

    std::string hmacSha256Base64(std::string_view s, std::string_view key);

    std::string hmacSha256Base64(std::string_view s, const char key[], size_t keyLen);

    /// @brief hashes password using sha2 (512bit) algorithm and formats it.
    /// format: $salt$hash, where the hash starts at the 10th character.
    /// @return formatted hash string of length 138.
    std::string passwordHashSha512(std::string_view pass, std::string_view salt, std::string_view pepper);

    /// @brief generates salt for password hashing. May contain a-z, A-Z, 0-9 characters.
    /// @return 8 character string.
    std::string generateSalt();

    /// @return pair of: private, public keys (in that order) in PEM format.
    std::pair<std::string, std::string> generateRsaKeys(int keyBits);

    std::string encryptRsaBase64(std::string_view msg, std::string_view pubRsaPEM);

    std::string decryptRsaBase64(std::string_view msg, std::string_view prvRsaPEM);

    std::string encryptAes256Base64(std::string_view msg, std::span<unsigned char> key);

    std::string decryptAesBase64(std::string_view msg, std::span<unsigned char> key);
}
