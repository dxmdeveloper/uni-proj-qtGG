#include <Crypt.hpp>
#include <Encoding.hpp>
#include <algorithm>
#include <cstring>
#include <openssl/sha.h>
#include <openssl/hmac.h>
#include <string>
#include <vector>
#include <random>

template<typename T>
static T getRandInt(T min, T max) {
    static_assert(std::is_integral_v<T>);

    static std::random_device rd;
    static std::mt19937 generator(rd());
    std::uniform_int_distribution<T> dist(min, max);

    return dist(generator);
}

namespace Crypt {
    template<bool useHMAC, const EVP_MD*(*evpMd)(void), typename StrT, typename ArgStrT>
    static StrT msgDigest(ArgStrT msg, const char *hmacKey, size_t hmacKeyLen, bool useBase64 = false) {
        unsigned char buffer[EVP_MAX_MD_SIZE]{};
        unsigned int md_len = 0;
        if constexpr (useHMAC) {
            HMAC(
                evpMd(),
                hmacKey,
                hmacKeyLen,
                reinterpret_cast<const unsigned char *>(msg.data()),
                msg.length(),
                buffer,
                &md_len
            );
        } else {
            EVP_Digest(msg.data(), msg.length(), buffer, &md_len, evpMd(), nullptr);
        }

        if (useBase64)
            return Encoding::base64UrlEncode(buffer, md_len);


        // hex to characters
        char strArr[EVP_MAX_MD_SIZE * 2 + 1]{};
        for (unsigned int i = 0; i < md_len; i++) {
            sprintf(&strArr[i * 2], "%02x", buffer[i]);
        }

        return {strArr};
    }

    std::string sha512(std::string_view s) {
        return msgDigest<false, EVP_sha512, std::string, std::string_view>(s, nullptr, 0);
    }

    std::string hmacSha256Base64(std::string_view s, std::string_view key) {
        return hmacSha256Base64(s, key.data(), key.size());
    }

    std::string hmacSha256Base64(std::string_view s, const char key[], size_t keyLen) {
        return msgDigest<true, EVP_sha256, std::string, std::string_view>(s, key, keyLen, true);
    }

    std::string passwordHashSha512(std::string_view pass, std::string_view salt, std::string_view pepper) {
        std::string salted = std::string(pass) + salt.data() + pepper.data();
        std::string hash = sha512(salted);

        return std::string("$") + salt.data() + "$" + hash;
    }

    std::string generateSalt() {
        char salt[9]{};
        for (int i = 0; i < 8; i++) {
            switch (getRandInt(0, 2)) {
                case 0:
                    salt[i] = getRandInt('0', '9');
                    break;
                case 1:
                    salt[i] = getRandInt('a', 'z');
                    break;
                default:
                    salt[i] = getRandInt('A', 'Z');
                    break;
            }
        }
        return {salt};
    }
}
