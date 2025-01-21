#include <Crypt.hpp>
#include <Encoding.hpp>
#include <algorithm>
#include <cstring>
#include <memory>
#include <openssl/sha.h>
#include <openssl/hmac.h>
#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/err.h>
#include <string>
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

    std::pair<std::string, std::string> generateRsaKeys(int keyBits) {
        int result{};
        auto ctx = std::unique_ptr<EVP_PKEY_CTX, decltype(&EVP_PKEY_CTX_free)>(
            EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, nullptr),
            EVP_PKEY_CTX_free
        );
        result = EVP_PKEY_keygen_init(ctx.get());
        if (result <= 0) return {};

        result = EVP_PKEY_CTX_set_rsa_keygen_bits(ctx.get(), keyBits);
        if (result <= 0) return {};

        // generate key pair
        EVP_PKEY *pKey = nullptr;
        result = EVP_PKEY_keygen(ctx.get(), &pKey);
        if (result <= 0) return {};

        auto scopedPtrPKey = std::unique_ptr<EVP_PKEY, decltype(&EVP_PKEY_free)>(pKey, EVP_PKEY_free);

        auto prvKeyBasicIO = std::unique_ptr<BIO, decltype(&BIO_free_all)>(
            BIO_new(BIO_s_mem()), BIO_free_all);
        auto pubKeyBasicIO = std::unique_ptr<BIO, decltype(&BIO_free_all)>(
            BIO_new(BIO_s_mem()), BIO_free_all);

        // write keys in PEM format
        result = PEM_write_bio_PrivateKey(prvKeyBasicIO.get(), pKey, nullptr, nullptr, 0, nullptr, nullptr);
        result &= PEM_write_bio_PUBKEY(pubKeyBasicIO.get(), pKey);
        if (!result) return {};

        char *prvKeyPEM = nullptr, *pubKeyPEM = nullptr;
        size_t prvKeyLen = BIO_get_mem_data(prvKeyBasicIO.get(), &prvKeyPEM);
        size_t pubKeyLen = BIO_get_mem_data(pubKeyBasicIO.get(), &pubKeyPEM);

        return {std::string(prvKeyPEM, prvKeyLen), std::string(pubKeyPEM, pubKeyLen)};
    }
}
