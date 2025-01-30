#include <Crypt.hpp>
#include <Encoding.hpp>
#include <algorithm>
#include <cstring>
#include <memory>
// I Wish I had used botan for encryption
#include <openssl/hmac.h>
#include <openssl/rsa.h>
#include <openssl/aes.h>
#include <openssl/pem.h>
#include <openssl/err.h>
#include <openssl/rand.h>
#include <string>
#include <random>
#include <span>

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

    std::string encryptRsaBase64(std::string_view msg, std::string_view pubRsaPEM) {
        // TODO: error handling
        if (pubRsaPEM.size() > 4096) return "";
        auto keyLen = static_cast<int>(pubRsaPEM.size());
        auto basicIO = std::unique_ptr<BIO, decltype(&BIO_free_all)>(
            BIO_new_mem_buf(pubRsaPEM.data(), keyLen), BIO_free_all
        );
        if (!basicIO) return "";

        EVP_PKEY *pKey = nullptr;
        PEM_read_bio_PUBKEY(basicIO.get(), &pKey, nullptr, nullptr);

        auto scopedPKey = std::unique_ptr<EVP_PKEY, decltype(&EVP_PKEY_free)>(pKey, EVP_PKEY_free);

        //std::vector<unsigned char> encrypted = std::vector<unsigned char>(EVP_PKEY_get_size(pKey));
        auto ctx = std::unique_ptr<EVP_PKEY_CTX, decltype(&EVP_PKEY_CTX_free)>(
            EVP_PKEY_CTX_new(pKey, nullptr), EVP_PKEY_CTX_free
        );

        EVP_PKEY_encrypt_init(ctx.get());
        size_t encryptedSize;
        auto *dataPtr = reinterpret_cast<const unsigned char *>(msg.data());
        // Get size first
        EVP_PKEY_encrypt(ctx.get(), nullptr, &encryptedSize, dataPtr, msg.size());
        std::vector<unsigned char> encrypted(encryptedSize);
        // Encrypt
        EVP_PKEY_encrypt(ctx.get(), encrypted.data(), &encryptedSize, dataPtr, msg.size());
        return Encoding::base64UrlEncode(encrypted.data(), encryptedSize);
    }

    std::string decryptRsaBase64(std::string_view msg, std::string_view prvRsaPEM) {
        if (prvRsaPEM.size() > 4096) return "";

        auto keyLen = static_cast<int>(prvRsaPEM.size());
        auto basicIO = std::unique_ptr<BIO, decltype(&BIO_free_all)>(
            BIO_new_mem_buf(prvRsaPEM.data(), keyLen), BIO_free_all
        );
        if (!basicIO) return "";

        EVP_PKEY *pKey = nullptr;
        PEM_read_bio_PrivateKey(basicIO.get(), &pKey, nullptr, nullptr);

        auto scopedPKey = std::unique_ptr<EVP_PKEY, decltype(&EVP_PKEY_free)>(pKey, EVP_PKEY_free);

        auto ctx = std::unique_ptr<EVP_PKEY_CTX, decltype(&EVP_PKEY_CTX_free)>(
            EVP_PKEY_CTX_new(pKey, nullptr), EVP_PKEY_CTX_free
        );

        EVP_PKEY_decrypt_init(ctx.get());
        size_t decryptedSize;
        auto decoded = Encoding::base64UrlDecode(msg);
        auto *dataPtr = reinterpret_cast<const unsigned char *>(decoded.data());
        // Get size first
        EVP_PKEY_decrypt(ctx.get(), nullptr, &decryptedSize, dataPtr, decoded.size());
        std::vector<unsigned char> decrypted(decryptedSize);
        // Decrypt
        EVP_PKEY_decrypt(ctx.get(), decrypted.data(), &decryptedSize, dataPtr, decoded.size());
        return std::string(reinterpret_cast<char*>(decrypted.data()), decryptedSize);
    }

    std::string encryptAes256Base64(std::string_view msg, std::span<unsigned char> key) {
        if (key.size() != 32) return "";

        // Generate a random IV
        unsigned char iv[AES_BLOCK_SIZE];
        if (!RAND_bytes(iv, AES_BLOCK_SIZE)) return "";

        std::vector<unsigned char> encrypted(msg.size() + AES_BLOCK_SIZE);
        int len = 0;
        int encryptedLen = 0;

        auto ctx = std::unique_ptr<EVP_CIPHER_CTX, decltype(&EVP_CIPHER_CTX_free)>(EVP_CIPHER_CTX_new(), EVP_CIPHER_CTX_free);
        if (!ctx) return "";

        if (EVP_EncryptInit_ex(ctx.get(), EVP_aes_256_cbc(), nullptr, key.data(), iv) != 1)
            return "";

        EVP_CIPHER_CTX_set_padding(ctx.get(), 1);

        auto msgData = reinterpret_cast<const unsigned char *>(msg.data());
        if (EVP_EncryptUpdate(ctx.get(), encrypted.data(), &len, msgData, msg.size()) != 1)
            return "";

        encryptedLen = len;

        if (EVP_EncryptFinal_ex(ctx.get(), encrypted.data() + len, &len) != 1)
            return "";

        encryptedLen += len;
        encrypted.resize(encryptedLen);

        // initialization vector + encrypted data
        std::vector<unsigned char> result(AES_BLOCK_SIZE + encryptedLen);

        std::copy(iv, iv + AES_BLOCK_SIZE, result.begin());
        std::copy(encrypted.begin(), encrypted.end(), result.begin() + AES_BLOCK_SIZE);

        return Encoding::base64UrlEncode(result.data(), result.size());
    }

    std::string decryptAesBase64(std::string_view msg, std::span<unsigned char> key) {
        if (key.size() != 32) return "";

        auto decoded = Encoding::base64UrlDecodeBytes(msg);
        if (decoded.size() < AES_BLOCK_SIZE) return ""; // Ensure the decoded data is large enough to contain the IV

        // Extract the IV from the beginning of the decoded data
        unsigned char iv[AES_BLOCK_SIZE];
        std::copy(decoded.begin(), decoded.begin() + AES_BLOCK_SIZE, iv);

        // The actual encrypted data starts after the IV
        auto encryptedData = decoded.data() + AES_BLOCK_SIZE;
        size_t encryptedSize = decoded.size() - AES_BLOCK_SIZE;

        std::vector<unsigned char> decrypted(encryptedSize);
        int len = 0;
        int decryptedLen = 0;

        auto ctx = std::unique_ptr<EVP_CIPHER_CTX, decltype(&EVP_CIPHER_CTX_free)>(
            EVP_CIPHER_CTX_new(), EVP_CIPHER_CTX_free);
        if (!ctx) return "";

        if (EVP_DecryptInit_ex(ctx.get(), EVP_aes_256_cbc(), nullptr, key.data(), iv) != 1)
            return "";

        EVP_CIPHER_CTX_set_padding(ctx.get(), 1);

        if (EVP_DecryptUpdate(ctx.get(), decrypted.data(), &len, encryptedData, encryptedSize) != 1)
            return "";

        decryptedLen = len;

        if (EVP_DecryptFinal_ex(ctx.get(), decrypted.data() + len, &len) != 1) {
            unsigned long errCode = ERR_get_error();
            char errBuffer[256]{};
            ERR_error_string_n(errCode, errBuffer, sizeof(errBuffer) - 1);
            return std::string("EVP_DecryptFinal_ex failed: ") + errBuffer;
        }

        decryptedLen += len;

        return std::string(reinterpret_cast<char*>(decrypted.data()), decryptedLen);
    }
}
