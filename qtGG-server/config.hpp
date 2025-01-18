#pragma once
#include <cstdint>

namespace config {
    using uint = uint32_t;
    // Server Rules
    inline constexpr uint SERVER_MAX_USERS = 1024;
    inline constexpr uint PASS_MIN_LEN = 8;
    inline constexpr uint PASS_MAX_LEN = 32;

    // Database
    inline constexpr char DATABASE_ADDR[] = "127.0.0.1";
    inline constexpr char DATABASE_NAME[] = "qtgg";
    inline constexpr char DATABASE_USER[] = "server";
    inline constexpr char DATABASE_PASSWORD[] = "pwdpwd";

    // Cryptography
    inline constexpr char SECRET_PEPPER[] = "o8aut3Hcr3O";
    inline constexpr char SECRET_HMAC_KEY[] = "hPgNc1Zs6pamZG18z0wtDrJfviy0oA1XGguL4NjZXzyNZsNLKE0RRSVL2px8ifzT";
}