#pragma once
#include <random>
#include <crow.h>
#include <QString>

inline constexpr int HTTP_CODE_UNAUTHORIZED = 401;

template <typename T>
T getRandInt(T min, T max) {
    static_assert(std::is_integral_v<T>);

    static std::random_device rd;
    static std::mt19937 generator(rd());
    std::uniform_int_distribution<T> dist(min, max);

    return dist(generator);
}

inline std::string base64UrlEncode(const unsigned char* data, size_t len) {
    std::string b64 = crow::utility::base64encode_urlsafe(data, len);
    while (b64.at(b64.size() - 1) == '=') {
        b64 = b64.substr(0, b64.size() - 1);
    }
    return b64;
}

inline std::string base64UrlEncode(const char* data, size_t len) {
    return base64UrlEncode(reinterpret_cast<const unsigned char *>(data), len);
}

inline std::string base64UrlEncode(std::string_view data) {
    return base64UrlEncode(reinterpret_cast<const unsigned char *>(data.data()), data.length());
}

inline std::string base64UrlDecode(std::string_view msg) {
    int pad = 0;
    switch (msg.size() % 4) {
        case 2: pad = 2; break;
        case 3: pad = 1; break;
        case 0: pad = 0; break;
        default: return "";
    }
    std::string str = std::string(msg);
    for (int i = 0; i < pad; i++) {
        str.append("=");
    }

    auto decoded = crow::utility::base64decode(str.data(), str.size());
    return decoded;
}

inline QString toQString(std::string_view str) {
    return QString::fromStdString({str.data(), str.size()});
}
