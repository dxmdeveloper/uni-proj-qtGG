#include <Jwt.hpp>
#include <Crypt.hpp>
#include <Encoding.hpp>
#include <nlohmann/json.hpp>

JwtReader::JwtReader(std::string_view token) {
    size_t dotPos[2];
    dotPos[0] = token.find('.');
    if (dotPos[0] == std::string_view::npos) {
        invalid = true;
        return;
    }

    dotPos[1] = token.find('.', dotPos[0] + 1);
    if (dotPos[1] == std::string_view::npos || dotPos[1] == token.size() - 1) {
        invalid = true;
        return;
    }

    std::string_view header = token.substr(0, dotPos[0]);
    std::string_view payload = token.substr(dotPos[0] + 1, dotPos[1] - dotPos[0] - 1);
    std::string_view hash = token.substr(dotPos[1] + 1);

    this->header = header;
    this->payload = payload;
    this->hash = hash;
}

bool JwtReader::validateHash(std::string_view secret) const {
    return Crypt::hmacSha256Base64(header + '.' + payload, secret) == hash;
}

bool JwtReader::isFormatValid() const {
    return !invalid;
}

std::string JwtReader::getPayload() const {
    return Encoding::base64UrlDecode(payload);
}

using namespace nlohmann;

JwtWriter::JwtWriter(std::string_view payload, std::string_view secret)
    : secret(secret), payload(payload) {}


template<typename T>
void JwtWriter::addFieldTmpl(std::string_view key, T val) {
    json j = json::parse(payload);
    j[key.data()] = val;
    payload = j.dump();
}

void JwtWriter::addField(std::string_view key, uint64_t val) {
    addFieldTmpl(key, val);
}

void JwtWriter::addField(std::string_view key, int64_t val) {
    addFieldTmpl(key, val);
}

void JwtWriter::addField(std::string_view key, bool val) {
    addFieldTmpl(key, val);
}

void JwtWriter::addField(std::string_view key, std::string_view s) {
    json j = json::parse(payload);
    j[key.data()] = s.data();
    payload = j.dump();
}

std::string JwtWriter::getPayload() const {
    return payload;
}

std::string JwtWriter::toString() const {
    std::string header = R"({"alg":"HS256","typ":"JWT"})";
    auto encodedHeader = Encoding::base64UrlEncode(header);
    auto encodedPayload = Encoding::base64UrlEncode(payload);
    auto signature = Crypt::hmacSha256Base64(encodedHeader + "." + encodedPayload, secret);
    return encodedHeader + "." + encodedPayload + "." + signature;
}
