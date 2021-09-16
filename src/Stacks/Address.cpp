// Copyright © 2017-2021 Trust Wallet
//
// This file is part of Trust. The full Trust copyright notice, including
// terms governing use, modification, and redistribution, is contained in the
// file LICENSE at the root of the source code distribution tree.

#include "Address.h"
#include "../Base32.h"
#include "../HexCoding.h"
#include "../Crc.h"

#include <boost/algorithm/string.hpp>
#include <array>

using namespace TW::Stacks;
using namespace boost::algorithm;

const char* Address::BASE32_ALPHABET_CROCKFORD = "0123456789ABCDEFGHJKMNPQRSTVWXYZ";

TW::Data Address::deconstruct(const std::string& string) {
    if ((string.length() < (checksumSize + 2)) || (string.length() > size)) {
        return {};
    }

    // Check that it decodes correctly
    Data data;
    auto normalise = to_upper_copy(string);
    auto pad = size - normalise.length();
    if (pad) {
        normalise.insert(2, std::string(pad, '0'));
    }
    replace_all(normalise, "O", "0");
    replace_all(normalise, "L", "1");
    replace_all(normalise, "I", "1");
    if ((normalise[0] != 'S') || !Base32::decode(normalise.substr(1), data, BASE32_ALPHABET_CROCKFORD)) {
        return {};
    }

    // Verify that checksums match
    data[0] >>= 3;
    auto checksum = Hash::sha256(Hash::sha256(&data[0], bytesSize));
    if (!std::equal(data.end() - checksumSize, data.end(), checksum.begin())) {
	return {};
    }
    return Data(data.begin(), data.begin() + bytesSize);
}

bool Address::isValid(const std::string& string, const std::vector<TW::byte>& validPrefixes) {
    auto data = deconstruct(string);
    return data.size() && (!validPrefixes.size() || std::find(validPrefixes.begin(), validPrefixes.end(), data[0]) != validPrefixes.end()); 
}

Address::Address(const std::string& string) {
    // Ensure address is valid
    auto data = deconstruct(string);
    if (!data.size()) {
        throw std::invalid_argument("Invalid address data");
    }
    std::copy(data.begin(), data.end(), bytes.begin());
}

Address::Address(const PublicKey& publicKey, TW::byte prefix) {
    if ((publicKey.type != TWPublicKeyTypeSECP256k1) && (publicKey.type != TWPublicKeyTypeSECP256k1Extended)) {
        throw std::invalid_argument("Invalid public key type");
    }
    auto data = publicKey.hash({}, Hash::sha256ripemd);
    std::copy(data.begin(), data.end(), bytes.begin() + 1);
    bytes[0] = prefix;
}

std::string Address::string() const {
    static_assert((8 * (bytesSize + checksumSize)) % 5 == 0);
    auto data = Data(bytes.begin(), bytes.end());
    auto checksum = Hash::sha256(Hash::sha256(data));
    data.insert(data.end(), checksum.begin(), checksum.begin() + checksumSize);
    TW::byte prefix = data[0] << 3;
    data[0] = 0;
    auto encoded = Base32::encode(data, BASE32_ALPHABET_CROCKFORD);
    encoded.erase(0, encoded.find_first_not_of('0'));
    for (int i = 1; i < data.size() && !data[i]; i++) {
       encoded.insert(0, "0");
    }
    return std::string("S") + Base32::encode({prefix}, BASE32_ALPHABET_CROCKFORD)[0] + encoded;
}
