// Copyright © 2017-2020 Trust Wallet.
//
// This file is part of Trust. The full Trust copyright notice, including
// terms governing use, modification, and redistribution, is contained in the
// file LICENSE at the root of the source code distribution tree.

#include "Address.h"
#include "../Base32.h"
#include "../HexCoding.h"
#include "../Crc.h"

#include <boost/algorithm/string.hpp>
#include <TrezorCrypto/memzero.h>

#include <array>
#include <cassert>

// TODO: Remove the next 2 lines -- used for debugging only
#include <iostream>
using namespace std;

using namespace TW::Stacks;
using namespace boost::algorithm;

const char* Address::BASE32_ALPHABET_CROCKFORD = "0123456789ABCDEFGHJKMNPQRSTVWXYZ";

bool Address::isValid(const std::string& string) {
    if (string.length() != size) {
        return false;
    }

    // Check that it decodes correctly
    auto normalise = to_upper_copy(string);
    replace_all(normalise, "O", "0");
    replace_all(normalise, "L", "1");
    replace_all(normalise, "I", "1");
    Data decoded;

    // Decode base32 from public key hash hex string (after 1 byte)
    if (!Base32::decode(normalise.substr(2), decoded, BASE32_ALPHABET_CROCKFORD)) {
        return false;
    }

    // Verify that checksums match.
    uint16_t checksum_expected = Crc::crc16(decoded.data(), rawSize);
    cout << "expected checksum: " << checksum_expected << endl;
    uint16_t checksum_actual = static_cast<uint16_t>((decoded[rawSize] << 8) | decoded[rawSize - 1]); // unsigned short (little endian)
    cout << "checksum actual: " << checksum_actual << endl;
    if (checksum_expected != checksum_actual) {
        return false;
    }

    memzero(decoded.data(), decoded.size());
    return true;
}

Address::Address(const std::string& string) {
    // Ensure address is valid
    if (!isValid(string)) {
        throw std::invalid_argument("Invalid address data");
    }

    Data decoded;
    Base32::decode(string, decoded, BASE32_ALPHABET_CROCKFORD);
    std::copy(decoded.begin() + 1, decoded.end(), bytes.begin());
}

Address::Address(const PublicKey& publicKey) {
    if (publicKey.type != TWPublicKeyTypeSECP256k1) {
        throw std::invalid_argument("Invalid public key type");
    }
    const auto hashData = publicKey.hash({}, Hash::sha256ripemd);
    std::copy(hashData.begin(), hashData.end(), bytes.data());
}

std::string Address::string() const {
    std::vector<uint8_t> bytes_full;
    bytes_full.push_back(26 << 3);

    bytes_full.insert(bytes_full.end(), bytes.begin(), bytes.end());

    auto checksum = Hash::sha256(Hash::sha256(bytes_full));
    bytes_full.insert(bytes_full.end(), checksum.begin(), checksum.begin() + 4);

    Data bytesAsData;
    bytesAsData.assign(bytes_full.begin(), bytes_full.end());
    return std::string("S") +  Base32::encode(bytesAsData, BASE32_ALPHABET_CROCKFORD);
}
