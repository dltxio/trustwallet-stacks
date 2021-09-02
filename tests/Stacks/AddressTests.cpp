// Copyright © 2017-2020 Trust Wallet.
//
// This file is part of Trust. The full Trust copyright notice, including
// terms governing use, modification, and redistribution, is contained in the
// file LICENSE at the root of the source code distribution tree.

#include <TrustWalletCore/TWCoinType.h>
#include "Stacks/Address.h"
#include "Bitcoin/Address.h"
#include "HexCoding.h"
#include "PrivateKey.h"

#include <gtest/gtest.h>

using namespace std;
using namespace TW;
using namespace TW::Stacks;

TEST(StacksAddress, Valid) {
    ASSERT_TRUE(Address::isValid("SP2PP2BSNVJV56CFRQFEMC5VA2X44ZBKMZAC4BWZ9"));
}

TEST(StacksAddress, Invalid) {
    ASSERT_FALSE(Address::isValid("TP2PP2BSNVJV56CFRQFEMC5VA2X44ZBKMZAC4BWZ9")); // Invalid prefix
    ASSERT_FALSE(Address::isValid("SP2PP2BSNVKV56CFRQFEMC5VA2X44ZBKMZAC4BWZ9")); // Modify address
    ASSERT_FALSE(Address::isValid("SP2PP2BSNVJV56CFRQFEMC5VA2X44ZBKMZAC4BWZ0")); // Modify checksum
    ASSERT_FALSE(Address::isValid("SP2PP2BSNVJV56CFRQFEMC5VA2X44ZBKMZAC4BWZ"));  // Short address
}

TEST(StacksAddress, FromPrivateKey) {
    const auto privateKey = PrivateKey(parse_hex("04f3335197813301af8e8ff65a71e613a93241790a9db25b1083943d81dafc1b"));
    const auto address = Address(privateKey.getPublicKey(TWPublicKeyTypeSECP256k1));
    ASSERT_EQ(address.string(), "SP2PP2BSNVJV56CFRQFEMC5VA2X44ZBKMZAC4BWZ9");
}

TEST(StacksAddress, FromString) {
    const auto compare = "SP2PP2BSNVJV56CFRQFEMC5VA2X44ZBKMZAC4BWZ9";
    const auto address = Address(compare);
    ASSERT_EQ(address.string(), compare);
}
