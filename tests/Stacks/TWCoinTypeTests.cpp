// Copyright © 2017-2021 Trust Wallet.
//
// This file is part of Trust. The full Trust copyright notice, including
// terms governing use, modification, and redistribution, is contained in the
// file LICENSE at the root of the source code distribution tree.
//
// This is a GENERATED FILE, changes made here MAY BE LOST.
// Generated one-time (codegen/bin/cointests)
//

#include "../interface/TWTestUtilities.h"
#include <TrustWalletCore/TWCoinTypeConfiguration.h>
#include <gtest/gtest.h>


TEST(TWStacksCoinType, TWCoinType) {
    auto symbol = WRAPS(TWCoinTypeConfigurationGetSymbol(TWCoinTypeStacks));
    auto txId = WRAPS(TWStringCreateWithUTF8Bytes("65f89adcacd272f07d198e09d5c9da8a749dd84e3b7f3c95118ce8858e359b3d"));
    auto txUrl = WRAPS(TWCoinTypeConfigurationGetTransactionURL(TWCoinTypeStacks, txId.get()));
    auto accId = WRAPS(TWStringCreateWithUTF8Bytes("SP30EF9XFSX2XC5BH2KJ6EQAP6RPX71JC1K5RQ0N2"));
    auto accUrl = WRAPS(TWCoinTypeConfigurationGetAccountURL(TWCoinTypeStacks, accId.get()));
    auto id = WRAPS(TWCoinTypeConfigurationGetID(TWCoinTypeStacks));
    auto name = WRAPS(TWCoinTypeConfigurationGetName(TWCoinTypeStacks));

    ASSERT_EQ(TWCoinTypeConfigurationGetDecimals(TWCoinTypeStacks), 8);
    ASSERT_EQ(TWBlockchainStacks, TWCoinTypeBlockchain(TWCoinTypeStacks));
    ASSERT_EQ(0x0, TWCoinTypeP2shPrefix(TWCoinTypeStacks));
    ASSERT_EQ(0x0, TWCoinTypeStaticPrefix(TWCoinTypeStacks));
    assertStringsEqual(symbol, "STX");
    assertStringsEqual(txUrl, "https://explorer.stacks.co/txid/0x65f89adcacd272f07d198e09d5c9da8a749dd84e3b7f3c95118ce8858e359b3d");
    assertStringsEqual(accUrl, "https://explorer.stacks.co/address/SP30EF9XFSX2XC5BH2KJ6EQAP6RPX71JC1K5RQ0N2?chain=mainnet");
    assertStringsEqual(id, "stacks");
    assertStringsEqual(name, "Stacks");
}
