// Copyright © 2017-2020 Trust Wallet.
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
    auto txId = WRAPS(TWStringCreateWithUTF8Bytes("fc57e27f8b631f1df3aeb47241309a4b90f8574f234b3b13a61637d5b7a7b6d0"));
    auto txUrl = WRAPS(TWCoinTypeConfigurationGetTransactionURL(TWCoinTypeStacks, txId.get()));
    auto accId = WRAPS(TWStringCreateWithUTF8Bytes("SP19TEDPGHNPAA3M4KSH9V3EZ3M7E5H89RMRZQH8A"));
    auto accUrl = WRAPS(TWCoinTypeConfigurationGetAccountURL(TWCoinTypeStacks, accId.get()));
    auto id = WRAPS(TWCoinTypeConfigurationGetID(TWCoinTypeStacks));
    auto name = WRAPS(TWCoinTypeConfigurationGetName(TWCoinTypeStacks));

    ASSERT_EQ(TWCoinTypeConfigurationGetDecimals(TWCoinTypeStacks), 6);
    ASSERT_EQ(TWBlockchainStacks, TWCoinTypeBlockchain(TWCoinTypeStacks));
    ASSERT_EQ(0x0, TWCoinTypeP2shPrefix(TWCoinTypeStacks));
    ASSERT_EQ(0x0, TWCoinTypeStaticPrefix(TWCoinTypeStacks));
    assertStringsEqual(symbol, "STX");
    assertStringsEqual(txUrl, "https://explorer.stacks.co/txid/fc57e27f8b631f1df3aeb47241309a4b90f8574f234b3b13a61637d5b7a7b6d0");
    assertStringsEqual(accUrl, "https://explorer.stacks.co/address/SP19TEDPGHNPAA3M4KSH9V3EZ3M7E5H89RMRZQH8A");
    assertStringsEqual(id, "stacks");
    assertStringsEqual(name, "Stacks");
}
