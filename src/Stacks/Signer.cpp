// Copyright © 2017-2021 Trust Wallet.
//
// This file is part of Trust. The full Trust copyright notice, including
// terms governing use, modification, and redistribution, is contained in the
// file LICENSE at the root of the source code distribution tree.

#include "Signer.h"
#include "Address.h"
#include "../PublicKey.h"
#include "../PrivateKey.h"
#include "../BinaryCoding.h"
#include "../HexCoding.h"

#include <algorithm>

using namespace TW;
using namespace TW::Stacks;

static const auto MAINNET_TRANSACTION_VERSION = 0x00;

static const auto MAINNET_CHAIN_ID = 0x01;

static const auto ANCHORMODE_ONCHAINONLY = 0x01;
static const auto ANCHORMODE_OFFCHAINONLY = 0x02;
static const auto ANCHORMODE_ANY = 0x03;
static const auto ANCHORMODE = { ANCHORMODE_ONCHAINONLY, ANCHORMODE_OFFCHAINONLY, ANCHORMODE_ANY };

static const auto ADDRESSHASHMODE_SERIALIZEP2PKH = 0x00;

static const auto AUTHTYPE_STANDARD = 0x04;

static const auto MEMO_MAX_LENGTH_BYTES = 34;

static const auto CLARITYTYPE_PRINCIPALSTANDARD = 0x05;

static const auto PAYLOADTYPE_TOKENTRANSFER = 0x00;

static const auto POSTCONDITIONMODE_DENY = 0x02;

static const auto PUBKEYENCODING_COMPRESSED = 0x01;

static const auto RECOVERABLE_ECSDA_SIG_LENGTH_BYTES = 65;

Data serialize(const Proto::MessageSignature& signature) {
    auto data = signature.data();
    return Data(data.begin(), data.end());
}

Data serialize(const Proto::SingleSigSpendingCondition& spending) {
    Data data;
    data.push_back(spending.hashmode());
    auto signer = spending.signer();
    data.insert(data.end(), signer.begin(), signer.end());
    encode64BE(spending.nonce(), data);
    encode64BE(spending.fee(), data);
    data.push_back(spending.keyencoding());
    auto signature = serialize(spending.signature());
    data.insert(data.end(), signature.begin(), signature.end());
    return data;
}

Data serialize(const Proto::SpendingCondition& spending) {
    if (!spending.has_single()) {
	throw std::exception(); // !!
    }
    return serialize(spending.single());
}

Data serialize(const Proto::Authorization& auth) {
    Data data;
    if (auth.authtype() != AUTHTYPE_STANDARD) {
        throw std::exception();
    }
    data.push_back(auth.authtype());
    auto spendingCondition = serialize(auth.spendingcondition());
    data.insert(data.end(), spendingCondition.begin(), spendingCondition.end());
    return data;
}

Data serialize(const Proto::Address& addr) {
    Data data;
    data.push_back(addr.version());
    auto hash = addr.hash160();
    data.insert(data.end(), hash.begin(), hash.end());
    return data;
}

Data serialize(const Proto::StandardPrincipalCV& cv) {
    Data data;
    data.push_back(CLARITYTYPE_PRINCIPALSTANDARD);
    auto addr = serialize(cv.address());
    data.insert(data.end(), addr.begin(), addr.end());
    return data;
}

Data serialize(const Proto::ContractPrincipalCV& cv) {
    return {};
}

Data serialize(const Proto::PrincipalCV& cv) {
    Data data;
    if (cv.has_standard()) {
        auto standard = serialize(cv.standard());
        data.insert(data.end(), standard.begin(), standard.end());
    }
    else if (cv.has_contract()) {
        auto contract = serialize(cv.contract());
	data.insert(data.end(), contract.begin(), contract.end());
    }
    else {
        throw std::exception();
    }
    return data;
}

Data serialize(const Proto::MemoString& memo) {
    Data data(MEMO_MAX_LENGTH_BYTES);
    auto content = memo.content();
    if (content.size() > data.size()) {
        throw std::exception();
    }
    std::copy(content.begin(), content.end(), data.begin());
    return data;
}

Data serialize(const Proto::TokenTransferPayload& transfer) {
    Data data;
    data.push_back(PAYLOADTYPE_TOKENTRANSFER);
    auto recipient = serialize(transfer.recipient());
    data.insert(data.end(), recipient.begin(), recipient.end());
    encode64BE(transfer.amount(), data);
    auto memo = serialize(transfer.memo());
    data.insert(data.end(), memo.begin(), memo.end());
    return data;
}

Data serialize(const Proto::Payload& payload) {
    Data data;
    if (payload.has_transfer()) {
        auto transfer = serialize(payload.transfer());
	data.insert(data.end(), transfer.begin(), transfer.end());
    }
    else {
        throw std::exception();
    }
    return data;
}

Data serialize(const Proto::StacksTransaction& transaction) {
    Data data;
    data.push_back(transaction.version());
    encode32BE(transaction.chainid(), data);
    auto auth = serialize(transaction.auth());
    data.insert(data.end(), auth.begin(), auth.end());
    data.push_back(transaction.anchormode());
    data.push_back(POSTCONDITIONMODE_DENY);
    encode32BE(0, data); // no items in post-condition list
    auto payload = serialize(transaction.payload());
    data.insert(data.end(), payload.begin(), payload.end());
    return data;
}

Proto::SigningOutput Signer::sign(const Proto::SigningInput& input) noexcept {
    auto signer = Signer(input);
    auto output = Proto::SigningOutput();
    auto data = signer.sign();
    output.set_encoded(&data[0], data.size());
    return output;
}

Data Signer::sign() const noexcept {
    if (input.has_tokentransfer()) {
	Proto::StacksTransaction tx;
	auto senderKey = PrivateKey(parse_hex(input.tokentransfer().senderkey()));
        auto senderAddress = Address(senderKey.getPublicKey(TWPublicKeyTypeSECP256k1));
        tx.set_version(MAINNET_TRANSACTION_VERSION);
        tx.set_chainid(MAINNET_CHAIN_ID);
	auto transferCommon = input.tokentransfer().common();
        if (std::find(ANCHORMODE.begin(), ANCHORMODE.end(), transferCommon.anchormode()) != ANCHORMODE.end()) {
	}
        tx.set_anchormode(transferCommon.anchormode());
	auto auth = tx.mutable_auth();
	auth->set_authtype(AUTHTYPE_STANDARD);
	auto spending = auth->mutable_spendingcondition()->mutable_single();
	spending->set_hashmode(ADDRESSHASHMODE_SERIALIZEP2PKH);
	spending->set_signer(&senderAddress.bytes[1], senderAddress.bytes.size() - 1);
	spending->set_nonce(transferCommon.nonce());
	spending->set_fee(transferCommon.fee());
	spending->set_keyencoding(PUBKEYENCODING_COMPRESSED);
	auto transfer = tx.mutable_payload()->mutable_transfer();
	auto address = transfer->mutable_recipient()->mutable_standard()->mutable_address();
	auto recipientAddress = Address(transferCommon.recipient());
	address->set_version(recipientAddress.bytes[0]);
	address->set_hash160(&recipientAddress.bytes[1], recipientAddress.bytes.size() - 1);
        transfer->set_payloadtype(PAYLOADTYPE_TOKENTRANSFER);
	transfer->set_amount(transferCommon.amount());
	auto memo = transfer->mutable_memo();
	memo->set_content(transferCommon.memo());
	auto result = serialize(tx);
	for (int i = 0; i < result.size(); i++)
            std::cout << std::setfill('0') << std::setw(2) << std::hex << (int)result[i];
	std::cout << std::endl;
	return result;
    }
    return {};
}
