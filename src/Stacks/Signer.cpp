// Copyright © 2017-2021 Trust Wallet.
//
// This file is part of Trust. The full Trust copyright notice, including
// terms governing use, modification, and redistribution, is contained in the
// file LICENSE at the root of the source code distribution tree.

#include "Signer.h"
#include "Address.h"
#include "../Hash.h"
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

static const auto PUBKEYENCODING_COMPRESSED = 0x00;
static const auto PUBKEYENCODING_UNCOMPRESSED = 0x01;

static const auto RECOVERABLE_ECSDA_SIG_LENGTH_BYTES = 65;

static const auto PRIVATE_KEY_LENGTH = 32;

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

void dump(const Data& data) {
    for (int i = 0; i < data.size(); i++)
        std::cout << std::setfill('0') << std::setw(2) << std::hex << (int)data[i];
    std::cout << std::endl;
}

std::tuple<PrivateKey, TWPublicKeyType> Signer::getKey() const {
    auto senderKey = input.senderkey();
    auto keyType = TWPublicKeyTypeSECP256k1;
    if ((senderKey.size() == (PRIVATE_KEY_LENGTH + 1)) && (senderKey.back() == 0x01)) {
        keyType = TWPublicKeyTypeSECP256k1Extended;
        senderKey.pop_back();
    }
    else if (senderKey.size() != PRIVATE_KEY_LENGTH) {
        throw std::invalid_argument("Invalid private key format"); 
    }
    return std::make_tuple(PrivateKey(senderKey), keyType);
}

Proto::StacksTransaction Signer::generate() const {
    Proto::StacksTransaction tx;
    if (input.has_tokentransfer()) {
        auto tokenTransfer = input.tokentransfer();
        auto[privateKey, keyType] = getKey();
        auto senderAddress = Address(privateKey.getPublicKey(keyType));
        auto recipientAddress = Address(tokenTransfer.recipient());
        tx.set_version(MAINNET_TRANSACTION_VERSION);
        tx.set_chainid(MAINNET_CHAIN_ID);
        if (std::find(ANCHORMODE.begin(), ANCHORMODE.end(), tokenTransfer.anchormode()) == ANCHORMODE.end()) {
            throw std::invalid_argument("Invalid anchor mode");
        }
        tx.set_anchormode(tokenTransfer.anchormode());
        auto auth = tx.mutable_auth();
        auth->set_authtype(AUTHTYPE_STANDARD);
        auto spending = auth->mutable_spendingcondition()->mutable_single();
        spending->set_hashmode(ADDRESSHASHMODE_SERIALIZEP2PKH);
        spending->set_signer(&senderAddress.bytes[1], senderAddress.bytes.size() - 1);
        spending->set_nonce(tokenTransfer.nonce());
        spending->set_fee(tokenTransfer.fee());
        spending->set_keyencoding(keyType == TWPublicKeyTypeSECP256k1 ? PUBKEYENCODING_COMPRESSED : PUBKEYENCODING_UNCOMPRESSED);
        auto transfer = tx.mutable_payload()->mutable_transfer();
        transfer->set_payloadtype(PAYLOADTYPE_TOKENTRANSFER);
        transfer->set_amount(tokenTransfer.amount());
        auto address = transfer->mutable_recipient()->mutable_standard()->mutable_address();
        address->set_version(recipientAddress.bytes[0]);
        address->set_hash160(&recipientAddress.bytes[1], recipientAddress.bytes.size() - 1);
        auto memo = transfer->mutable_memo();
        memo->set_content(tokenTransfer.memo());
    }
    else {
        throw std::invalid_argument("Invalid input type");
    }
    return tx;
}

void Signer::sign(Proto::StacksTransaction& tx) const {
    auto copyTx(tx);
    auto auth = copyTx.mutable_auth();
    if ((auth->authtype() != AUTHTYPE_STANDARD) || !auth->spendingcondition().has_single()) {
        throw std::exception();
    }
    auto spending = auth->mutable_spendingcondition()->mutable_single();
    spending->set_nonce(0);
    spending->set_fee(0);
    spending->mutable_signature()->set_data(std::string(RECOVERABLE_ECSDA_SIG_LENGTH_BYTES, 0x00));
    auto encoded = serialize(copyTx);
    auto sig = Hash::sha512_256(encoded);
    sig.push_back(AUTHTYPE_STANDARD);
    encode64BE(tx.auth().spendingcondition().single().fee(), sig);
    encode64BE(tx.auth().spendingcondition().single().nonce(), sig);
    auto newSig = Hash::sha512_256(sig);
    auto [privateKey, keyType] = getKey();
    auto result = privateKey.sign(newSig, TWCurveSECP256k1);
    result.insert(result.begin(), result.back());
    result.pop_back();
    spending = tx.mutable_auth()->mutable_spendingcondition()->mutable_single();    
    spending->mutable_signature()->set_data(&result[0], result.size());
}

Data Signer::sign() const noexcept {
    auto tx = generate();
    sign(tx);
    return serialize(tx);
}

