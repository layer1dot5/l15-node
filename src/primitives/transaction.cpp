// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2021 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <primitives/transaction.h>

#include <consensus/amount.h>
#include <hash.h>
#include <tinyformat.h>
#include <util/strencodings.h>

#include <assert.h>



std::string COutPoint::ToString() const
{
    return strprintf("COutPoint(%s, %u)", hash.ToString().substr(0,10), n);
}

CTxIn::CTxIn(COutPoint prevoutIn, CScript scriptSigIn, uint32_t nSequenceIn)
{
    prevout = prevoutIn;
    scriptSig = scriptSigIn;
    nSequence = nSequenceIn;
}

CTxIn::CTxIn(uint256 hashPrevTx, uint32_t nOut, CScript scriptSigIn, uint32_t nSequenceIn)
{
    prevout = COutPoint(hashPrevTx, nOut);
    scriptSig = scriptSigIn;
    nSequence = nSequenceIn;
}

std::string CTxIn::ToString() const
{
    std::string str;
    str += "CTxIn(";
    str += prevout.ToString();
    if (prevout.IsNull())
        str += strprintf(", coinbase %s", HexStr(scriptSig));
    else
        str += strprintf(", scriptSig=%s", HexStr(scriptSig).substr(0, 24));
    if (nSequence != SEQUENCE_FINAL)
        str += strprintf(", nSequence=%u", nSequence);
    str += ")";
    return str;
}

std::string CTxOut::ToString() const
{
    return strprintf("CTxOut(mMagicTag=%s, nValue=%d.%08d, scriptPubKey=%s)", toString(magicTag()), nValue / COIN, nValue % COIN, HexStr(scriptPubKey).substr(0, 30));
}

CTxOut::CTxOut(const CDataTxOut &dataOut)
{
    if (dataOut.mMagicTag & L15_DATA_FLAG) {
        throw std::runtime_error(strprintf("Cannot convert %s output to coin value output", toString(dataOut.magicTag())));
    }

    mMagicTag = dataOut.mMagicTag;

    CDataStream s(dataOut.mData, SER_NETWORK, PROTOCOL_VERSION);
    s >> nValue;
    s >> scriptPubKey;
}

CTxOut &CTxOut::operator=(CDataTxOut &dataOut)
{
    if (dataOut.mMagicTag & L15_DATA_FLAG) {
        throw std::runtime_error(strprintf("Cannot convert %s output to coin value output", toString(dataOut.magicTag())));
    }

    mMagicTag = dataOut.mMagicTag;

    CDataStream s(dataOut.mData, SER_NETWORK, PROTOCOL_VERSION);
    s >> nValue;
    s >> scriptPubKey;

    return *this;
}

CMutableTransaction::CMutableTransaction() : nVersion(CTransaction::CURRENT_VERSION), nLockTime(0) {}
CMutableTransaction::CMutableTransaction(const CTransaction& tx) : vin(tx.vin), vout(tx.vout), nVersion(tx.nVersion), nLockTime(tx.nLockTime) {}

uint256 CMutableTransaction::GetHash() const
{
    return SerializeHash(*this, SER_GETHASH, SERIALIZE_TRANSACTION_NO_WITNESS);
}

uint256 CTransaction::ComputeHash() const
{
    return SerializeHash(*this, SER_GETHASH, SERIALIZE_TRANSACTION_NO_WITNESS);
}

uint256 CTransaction::ComputeWitnessHash() const
{
    if (!HasWitness()) {
        return hash;
    }
    return SerializeHash(*this, SER_GETHASH, 0);
}

CTransaction::CTransaction(const CMutableTransaction& tx) : vin(tx.vin), vout(tx.vout), nVersion(tx.nVersion), nLockTime(tx.nLockTime), hash{ComputeHash()}, m_witness_hash{ComputeWitnessHash()} {}
CTransaction::CTransaction(CMutableTransaction&& tx) : vin(std::move(tx.vin)), vout(std::move(tx.vout)), nVersion(tx.nVersion), nLockTime(tx.nLockTime), hash{ComputeHash()}, m_witness_hash{ComputeWitnessHash()} {}

CAmount CTransaction::GetValueOut(L15MagicTag tag) const
{
    assert(!(tag | L15_DATA_FLAG));

    CAmount nValueOut = 0;
    for (const auto& tx_out : vout) {
        if (tx_out.magicTag() != tag)
            continue;

        CTxOut val_out(tx_out);
        if (!MoneyRange(val_out.nValue) || !MoneyRange(nValueOut + val_out.nValue))
            throw std::runtime_error(std::string(__func__) + ": value out of range");
        nValueOut += val_out.nValue;
    }
    assert(MoneyRange(nValueOut));
    return nValueOut;
}

unsigned int CTransaction::GetTotalSize() const
{
    return ::GetSerializeSize(*this, PROTOCOL_VERSION);
}

std::string CTransaction::ToString() const
{
    std::string str;
    str += strprintf("CTransaction(hash=%s, ver=%d, vin.size=%u, vout.size=%u, nLockTime=%u)\n",
        GetHash().ToString().substr(0,10),
        nVersion,
        vin.size(),
        vout.size(),
        nLockTime);
    for (const auto& tx_in : vin)
        str += "    " + tx_in.ToString() + "\n";
    for (const auto& tx_in : vin)
        str += "    " + tx_in.scriptWitness.ToString() + "\n";
    for (const auto& tx_out : vout)
        str += "    " + tx_out.ToString() + "\n";
    return str;
}

//size_t CTxOut::GetDataLength() const
//{
//    switch (mMagicTag) {
//    L15_SR:
//    L15_USD:
//        return sizeof(CAmount) + 32/*size of XOnlyPubKey*/;
//    L15_UNKNOWN:
//        return 0;
//    }
//    return 0;
//}

namespace {
    const static char * const szL15_SR = "L15_SR";
    const static char * const szL15_USD = "L15_USD";
    const static char * const szL15_MEMBER_PUBNONCE = "L15_MEMBER_PUBNONCE";
    const static char * const szL15_UNKNOWN = "UNKNOWN";
}


const char *toString(L15MagicTag tag)
{
    switch (tag) {
    case L15MagicTag::L15_SR: return szL15_SR;
    case L15MagicTag::L15_USD: return szL15_USD;
    case L15MagicTag::L15_MEMBER_PUBNONCE: return szL15_MEMBER_PUBNONCE;
    default: return szL15_UNKNOWN;
    }
}

std::string CDataTxOut::ToString() const
{
    return strprintf("CTxOut(mMagicTag=%s, nData=%s)", toString(static_cast<L15MagicTag>(mMagicTag)), HexStr(mData).substr(0, 32));

}

CDataTxOut::CDataTxOut(const CTxOut & out) : mMagicTag(out.mMagicTag)
{
    CDataStream s(mData, SER_NETWORK, PROTOCOL_VERSION);
    s << out.nValue;
    s << out.scriptPubKey;
}

CDataTxOut &CDataTxOut::operator=(const CTxOut & out)
{
    mMagicTag = out.mMagicTag;

    CDataStream s(mData, SER_NETWORK, PROTOCOL_VERSION);
    s << out.nValue;
    s << out.scriptPubKey;

    return *this;
}
