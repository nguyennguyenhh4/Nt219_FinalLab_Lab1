#include <gtest/gtest.h>
#include <string>
#include <stdexcept>
#include <cryptopp/cryptlib.h>
#include <cryptopp/aes.h>
#include <cryptopp/osrng.h>
#include <cryptopp/secblock.h>
#include <cryptopp/modes.h>
#include <cryptopp/gcm.h>
#include <cryptopp/ccm.h>
#include <cryptopp/filters.h>

using namespace CryptoPP;
using namespace std;

static constexpr size_t GCM_TAG_SIZE    = 16;
static constexpr size_t CCM_TAG_SIZE    = 16;
static constexpr size_t CCM_IV_SIZE     = 7;
static constexpr size_t GCM_IV_SIZE     = 12;

template<class ENC>
static void EncryptIV(const string& inData, string& outData, const SecByteBlock& key, const SecByteBlock& iv) {
    ENC enc;
    enc.SetKeyWithIV(key, key.size(), iv);
    StringSource(inData, true, new StreamTransformationFilter(enc, new StringSink(outData)));
}

template<class DEC>
static void DecryptIV(const string& inData, string& outData, const SecByteBlock& key, const SecByteBlock& iv) {
    DEC dec;
    dec.SetKeyWithIV(key, key.size(), iv);
    StringSource(inData, true, new StreamTransformationFilter(dec, new StringSink(outData)));
}

static void EncryptGCM(const string& inData, string& outData, const SecByteBlock& key, const SecByteBlock& iv, const string& aad) {
    GCM<AES>::Encryption enc;
    enc.SetKeyWithIV(key, key.size(), iv, iv.size());
    AuthenticatedEncryptionFilter f(enc, new StringSink(outData), false, GCM_TAG_SIZE);
    if (!aad.empty()) f.ChannelPut(AAD_CHANNEL, reinterpret_cast<const CryptoPP::byte*>(aad.data()), aad.size());
    f.ChannelMessageEnd(AAD_CHANNEL);
    f.Put(reinterpret_cast<const CryptoPP::byte*>(inData.data()), inData.size());
    f.MessageEnd();
}

static void DecryptGCM(const string& inData, string& outData, const SecByteBlock& key, const SecByteBlock& iv, const string& aad) {
    GCM<AES>::Decryption dec;
    dec.SetKeyWithIV(key, key.size(), iv, iv.size());
    AuthenticatedDecryptionFilter f(dec, new StringSink(outData),
        AuthenticatedDecryptionFilter::MAC_AT_END | AuthenticatedDecryptionFilter::THROW_EXCEPTION, GCM_TAG_SIZE);
    if (!aad.empty()) f.ChannelPut(AAD_CHANNEL, reinterpret_cast<const CryptoPP::byte*>(aad.data()), aad.size());
    f.ChannelMessageEnd(AAD_CHANNEL);
    f.Put(reinterpret_cast<const CryptoPP::byte*>(inData.data()), inData.size());
    f.MessageEnd();
}

static void EncryptCCM(const string& inData, string& outData, const SecByteBlock& key, const SecByteBlock& iv, const string& aad) {
    CCM<AES, CCM_TAG_SIZE>::Encryption enc;
    enc.SetKeyWithIV(key, key.size(), iv, iv.size());
    enc.SpecifyDataLengths(aad.size(), inData.size(), 0);
    AuthenticatedEncryptionFilter f(enc, new StringSink(outData));
    if (!aad.empty()) f.ChannelPut(AAD_CHANNEL, reinterpret_cast<const CryptoPP::byte*>(aad.data()), aad.size());
    f.ChannelMessageEnd(AAD_CHANNEL);
    f.Put(reinterpret_cast<const CryptoPP::byte*>(inData.data()), inData.size());
    f.MessageEnd();
}

static void DecryptCCM(const string& inData, string& outData, const SecByteBlock& key, const SecByteBlock& iv, const string& aad) {
    CCM<AES, CCM_TAG_SIZE>::Decryption dec;
    dec.SetKeyWithIV(key, key.size(), iv, iv.size());
    size_t ctLen = inData.size() > CCM_TAG_SIZE ? inData.size() - CCM_TAG_SIZE : 0;
    dec.SpecifyDataLengths(aad.size(), ctLen, 0);
    AuthenticatedDecryptionFilter f(dec, new StringSink(outData),
        AuthenticatedDecryptionFilter::MAC_AT_END | AuthenticatedDecryptionFilter::THROW_EXCEPTION);
    if (!aad.empty()) f.ChannelPut(AAD_CHANNEL, reinterpret_cast<const CryptoPP::byte*>(aad.data()), aad.size());
    f.ChannelMessageEnd(AAD_CHANNEL);
    f.Put(reinterpret_cast<const CryptoPP::byte*>(inData.data()), inData.size());
    f.MessageEnd();
}

// ---------------------- GOOGLETEST CASES ----------------------
class AesNegativeTest : public ::testing::Test {
protected:
    AutoSeededRandomPool prng;
    SecByteBlock key, wrongKey, iv, wrongIV;
    SecByteBlock gcmIV, wrongGcmIV, ccmIV, wrongCcmIV;
    string plaintext;

    void SetUp() override {
        plaintext = "NegativeTestPlaintext1234567890!";
        
        key.New(32); wrongKey.New(32);
        iv.New(AES::BLOCKSIZE); wrongIV.New(AES::BLOCKSIZE);
        
        prng.GenerateBlock(key, key.size());
        prng.GenerateBlock(wrongKey, wrongKey.size());
        prng.GenerateBlock(iv, iv.size());
        prng.GenerateBlock(wrongIV, wrongIV.size());

        gcmIV.New(GCM_IV_SIZE); wrongGcmIV.New(GCM_IV_SIZE);
        prng.GenerateBlock(gcmIV, gcmIV.size());
        prng.GenerateBlock(wrongGcmIV, wrongGcmIV.size());

        ccmIV.New(CCM_IV_SIZE); wrongCcmIV.New(CCM_IV_SIZE);
        prng.GenerateBlock(ccmIV, ccmIV.size());
        prng.GenerateBlock(wrongCcmIV, wrongCcmIV.size());
    }
};

TEST_F(AesNegativeTest, CBC_WrongKey) {
    string ct, recovered;
    EncryptIV<CBC_Mode<AES>::Encryption>(plaintext, ct, key, iv);
    try {
        DecryptIV<CBC_Mode<AES>::Decryption>(ct, recovered, wrongKey, iv);
        EXPECT_NE(recovered, plaintext);
    } catch (...) { SUCCEED(); }
}

TEST_F(AesNegativeTest, CBC_WrongIV) {
    string ct, recovered;
    EncryptIV<CBC_Mode<AES>::Encryption>(plaintext, ct, key, iv);
    try {
        DecryptIV<CBC_Mode<AES>::Decryption>(ct, recovered, key, wrongIV);
        EXPECT_NE(recovered, plaintext);
    } catch (...) { SUCCEED(); }
}

TEST_F(AesNegativeTest, CBC_TamperedCiphertext) {
    string ct, recovered;
    EncryptIV<CBC_Mode<AES>::Encryption>(plaintext, ct, key, iv);
    if (!ct.empty()) ct[ct.size() / 2] ^= 0xFF;
    try {
        DecryptIV<CBC_Mode<AES>::Decryption>(ct, recovered, key, iv);
        EXPECT_NE(recovered, plaintext);
    } catch (...) { SUCCEED(); }
}

TEST_F(AesNegativeTest, CTR_WrongKey) {
    string ct, recovered;
    EncryptIV<CTR_Mode<AES>::Encryption>(plaintext, ct, key, iv);
    try {
        DecryptIV<CTR_Mode<AES>::Decryption>(ct, recovered, wrongKey, iv);
        EXPECT_NE(recovered, plaintext);
    } catch (...) { SUCCEED(); }
}

TEST_F(AesNegativeTest, GCM_WrongKey_Throws) {
    string ct, rec;
    EncryptGCM(plaintext, ct, key, gcmIV, "");
    EXPECT_THROW(DecryptGCM(ct, rec, wrongKey, gcmIV, ""), HashVerificationFilter::HashVerificationFailed);
}

TEST_F(AesNegativeTest, GCM_WrongIV_Throws) {
    string ct, rec;
    EncryptGCM(plaintext, ct, key, gcmIV, "");
    EXPECT_THROW(DecryptGCM(ct, rec, key, wrongGcmIV, ""), HashVerificationFilter::HashVerificationFailed);
}

TEST_F(AesNegativeTest, GCM_TamperedCT_Throws) {
    string ct, rec;
    EncryptGCM(plaintext, ct, key, gcmIV, "");
    if (!ct.empty()) ct[0] ^= 0xFF;
    EXPECT_THROW(DecryptGCM(ct, rec, key, gcmIV, ""), HashVerificationFilter::HashVerificationFailed);
}

TEST_F(AesNegativeTest, GCM_TamperedTag_Throws) {
    string ct, rec;
    EncryptGCM(plaintext, ct, key, gcmIV, "");
    if (ct.size() >= GCM_TAG_SIZE) ct[ct.size() - 1] ^= 0xFF;
    EXPECT_THROW(DecryptGCM(ct, rec, key, gcmIV, ""), HashVerificationFilter::HashVerificationFailed);
}

TEST_F(AesNegativeTest, CCM_TamperedCT_Throws) {
    string ct, rec;
    EncryptCCM(plaintext, ct, key, ccmIV, "");
    if (!ct.empty()) ct[0] ^= 0xAA;
    EXPECT_THROW(DecryptCCM(ct, rec, key, ccmIV, ""), HashVerificationFilter::HashVerificationFailed);
}

TEST_F(AesNegativeTest, InvalidKeyLength_Throws) {
    SecByteBlock badKey(10);
    prng.GenerateBlock(badKey, badKey.size());
    CBC_Mode<AES>::Encryption enc;
    EXPECT_THROW(enc.SetKeyWithIV(badKey, badKey.size(), iv), InvalidKeyLength);
}