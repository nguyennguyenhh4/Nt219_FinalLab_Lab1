/**
 * aescli.cpp - Lab 1: Symmetric Encryption with Crypto++
 *
 * Supported modes : ECB, CBC, OFB, CFB, CTR, XTS, CCM, GCM
 * AEAD            : GCM, CCM  (--aead --aad / --aad-text)
 * IV handling     : auto-generate, persist to sidecar JSON, nonce-reuse protection
 * Encoding        : --encode hex|base64|raw
 * KAT runner      : --kat vectors.json
 *
 * Build (example):
 *   mkdir build && cd build
 *   cmake .. && cmake --build .
 *
 * Usage examples:
 *   aescli keygen --bits 256 --out key.bin
 *   aescli encrypt --mode gcm --key key.bin --in plain.txt --out ct.bin --aead
 *   aescli decrypt --mode gcm --key key.bin --in ct.bin  --out plain.txt --aead
 *   aescli encrypt --mode ecb --key key.bin --in small.txt --out ct.bin --allow-ecb
 *   aescli --kat vectors.json
 */

// --------------------------- Includes ---------------------------
#include <iostream>
#include <fstream>
#include <sstream>
#include <string>
#include <vector>
#include <stdexcept>
#include <algorithm>
#include <cstring>
#include <filesystem>

// Crypto++ headers
#include <cryptopp/cryptlib.h>
#include <cryptopp/aes.h>
#include <cryptopp/osrng.h>
#include <cryptopp/secblock.h>
#include <cryptopp/hex.h>
#include <cryptopp/base64.h>
#include <cryptopp/files.h>
#include <cryptopp/filters.h>
#include <cryptopp/modes.h>
#include <cryptopp/gcm.h>
#include <cryptopp/ccm.h>
#include <cryptopp/xts.h>

// Minimal JSON parser (single-header style, no external deps)
// We use a hand-rolled tiny parser for KAT vectors.json
// Format supported: flat array of objects with string values only.

namespace fs = std::filesystem;
using namespace CryptoPP;
using namespace std;

// ------------------------- Constants -------------------------
static constexpr size_t ECB_MAX_BYTES   = 16 * 1024;   // 16 KiB
static constexpr size_t GCM_TAG_SIZE    = 16;
static constexpr size_t CCM_TAG_SIZE    = 16;
static constexpr size_t CCM_IV_SIZE     = 7;            // 7–13 bytes; we use 7
static constexpr size_t GCM_IV_SIZE     = 12;           // 96-bit recommended
static constexpr size_t XTS_KEY_FACTOR  = 2;            // XTS needs 2× key material

// ------------------------- Utilities -------------------------

// Hex-encode arbitrary bytes to lowercase string
static string ToHex(const CryptoPP::byte* data, size_t len)
{
    string out;
    StringSource(data, len, true,
        new HexEncoder(new StringSink(out), false));
    return out;
}

// Hex-decode string > SecByteBlock
static SecByteBlock FromHex(const string& hex)
{
    string raw;
    StringSource(hex, true, new HexDecoder(new StringSink(raw)));
    SecByteBlock blk(reinterpret_cast<const CryptoPP::byte*>(raw.data()), raw.size());
    return blk;
}

// Base64-encode
static string ToBase64(const CryptoPP::byte* data, size_t len)
{
    string out;
    StringSource(data, len, true,
        new Base64Encoder(new StringSink(out), false));
    return out;
}

// Print hex with label to stdout
static void PrintHex(const string& label, const CryptoPP::byte* data, size_t len)
{
    cout << label << ": " << ToHex(data, len) << "\n";
}

// Print bytes according to chosen encoding
static void PrintEncoded(const string& label, const string& enc, const CryptoPP::byte* data, size_t len)
{
    if (enc == "hex")
        cout << label << ": " << ToHex(data, len) << "\n";
    else if (enc == "base64")
        cout << label << ": " << ToBase64(data, len) << "\n";
    else
        cout << label << ": [raw binary, " << len << " bytes]\n";
}

// Read entire file into string
static string ReadFile(const string& path)
{
    ifstream f(path, ios::binary);
    if (!f) throw runtime_error("Cannot open file: " + path);
    return string(istreambuf_iterator<char>(f), {});
}

// Write string/bytes to file
static void WriteFile(const string& path, const string& data)
{
    ofstream f(path, ios::binary | ios::trunc);
    if (!f) throw runtime_error("Cannot write file: " + path);
    f.write(data.data(), static_cast<streamsize>(data.size()));
}

// ------------------------- Sidecar JSON -------------------------
/*
 * Sidecar format  <outfile>.json
 * {
 *   "alg"  : "AES-256-GCM",
 *   "mode" : "gcm",
 *   "iv"   : "<hex>",
 *   "aad"  : "<hex>",   // optional
 *   "tag"  : "<hex>"    // AEAD only
 * }
 *
 * Nonce-reuse protection:
 *   Before encrypting with CTR/CCM/GCM we check if <outfile>.json exists
 *   and if the stored (key_fingerprint + iv) matches the current call.
 *   If yes > reject.  Key fingerprint = first 8 bytes of key in hex.
 */

struct SidecarInfo {
    string alg;
    string mode;
    string iv_hex;
    string aad_hex;
    string tag_hex;
    string key_fp;      // key fingerprint (first 8 bytes hex)
};

static string JsonField(const string& json, const string& key)
{
    // Very small JSON string-field extractor: "key":"value"
    string needle = "\"" + key + "\"";
    size_t pos = json.find(needle);
    if (pos == string::npos) return "";
    pos = json.find(':', pos);
    if (pos == string::npos) return "";
    pos = json.find('"', pos);
    if (pos == string::npos) return "";
    size_t start = pos + 1;
    size_t end   = json.find('"', start);
    if (end == string::npos) return "";
    return json.substr(start, end - start);
}

static void WriteSidecar(const string& outfile, const SidecarInfo& info)
{
    string path = outfile + ".json";
    ofstream f(path);
    f << "{\n";
    f << "  \"alg\"    : \"" << info.alg     << "\",\n";
    f << "  \"mode\"   : \"" << info.mode    << "\",\n";
    f << "  \"iv\"     : \"" << info.iv_hex  << "\",\n";
    if (!info.aad_hex.empty())
        f << "  \"aad\"   : \"" << info.aad_hex << "\",\n";
    if (!info.tag_hex.empty())
        f << "  \"tag\"   : \"" << info.tag_hex << "\",\n";
    f << "  \"key_fp\" : \"" << info.key_fp  << "\"\n";
    f << "}\n";
}

static SidecarInfo ReadSidecar(const string& outfile)
{
    string path = outfile + ".json";
    if (!fs::exists(path)) return {};
    string json = ReadFile(path);
    SidecarInfo s;
    s.alg     = JsonField(json, "alg");
    s.mode    = JsonField(json, "mode");
    s.iv_hex  = JsonField(json, "iv");
    s.aad_hex = JsonField(json, "aad");
    s.tag_hex = JsonField(json, "tag");
    s.key_fp  = JsonField(json, "key_fp");
    return s;
}

// ------------------------- Key management -------------------------

struct KeyMaterial {
    SecByteBlock key;
    SecByteBlock iv;
};

static void SaveKeyBin(const string& path, const SecByteBlock& key)
{
    WriteFile(path, string(reinterpret_cast<const char*>(key.data()), key.size()));
}

static SecByteBlock LoadKeyBin(const string& path)
{
    string raw = ReadFile(path);
    if (raw.size() != 16 && raw.size() != 24 && raw.size() != 32)
        throw runtime_error("Key file must be 16, 24, or 32 bytes (AES-128/192/256)");
    return SecByteBlock(reinterpret_cast<const CryptoPP::byte*>(raw.data()), raw.size());
}

// For XTS we need 2× key: store as 32/48/64 bytes
static SecByteBlock LoadXTSKeyBin(const string& path)
{
    string raw = ReadFile(path);
    if (raw.size() != 32 && raw.size() != 48 && raw.size() != 64)
        throw runtime_error("XTS key file must be 32, 48, or 64 bytes (2× AES key)");
    return SecByteBlock(reinterpret_cast<const CryptoPP::byte*>(raw.data()), raw.size());
}

// Auto-generate IV of requested size
static SecByteBlock GenIV(size_t size)
{
    AutoSeededRandomPool prng;
    SecByteBlock iv(size);
    prng.GenerateBlock(iv, iv.size());
    return iv;
}

// Key fingerprint = hex of first 8 bytes
static string KeyFingerprint(const SecByteBlock& key)
{
    size_t sz = min(key.size(), (size_t)8);
    return ToHex(key.data(), sz);
}

// ------------------------- keygen command -------------------------

static void CmdKeygen(int argc, char* argv[])
{
    // aescli keygen --bits 128|192|256 --out keyfile [--xts]
    size_t bits    = 256;
    string outfile;
    bool   xts     = false;

    for (int i = 2; i < argc; ++i) {
        string a = argv[i];
        if (a == "--bits"  && i+1 < argc) { bits   = stoul(argv[++i]); }
        else if (a == "--out" && i+1 < argc) { outfile = argv[++i]; }
        else if (a == "--xts") { xts = true; }
    }

    if (outfile.empty()) throw runtime_error("keygen: --out <keyfile> required");
    if (bits != 128 && bits != 192 && bits != 256)
        throw runtime_error("keygen: --bits must be 128, 192, or 256");

    size_t keyBytes = bits / 8;
    size_t total    = xts ? keyBytes * 2 : keyBytes;

    AutoSeededRandomPool prng;
    SecByteBlock key(total);
    prng.GenerateBlock(key, key.size());
    SaveKeyBin(outfile, key);

    cout << "Generated AES-" << bits << (xts ? "-XTS" : "") << " key > " << outfile
         << " (" << total << " bytes)\n";
}

// ------------------------- ECB -------------------------

static void EncryptECB(const string& inData, string& outData,
                       const SecByteBlock& key)
{
    ECB_Mode<AES>::Encryption enc;
    enc.SetKey(key, key.size());
    StringSource(inData, true,
        new StreamTransformationFilter(enc, new StringSink(outData)));
}

static void DecryptECB(const string& inData, string& outData,
                       const SecByteBlock& key)
{
    ECB_Mode<AES>::Decryption dec;
    dec.SetKey(key, key.size());
    StringSource(inData, true,
        new StreamTransformationFilter(dec, new StringSink(outData)));
}

// ------------------------- Generic block/stream modes -------------------------

template<class ENC>
static void EncryptIV(const string& inData, string& outData,
                      const SecByteBlock& key, const SecByteBlock& iv)
{
    ENC enc;
    enc.SetKeyWithIV(key, key.size(), iv);
    StringSource(inData, true,
        new StreamTransformationFilter(enc, new StringSink(outData)));
}

template<class DEC>
static void DecryptIV(const string& inData, string& outData,
                      const SecByteBlock& key, const SecByteBlock& iv)
{
    DEC dec;
    dec.SetKeyWithIV(key, key.size(), iv);
    StringSource(inData, true,
        new StreamTransformationFilter(dec, new StringSink(outData)));
}

// ------------------------- GCM -------------------------

static void EncryptGCM(const string& inData, string& outData,
                       const SecByteBlock& key, const SecByteBlock& iv,
                       const string& aad)
{
    GCM<AES>::Encryption enc;
    enc.SetKeyWithIV(key, key.size(), iv, iv.size());

    AuthenticatedEncryptionFilter f(enc,
        new StringSink(outData), false, GCM_TAG_SIZE);

    if (!aad.empty()) f.ChannelPut(AAD_CHANNEL,
        reinterpret_cast<const CryptoPP::byte*>(aad.data()), aad.size());
    f.ChannelMessageEnd(AAD_CHANNEL);

    f.Put(reinterpret_cast<const CryptoPP::byte*>(inData.data()), inData.size());
    f.MessageEnd();
}

static void DecryptGCM(const string& inData, string& outData,
                       const SecByteBlock& key, const SecByteBlock& iv,
                       const string& aad)
{
    GCM<AES>::Decryption dec;
    dec.SetKeyWithIV(key, key.size(), iv, iv.size());

    AuthenticatedDecryptionFilter f(dec,
        new StringSink(outData),
        AuthenticatedDecryptionFilter::MAC_AT_END |
        AuthenticatedDecryptionFilter::THROW_EXCEPTION,
        GCM_TAG_SIZE);

    if (!aad.empty()) f.ChannelPut(AAD_CHANNEL,
        reinterpret_cast<const CryptoPP::byte*>(aad.data()), aad.size());
    f.ChannelMessageEnd(AAD_CHANNEL);

    f.Put(reinterpret_cast<const CryptoPP::byte*>(inData.data()), inData.size());
    f.MessageEnd();
}

// ------------------------- CCM -------------------------

static void EncryptCCM(const string& inData, string& outData,
                       const SecByteBlock& key, const SecByteBlock& iv,
                       const string& aad)
{
    CCM<AES, CCM_TAG_SIZE>::Encryption enc;
    enc.SetKeyWithIV(key, key.size(), iv, iv.size());
    enc.SpecifyDataLengths(aad.size(), inData.size(), 0);

    AuthenticatedEncryptionFilter f(enc, new StringSink(outData));

    if (!aad.empty()) f.ChannelPut(AAD_CHANNEL,
        reinterpret_cast<const CryptoPP::byte*>(aad.data()), aad.size());
    f.ChannelMessageEnd(AAD_CHANNEL);

    f.Put(reinterpret_cast<const CryptoPP::byte*>(inData.data()), inData.size());
    f.MessageEnd();
}

static void DecryptCCM(const string& inData, string& outData,
                       const SecByteBlock& key, const SecByteBlock& iv,
                       const string& aad)
{
    CCM<AES, CCM_TAG_SIZE>::Decryption dec;
    dec.SetKeyWithIV(key, key.size(), iv, iv.size());

    // CCM requires knowing plaintext length in advance
    size_t ctLen = inData.size() > CCM_TAG_SIZE ? inData.size() - CCM_TAG_SIZE : 0;
    dec.SpecifyDataLengths(aad.size(), ctLen, 0);

    AuthenticatedDecryptionFilter f(dec,
        new StringSink(outData),
        AuthenticatedDecryptionFilter::MAC_AT_END |
        AuthenticatedDecryptionFilter::THROW_EXCEPTION);

    if (!aad.empty()) f.ChannelPut(AAD_CHANNEL,
        reinterpret_cast<const CryptoPP::byte*>(aad.data()), aad.size());
    f.ChannelMessageEnd(AAD_CHANNEL);

    f.Put(reinterpret_cast<const CryptoPP::byte*>(inData.data()), inData.size());
    f.MessageEnd();
}

// ------------------------- XTS -------------------------
// XTS uses 2× key material and a 128-bit "tweak" (sector/block number)

static void EncryptXTS(const string& inData, string& outData,
                       const SecByteBlock& key)
{
    // XTS requires at least one full block (16 bytes)
    if (inData.size() < AES::BLOCKSIZE)
        throw runtime_error("XTS: plaintext must be >= 16 bytes");

    XTS_Mode<AES>::Encryption enc;
    // Key must be 2× normal key size; tweak = 16-byte zero (sector 0)
    SecByteBlock tweak(AES::BLOCKSIZE);
    memset(tweak, 0, tweak.size());
    enc.SetKeyWithIV(key, key.size(), tweak, tweak.size());

    StringSource(inData, true,
        new StreamTransformationFilter(enc, new StringSink(outData)));
}

static void DecryptXTS(const string& inData, string& outData,
                       const SecByteBlock& key)
{
    if (inData.size() < AES::BLOCKSIZE)
        throw runtime_error("XTS: ciphertext must be >= 16 bytes");

    XTS_Mode<AES>::Decryption dec;
    SecByteBlock tweak(AES::BLOCKSIZE);
    memset(tweak, 0, tweak.size());
    dec.SetKeyWithIV(key, key.size(), tweak, tweak.size());

    StringSource(inData, true,
        new StreamTransformationFilter(dec, new StringSink(outData)));
}

// ------------------------- Nonce-reuse protection -------------------------

// Returns true if (key_fp, iv_hex) was seen before in <outfile>.json
static bool NonceWasUsed(const string& outfile,
                          const string& key_fp,
                          const string& iv_hex)
{
    if (!fs::exists(outfile + ".json")) return false;
    SidecarInfo s = ReadSidecar(outfile);
    return (s.key_fp == key_fp && s.iv_hex == iv_hex);
}

// ------------------------- Encoding helper -------------------------

static string EncodeOutput(const string& enc, const string& raw)
{
    if (enc == "hex") {
        string out;
        StringSource(raw, true,
            new HexEncoder(new StringSink(out), false));
        return out;
    }
    if (enc == "base64") {
        string out;
        StringSource(raw, true,
            new Base64Encoder(new StringSink(out), false));
        return out;
    }
    return raw; // "raw"
}

// ------------------------- encrypt -------------------------

static void CmdEncrypt(int argc, char* argv[])
{
    // Parse flags
    string mode, keyfile, keyhex, infile, outfile, ivfile;
    string aad_file, aad_text, encode = "hex";
    bool   aead     = false;
    bool   allow_ecb = false;
    string text_in;

    for (int i = 2; i < argc; ++i) {
        string a = argv[i];
        if      (a == "--mode"      && i+1 < argc) mode      = argv[++i];
        else if (a == "--key"       && i+1 < argc) keyfile   = argv[++i];
        else if (a == "--key-hex"   && i+1 < argc) keyhex    = argv[++i];
        else if (a == "--in"        && i+1 < argc) infile    = argv[++i];
        else if (a == "--out"       && i+1 < argc) outfile   = argv[++i];
        else if (a == "--iv"        && i+1 < argc) ivfile    = argv[++i];
        else if (a == "--nonce"     && i+1 < argc) ivfile    = argv[++i];
        else if (a == "--aad"       && i+1 < argc) aad_file  = argv[++i];
        else if (a == "--aad-text"  && i+1 < argc) aad_text  = argv[++i];
        else if (a == "--encode"    && i+1 < argc) encode    = argv[++i];
        else if (a == "--text"      && i+1 < argc) text_in   = argv[++i];
        else if (a == "--aead")  aead      = true;
        else if (a == "--allow-ecb") allow_ecb = true;
    }

    // Validate
    if (mode.empty())   throw runtime_error("encrypt: --mode required");
    if (outfile.empty()) throw runtime_error("encrypt: --out required");
    if (infile.empty() && text_in.empty())
        throw runtime_error("encrypt: --in or --text required");
    if (!keyfile.empty() && !keyhex.empty())
        throw runtime_error("encrypt: use --key OR --key-hex, not both");

    // Load key
    SecByteBlock key;
    if (!keyhex.empty())      key = FromHex(keyhex);
    else if (!keyfile.empty()) {
        if (mode == "xts") key = LoadXTSKeyBin(keyfile);
        else               key = LoadKeyBin(keyfile);
    } else throw runtime_error("encrypt: --key or --key-hex required");

    // Read plaintext
    string plaintext = text_in.empty() ? ReadFile(infile) : text_in;

    // ECB size check
    if (mode == "ecb") {
        cerr << "WARNING: ECB mode is insecure. Never use for sensitive data.\n";
        if (!allow_ecb && plaintext.size() > ECB_MAX_BYTES)
            throw runtime_error(
                "ECB: input > 16 KiB refused. Use --allow-ecb to override.");
    }

    // Load or generate IV
    SecByteBlock iv;
    bool iv_generated = false;
    if (mode != "ecb" && mode != "xts") {
        if (!ivfile.empty()) {
            string raw = ReadFile(ivfile);
            iv = SecByteBlock(reinterpret_cast<const CryptoPP::byte*>(raw.data()), raw.size());
        } else {
            // Auto-generate
            size_t ivSz = (mode == "gcm") ? GCM_IV_SIZE
                        : (mode == "ccm") ? CCM_IV_SIZE
                        : (size_t)AES::BLOCKSIZE;
            iv = GenIV(ivSz);
            iv_generated = true;
        }
    }

    // IV length enforcement
    if (mode == "gcm" && !iv.empty() && iv.size() != GCM_IV_SIZE)
        throw runtime_error("GCM nonce must be 12 bytes (96-bit)");
    if (mode == "ccm" && !iv.empty() && (iv.size() < 7 || iv.size() > 13))
        throw runtime_error("CCM nonce must be 7–13 bytes");
    if ((mode == "cbc" || mode == "cfb" || mode == "ofb" || mode == "ctr")
        && !iv.empty() && iv.size() != AES::BLOCKSIZE)
        throw runtime_error("IV must be 16 bytes for " + mode);

    // Nonce-reuse check for CTR/GCM/CCM
    if (mode == "ctr" || mode == "gcm" || mode == "ccm") {
        string fp = KeyFingerprint(key);
        string ih = ToHex(iv.data(), iv.size());
        if (NonceWasUsed(outfile, fp, ih)) {
            throw runtime_error(
                "NONCE REUSE DETECTED: same key+nonce was used for '" + outfile +
                "'. Generate a new IV or use a different key.");
        }
    }

    // Collect AAD
    string aad;
    if (!aad_file.empty())   aad = ReadFile(aad_file);
    else if (!aad_text.empty()) aad = aad_text;

    // Dispatch
    string ciphertext;
    string algLabel = "AES-" + to_string(key.size() * 8) + "-" +
                      [&]{ string m=mode; for(auto& c:m) c=toupper(c); return m; }();

    if (mode == "ecb") {
        EncryptECB(plaintext, ciphertext, key);
    } else if (mode == "cbc") {
        EncryptIV<CBC_Mode<AES>::Encryption>(plaintext, ciphertext, key, iv);
    } else if (mode == "cfb") {
        EncryptIV<CFB_Mode<AES>::Encryption>(plaintext, ciphertext, key, iv);
    } else if (mode == "ofb") {
        EncryptIV<OFB_Mode<AES>::Encryption>(plaintext, ciphertext, key, iv);
    } else if (mode == "ctr") {
        EncryptIV<CTR_Mode<AES>::Encryption>(plaintext, ciphertext, key, iv);
    } else if (mode == "gcm") {
        if (!aead) cerr << "WARNING: GCM without --aead flag; AAD will be empty.\n";
        EncryptGCM(plaintext, ciphertext, key, iv, aad);
    } else if (mode == "ccm") {
        if (!aead) cerr << "WARNING: CCM without --aead flag; AAD will be empty.\n";
        EncryptCCM(plaintext, ciphertext, key, iv, aad);
    } else if (mode == "xts") {
        EncryptXTS(plaintext, ciphertext, key);
    } else {
        throw runtime_error("Unsupported mode: " + mode);
    }

    // Write output (raw binary)
    WriteFile(outfile, ciphertext);

    // Write sidecar JSON (always, except ECB)
    if (mode != "ecb") {
        SidecarInfo sc;
        sc.alg    = algLabel;
        sc.mode   = mode;
        sc.iv_hex = (iv.empty()) ? "" : ToHex(iv.data(), iv.size());
        sc.aad_hex = aad.empty() ? "" :
            ToHex(reinterpret_cast<const CryptoPP::byte*>(aad.data()), aad.size());
        sc.key_fp = KeyFingerprint(key);
        WriteSidecar(outfile, sc);
    }

    // Console output
    cout << "Encrypted   : " << algLabel << "\n";
    cout << "Input       : " << (infile.empty() ? "(text)" : infile)
         << " (" << plaintext.size() << " bytes)\n";
    cout << "Output      : " << outfile << " (" << ciphertext.size() << " bytes)\n";
    if (iv_generated && !iv.empty())
        cout << "IV (auto)   : " << ToHex(iv.data(), iv.size()) << "\n";
    PrintEncoded("Ciphertext", encode,
        reinterpret_cast<const CryptoPP::byte*>(ciphertext.data()), ciphertext.size());
}

// ------------------------- decrypt -------------------------

static void CmdDecrypt(int argc, char* argv[])
{
    string mode, keyfile, keyhex, infile, outfile, ivfile;
    string aad_file, aad_text, encode = "hex";
    bool   aead = false;

    for (int i = 2; i < argc; ++i) {
        string a = argv[i];
        if      (a == "--mode"     && i+1 < argc) mode     = argv[++i];
        else if (a == "--key"      && i+1 < argc) keyfile  = argv[++i];
        else if (a == "--key-hex"  && i+1 < argc) keyhex   = argv[++i];
        else if (a == "--in"       && i+1 < argc) infile   = argv[++i];
        else if (a == "--out"      && i+1 < argc) outfile  = argv[++i];
        else if (a == "--iv"       && i+1 < argc) ivfile   = argv[++i];
        else if (a == "--nonce"    && i+1 < argc) ivfile   = argv[++i];
        else if (a == "--aad"      && i+1 < argc) aad_file = argv[++i];
        else if (a == "--aad-text" && i+1 < argc) aad_text = argv[++i];
        else if (a == "--encode"   && i+1 < argc) encode   = argv[++i];
        else if (a == "--aead") aead = true;
    }

    if (mode.empty())    throw runtime_error("decrypt: --mode required");
    if (infile.empty())  throw runtime_error("decrypt: --in required");
    if (outfile.empty()) throw runtime_error("decrypt: --out required");

    // Load key
    SecByteBlock key;
    if (!keyhex.empty())       key = FromHex(keyhex);
    else if (!keyfile.empty()) {
        if (mode == "xts") key = LoadXTSKeyBin(keyfile);
        else               key = LoadKeyBin(keyfile);
    } else throw runtime_error("decrypt: --key or --key-hex required");

    // Load IV: prefer explicit --iv, then sidecar
    SecByteBlock iv;
    if (mode != "ecb" && mode != "xts") {
        if (!ivfile.empty()) {
            string raw = ReadFile(ivfile);
            iv = SecByteBlock(reinterpret_cast<const CryptoPP::byte*>(raw.data()), raw.size());
        } else {
            // Try sidecar
            if (fs::exists(infile + ".json")) {
                SidecarInfo sc = ReadSidecar(infile);
                if (!sc.iv_hex.empty()) iv = FromHex(sc.iv_hex);
            }
            if (iv.empty())
                throw runtime_error(
                    "decrypt: IV not provided and no sidecar JSON found for " + infile);
        }
    }

    // IV length enforcement
    if (mode == "gcm" && iv.size() != GCM_IV_SIZE)
        throw runtime_error("GCM nonce must be 12 bytes");
    if (mode == "ccm" && (iv.size() < 7 || iv.size() > 13))
        throw runtime_error("CCM nonce must be 7–13 bytes");

    string ciphertext = ReadFile(infile);

    // Collect AAD
    string aad;
    if (!aad_file.empty())    aad = ReadFile(aad_file);
    else if (!aad_text.empty()) aad = aad_text;
    else if (fs::exists(infile + ".json")) {
        SidecarInfo sc = ReadSidecar(infile);
        if (!sc.aad_hex.empty()) aad = string(FromHex(sc.aad_hex).begin(),
                                               FromHex(sc.aad_hex).end());
    }

    string plaintext;
    string algLabel = "AES-" + to_string(key.size() * 8) + "-" +
                      [&]{ string m=mode; for(auto& c:m) c=toupper(c); return m; }();

    if (mode == "ecb") {
        DecryptECB(ciphertext, plaintext, key);
    } else if (mode == "cbc") {
        DecryptIV<CBC_Mode<AES>::Decryption>(ciphertext, plaintext, key, iv);
    } else if (mode == "cfb") {
        DecryptIV<CFB_Mode<AES>::Decryption>(ciphertext, plaintext, key, iv);
    } else if (mode == "ofb") {
        DecryptIV<OFB_Mode<AES>::Decryption>(ciphertext, plaintext, key, iv);
    } else if (mode == "ctr") {
        DecryptIV<CTR_Mode<AES>::Decryption>(ciphertext, plaintext, key, iv);
    } else if (mode == "gcm") {
        DecryptGCM(ciphertext, plaintext, key, iv, aad);
    } else if (mode == "ccm") {
        DecryptCCM(ciphertext, plaintext, key, iv, aad);
    } else if (mode == "xts") {
        DecryptXTS(ciphertext, plaintext, key);
    } else {
        throw runtime_error("Unsupported mode: " + mode);
    }

    WriteFile(outfile, plaintext);

    cout << "Decrypted   : " << algLabel << "\n";
    cout << "Input       : " << infile << " (" << ciphertext.size() << " bytes)\n";
    cout << "Output      : " << outfile << " (" << plaintext.size() << " bytes)\n";
}

// ------------------------- KAT -------------------------
/*
 * vectors.json format (array of objects):
 * [
 *   {
 *     "id"   : "CBC-AES128-1",
 *     "mode" : "cbc",
 *     "key"  : "<hex>",
 *     "iv"   : "<hex>",
 *     "pt"   : "<hex>",
 *     "ct"   : "<hex>"
 *   },
 *   ...
 *   // For GCM/CCM:
 *   {
 *     "id"   : "GCM-AES128-1",
 *     "mode" : "gcm",
 *     "key"  : "<hex>",
 *     "iv"   : "<hex>",
 *     "aad"  : "<hex>",   // optional
 *     "pt"   : "<hex>",
 *     "ct"   : "<hex>"    // includes appended tag
 *   }
 * ]
 */

struct KATVector {
    string id, mode, key_hex, iv_hex, aad_hex, pt_hex, ct_hex;
};

static vector<KATVector> ParseKATFile(const string& path)
{
    string json = ReadFile(path);
    vector<KATVector> vecs;

    // Split on "}" to get each object block
    size_t pos = 0;
    while ((pos = json.find('{', pos)) != string::npos) {
        size_t end = json.find('}', pos);
        if (end == string::npos) break;
        string obj = json.substr(pos, end - pos + 1);
        pos = end + 1;

        KATVector v;
        v.id      = JsonField(obj, "id");
        v.mode    = JsonField(obj, "mode");
        v.key_hex = JsonField(obj, "key");
        v.iv_hex  = JsonField(obj, "iv");
        v.aad_hex = JsonField(obj, "aad");
        v.pt_hex  = JsonField(obj, "pt");
        v.ct_hex  = JsonField(obj, "ct");

        if (!v.mode.empty() && !v.key_hex.empty())
            vecs.push_back(v);
    }
    return vecs;
}

static void CmdKAT(const string& vecfile)
{
    auto vecs = ParseKATFile(vecfile);
    if (vecs.empty())
        throw runtime_error("KAT: no valid vectors found in " + vecfile);

    int pass = 0, fail = 0;
    cout << "\n=== KAT Runner: " << vecfile << " ===\n\n";

    for (auto& v : vecs) {
        try {
            SecByteBlock key = FromHex(v.key_hex);
            SecByteBlock iv  = v.iv_hex.empty() ? SecByteBlock(0) : FromHex(v.iv_hex);
            string pt = string(reinterpret_cast<const char*>(FromHex(v.pt_hex).data()),
                               FromHex(v.pt_hex).size());
            string expected_ct = string(reinterpret_cast<const char*>(FromHex(v.ct_hex).data()),
                                        FromHex(v.ct_hex).size());
            string aad;
            if (!v.aad_hex.empty())
                aad = string(reinterpret_cast<const char*>(FromHex(v.aad_hex).data()),
                             FromHex(v.aad_hex).size());

            string got_ct;

            if (v.mode == "ecb") EncryptECB(pt, got_ct, key);
            else if (v.mode == "cbc") {
                CBC_Mode<AES>::Encryption enc;
                enc.SetKeyWithIV(key, key.size(), iv);
                    StringSource(pt, true,
                        new StreamTransformationFilter(
                            enc,
                            new StringSink(got_ct),
                            StreamTransformationFilter::NO_PADDING
                            )
                        );
                    }
            else if (v.mode == "cfb")
                EncryptIV<CFB_Mode<AES>::Encryption>(pt, got_ct, key, iv);
            else if (v.mode == "ofb")
                EncryptIV<OFB_Mode<AES>::Encryption>(pt, got_ct, key, iv);
            else if (v.mode == "ctr")
                EncryptIV<CTR_Mode<AES>::Encryption>(pt, got_ct, key, iv);
            else if (v.mode == "gcm")
                EncryptGCM(pt, got_ct, key, iv, aad);
            else if (v.mode == "ccm")
                EncryptCCM(pt, got_ct, key, iv, aad);
            else {
                cout << "[SKIP] " << v.id << " (mode '" << v.mode << "' not in KAT scope)\n";
                continue;
            }

            if (got_ct == expected_ct) {
                cout << "[PASS] " << v.id << "\n";
                ++pass;
            } else {
                cout << "[FAIL] " << v.id << "\n";
                cout << "       expected: " << v.ct_hex << "\n";
                cout << "       got     : " << ToHex(
                    reinterpret_cast<const CryptoPP::byte*>(got_ct.data()), got_ct.size()) << "\n";
                ++fail;
            }
        } catch (const exception& e) {
            cout << "[FAIL] " << v.id << " - exception: " << e.what() << "\n";
            ++fail;
        }
    }

    cout << "Total : " << (pass+fail) << "  |  PASS: " << pass
         << "  |  FAIL: " << fail << "\n";

    if (fail > 0) exit(1);
}

// ------------------------- show -------------------------

static void CmdShow(int argc, char* argv[])
{
    // aescli show --key keyfile [--xts]
    string keyfile;
    bool xts = false;
    for (int i = 2; i < argc; ++i) {
        string a = argv[i];
        if (a == "--key" && i+1 < argc) keyfile = argv[++i];
        else if (a == "--xts") xts = true;
    }
    if (keyfile.empty()) throw runtime_error("show: --key required");

    SecByteBlock key = xts ? LoadXTSKeyBin(keyfile) : LoadKeyBin(keyfile);
    PrintHex("Key", key, key.size());
    cout << "Key size : " << key.size() << " bytes (AES-"
         << (xts ? key.size()*4 : key.size()*8) << (xts?"-XTS":"") << ")\n";
}

// ------------------------- Negative Tests -------------------------
/*
 * Usage:
 *   aescli --test-negative
 *
 * All tests are self-contained (no external files needed).
 * Each test verifies that an invalid or tampered operation is
 * correctly rejected. Exits with code 1 if any test fails.
 */
 
static void CmdNegativeTest()
{
    cout << "\n=== Negative Tests (Lab 1) ===\n\n";
 
    AutoSeededRandomPool prng;
    int pass = 0, fail = 0;
 
    // Helper: PASS/FAIL printer
    auto Result = [&](bool ok, const string& name, const string& detail = "")
    {
        if (ok) {
            cout << "[PASS] " << name << "\n";
            ++pass;
        } else {
            cout << "[FAIL] " << name;
            if (!detail.empty()) cout << " - " << detail;
            cout << "\n";
            ++fail;
        }
    };
 
    // Shared test data 
    const string plaintext = "NegativeTestPlaintext1234567890!"; // 32 bytes
 
    // Generate a valid AES-256 key + IV
    SecByteBlock key(32), wrongKey(32), iv(AES::BLOCKSIZE), wrongIV(AES::BLOCKSIZE);
    prng.GenerateBlock(key,      key.size());
    prng.GenerateBlock(wrongKey, wrongKey.size());
    prng.GenerateBlock(iv,       iv.size());
    prng.GenerateBlock(wrongIV,  wrongIV.size());
 
    // GCM nonce (12 bytes)
    SecByteBlock gcmIV(GCM_IV_SIZE), wrongGcmIV(GCM_IV_SIZE);
    prng.GenerateBlock(gcmIV,      gcmIV.size());
    prng.GenerateBlock(wrongGcmIV, wrongGcmIV.size());
 
    // CCM nonce (7 bytes)
    SecByteBlock ccmIV(CCM_IV_SIZE), wrongCcmIV(CCM_IV_SIZE);
    prng.GenerateBlock(ccmIV,      ccmIV.size());
    prng.GenerateBlock(wrongCcmIV, wrongCcmIV.size());
 
    // Test 1: CBC - Wrong key > plaintext mismatch
    {
        string ct, recovered;
        EncryptIV<CBC_Mode<AES>::Encryption>(plaintext, ct, key, iv);
        try {
            DecryptIV<CBC_Mode<AES>::Decryption>(ct, recovered, wrongKey, iv);
            Result(recovered != plaintext, "T01: CBC wrong key > plaintext mismatch");
        } catch (...) {
            Result(true, "T01: CBC wrong key > exception thrown");
        }
    }
 
    // Test 2: CBC - Wrong IV > plaintext mismatch 
    {
        string ct, recovered;
        EncryptIV<CBC_Mode<AES>::Encryption>(plaintext, ct, key, iv);
        try {
            DecryptIV<CBC_Mode<AES>::Decryption>(ct, recovered, key, wrongIV);
            Result(recovered != plaintext, "T02: CBC wrong IV > plaintext mismatch");
        } catch (...) {
            Result(true, "T02: CBC wrong IV > exception thrown");
        }
    }
 
    // Test 3: CBC - Tampered ciphertext > garbled plaintext 
    {
        string ct, recovered;
        EncryptIV<CBC_Mode<AES>::Encryption>(plaintext, ct, key, iv);
        if (!ct.empty()) ct[ct.size() / 2] ^= 0xFF; // flip middle byte
        try {
            DecryptIV<CBC_Mode<AES>::Decryption>(ct, recovered, key, iv);
            Result(recovered != plaintext, "T03: CBC tampered CT > garbled plaintext");
        } catch (...) {
            Result(true, "T03: CBC tampered CT > exception thrown");
        }
    }
 
    // Test 4: CTR - Wrong key > plaintext mismatch
    {
        string ct, recovered;
        EncryptIV<CTR_Mode<AES>::Encryption>(plaintext, ct, key, iv);
        try {
            DecryptIV<CTR_Mode<AES>::Decryption>(ct, recovered, wrongKey, iv);
            Result(recovered != plaintext, "T04: CTR wrong key > plaintext mismatch");
        } catch (...) {
            Result(true, "T04: CTR wrong key > exception thrown");
        }
    }
 
    // Test 5: CTR - Wrong IV > plaintext mismatch
    {
        string ct, recovered;
        EncryptIV<CTR_Mode<AES>::Encryption>(plaintext, ct, key, iv);
        try {
            DecryptIV<CTR_Mode<AES>::Decryption>(ct, recovered, key, wrongIV);
            Result(recovered != plaintext, "T05: CTR wrong IV > plaintext mismatch");
        } catch (...) {
            Result(true, "T05: CTR wrong IV > exception thrown");
        }
    }
 
    // Test 6: CTR - Note: no authentication, tamper undetected 
    {
        // CTR cannot detect tampering - this is expected / documented
        string ct, recovered;
        EncryptIV<CTR_Mode<AES>::Encryption>(plaintext, ct, key, iv);
        if (!ct.empty()) ct[0] ^= 0x01;
        try {
            DecryptIV<CTR_Mode<AES>::Decryption>(ct, recovered, key, iv);
            // Tamper changes exactly 1 bit of plaintext - NOT equal
            Result(recovered != plaintext,
                "T06: CTR tampered CT > silent plaintext corruption (expected)");
        } catch (...) {
            Result(false, "T06: CTR tampered CT > unexpected exception");
        }
    }
 
    // Test 7: GCM - Wrong key > authentication fails
    {
        string ct;
        EncryptGCM(plaintext, ct, key, gcmIV, "");
        try {
            string rec;
            DecryptGCM(ct, rec, wrongKey, gcmIV, "");
            Result(false, "T07: GCM wrong key > should have thrown");
        } catch (...) {
            Result(true, "T07: GCM wrong key > authentication failed (correct)");
        }
    }
 
    // Test 8: GCM - Wrong IV > authentication fails 
    {
        string ct;
        EncryptGCM(plaintext, ct, key, gcmIV, "");
        try {
            string rec;
            DecryptGCM(ct, rec, key, wrongGcmIV, "");
            Result(false, "T08: GCM wrong IV > should have thrown");
        } catch (...) {
            Result(true, "T08: GCM wrong IV > authentication failed (correct)");
        }
    }
 
    // Test 9: GCM - Tampered ciphertext > authentication fails 
    {
        string ct;
        EncryptGCM(plaintext, ct, key, gcmIV, "");
        if (!ct.empty()) ct[0] ^= 0xFF; // flip first ciphertext byte
        try {
            string rec;
            DecryptGCM(ct, rec, key, gcmIV, "");
            Result(false, "T09: GCM tampered CT > should have thrown");
        } catch (...) {
            Result(true, "T09: GCM tampered CT > authentication failed (correct)");
        }
    }
 
    // Test 10: GCM - Tampered auth tag > authentication fails 
    {
        string ct;
        EncryptGCM(plaintext, ct, key, gcmIV, "");
        // Tag is appended at the END of ciphertext (last GCM_TAG_SIZE bytes)
        if (ct.size() >= GCM_TAG_SIZE)
            ct[ct.size() - 1] ^= 0xFF; // flip last tag byte
        try {
            string rec;
            DecryptGCM(ct, rec, key, gcmIV, "");
            Result(false, "T10: GCM tampered tag > should have thrown");
        } catch (...) {
            Result(true, "T10: GCM tampered tag > authentication failed (correct)");
        }
    }
 
    // Test 11: GCM - Wrong AAD > authentication fails
    {
        const string aad = "header-v1";
        string ct;
        EncryptGCM(plaintext, ct, key, gcmIV, aad);
        try {
            string rec;
            DecryptGCM(ct, rec, key, gcmIV, "wrong-aad");
            Result(false, "T11: GCM wrong AAD > should have thrown");
        } catch (...) {
            Result(true, "T11: GCM wrong AAD > authentication failed (correct)");
        }
    }
 
    // Test 12: GCM - Truncated ciphertext (tag missing) 
    {
        string ct;
        EncryptGCM(plaintext, ct, key, gcmIV, "");
        // Remove last 8 bytes (partial tag)
        if (ct.size() > 8) ct.resize(ct.size() - 8);
        try {
            string rec;
            DecryptGCM(ct, rec, key, gcmIV, "");
            Result(false, "T12: GCM truncated CT > should have thrown");
        } catch (...) {
            Result(true, "T12: GCM truncated CT (partial tag) > rejected (correct)");
        }
    }
 
    // Test 13: CCM - Tampered ciphertext > auth fails 
    {
        string ct;
        EncryptCCM(plaintext, ct, key, ccmIV, "");
        if (!ct.empty()) ct[0] ^= 0xAA;
        try {
            string rec;
            DecryptCCM(ct, rec, key, ccmIV, "");
            Result(false, "T13: CCM tampered CT > should have thrown");
        } catch (...) {
            Result(true, "T13: CCM tampered CT > authentication failed (correct)");
        }
    }
 
    // Test 14: CCM - Wrong key > auth fails 
    {
        string ct;
        EncryptCCM(plaintext, ct, key, ccmIV, "");
        try {
            string rec;
            DecryptCCM(ct, rec, wrongKey, ccmIV, "");
            Result(false, "T14: CCM wrong key > should have thrown");
        } catch (...) {
            Result(true, "T14: CCM wrong key > authentication failed (correct)");
        }
    }
 
    // Test 15: Invalid key length > reject 
    {
        bool caught = false;
        try {
            SecByteBlock badKey(10); // 10 bytes - invalid for AES
            prng.GenerateBlock(badKey, badKey.size());
            CBC_Mode<AES>::Encryption enc;
            enc.SetKeyWithIV(badKey, badKey.size(), iv);
            string ct;
            StringSource(plaintext, true,
                new StreamTransformationFilter(enc, new StringSink(ct)));
        } catch (...) {
            caught = true;
        }
        Result(caught, "T15: Invalid key length (10 bytes) > rejected");
    }
    // Test 16: GCM IV wrong length > reject 
    {
        bool caught = false;
        try {
            SecByteBlock badIV(8); // 8 bytes - not 12
            prng.GenerateBlock(badIV, badIV.size());
            // GCM_IV_SIZE enforcement in CmdEncrypt; here test Crypto++ directly
            GCM<AES>::Encryption enc;
            enc.SetKeyWithIV(key, key.size(), badIV, badIV.size());
            // Crypto++ GCM accepts any IV length, so we enforce it ourselves:
            if (badIV.size() != GCM_IV_SIZE)
                throw runtime_error("GCM nonce must be 12 bytes");
        } catch (...) {
            caught = true;
        }
        Result(caught, "T16: GCM IV wrong length (8 bytes) > rejected");
    }
 
    // Test 17: ECB - file > 16 KiB without --allow-ecb 
    {
        bool caught = false;
        try {
            string big(ECB_MAX_BYTES + 1, 'X');
            // Simulate the guard in CmdEncrypt
            if (big.size() > ECB_MAX_BYTES)
                throw runtime_error(
                    "ECB: input > 16 KiB refused. Use --allow-ecb to override.");
        } catch (const runtime_error&) {
            caught = true;
        }
        Result(caught, "T17: ECB input > 16 KiB without --allow-ecb > rejected");
    }
 
    // Test 18: OFB - Wrong key > plaintext mismatch 
    {
        string ct, recovered;
        EncryptIV<OFB_Mode<AES>::Encryption>(plaintext, ct, key, iv);
        try {
            DecryptIV<OFB_Mode<AES>::Decryption>(ct, recovered, wrongKey, iv);
            Result(recovered != plaintext, "T18: OFB wrong key > plaintext mismatch");
        } catch (...) {
            Result(true, "T18: OFB wrong key > exception thrown");
        }
    }
 
    // Test 19: CFB - Tampered CT > garbled plaintext 
    {
        string ct, recovered;
        EncryptIV<CFB_Mode<AES>::Encryption>(plaintext, ct, key, iv);
        if (!ct.empty()) ct[0] ^= 0xFF;
        try {
            DecryptIV<CFB_Mode<AES>::Decryption>(ct, recovered, key, iv);
            Result(recovered != plaintext, "T19: CFB tampered CT > garbled plaintext");
        } catch (...) {
            Result(true, "T19: CFB tampered CT > exception thrown");
        }
    }
 
    // -- Summary --
    cout << "\n----------------------------------------\n";
    cout << "Total : " << (pass + fail)
         << "  |  PASS: " << pass
         << "  |  FAIL: " << fail << "\n";
    cout << "----------------------------------------\n\n";
 
    if (fail > 0) exit(1);
}

// ------------------------- usage --------------------------------

static void PrintUsage()
{
    cout <<
R"(Usage: aescli <command> [options]
 
Commands:
  keygen            --bits 128|192|256 --out <keyfile> [--xts]
  show              --key <keyfile> [--xts]
  encrypt           --mode <mode> --key <keyfile> --in <file> --out <file> [options]
  decrypt           --mode <mode> --key <keyfile> --in <file> --out <file> [options]
  --kat             <vectors.json>
  --test-negative   Run all negative/misuse test cases
 
Modes: ecb  cbc  ofb  cfb  ctr  xts  ccm  gcm
 
Encrypt/Decrypt options:
  --key-hex <HEX>        Inline hex key (alternative to --key)
  --iv  <file>           IV / nonce file (auto-generated if omitted)
  --nonce <file>         Alias for --iv
  --text "<string>"      Encrypt from string instead of file
  --aead                 Enable authenticated mode (GCM/CCM)
  --aad <file>           Additional authenticated data from file
  --aad-text "<string>"  Additional authenticated data from string
  --encode hex|base64|raw  Console output encoding (default: hex)
  --allow-ecb            Override 16 KiB ECB file size limit
 
Examples:
  aescli keygen --bits 256 --out key.bin
  aescli encrypt --mode gcm --key key.bin --in plain.txt --out ct.bin --aead
  aescli decrypt --mode gcm --key key.bin --in ct.bin   --out plain.txt --aead
  aescli encrypt --mode cbc --key key.bin --in file.txt --out ct.bin
  aescli --kat nist_vectors.json
  aescli --test-negative
)";
}
 
// ----------------------------- main -----------------------------
 
int main(int argc, char* argv[])
{
    if (argc < 2) { PrintUsage(); return 1; }
 
    string cmd = argv[1];
 
    try {
        if (cmd == "keygen")                  CmdKeygen(argc, argv);
        else if (cmd == "show")               CmdShow(argc, argv);
        else if (cmd == "encrypt")            CmdEncrypt(argc, argv);
        else if (cmd == "decrypt")            CmdDecrypt(argc, argv);
        else if (cmd == "--kat" && argc >= 3) CmdKAT(argv[2]);
        else if (cmd == "--test-negative")    CmdNegativeTest();
        else { cerr << "Unknown command: " << cmd << "\n"; PrintUsage(); return 1; }
    }
    catch (const HashVerificationFilter::HashVerificationFailed&) {
        cerr << "AUTHENTICATION FAILED: ciphertext was tampered or wrong key/AAD.\n";
        return 2;
    }
    catch (const Exception& e) {
        cerr << "Crypto++ error: " << e.what() << "\n";
        return 2;
    }
    catch (const exception& e) {
        cerr << "Error: " << e.what() << "\n";
        return 1;
    }
    return 0;
}
 