/**
 * bench.cpp — Lab 1 Benchmark
 *
 * Benchmarks AES modes: CBC, CFB, OFB, CTR, GCM, CCM, XTS
 * Payload sizes : 1KB, 4KB, 16KB, 256KB, 1MB, 8MB
 * Metrics       : throughput (MB/s), latency (ms/op)
 * Statistics    : mean, median, std dev, 95% CI
 * Runs per case : 50  (warm-up: 5)
 *
 * Build & run:
 *   cmake --build . && ./bench
 *   ./bench --runs 100 --csv results.csv
 */

#include <iostream>
#include <fstream>
#include <sstream>
#include <string>
#include <vector>
#include <algorithm>
#include <numeric>
#include <cmath>
#include <chrono>
#include <iomanip>
#include <stdexcept>
#include <cstring>

// Crypto++
#include <cryptopp/aes.h>
#include <cryptopp/osrng.h>
#include <cryptopp/secblock.h>
#include <cryptopp/modes.h>
#include <cryptopp/gcm.h>
#include <cryptopp/ccm.h>
#include <cryptopp/xts.h>
#include <cryptopp/filters.h>
#include <cryptopp/files.h>

using namespace CryptoPP;
using namespace std;
using Clock = chrono::high_resolution_clock;

// ─────────────────────── Config ─────────────────────────────────
static int    N_WARMUP = 5;
static int    N_RUNS   = 50;

static const vector<size_t> PAYLOAD_SIZES = {
    1   * 1024,          //   1 KB
    4   * 1024,          //   4 KB
    16  * 1024,          //  16 KB
    256 * 1024,          // 256 KB
    1   * 1024 * 1024,   //   1 MB
    8   * 1024 * 1024    //   8 MB
};

static const string SIZE_LABELS[] = {
    "1 KB", "4 KB", "16 KB", "256 KB", "1 MB", "8 MB"
};

static constexpr size_t GCM_TAG = 16;
static constexpr size_t CCM_TAG = 16;
static constexpr size_t CCM_IV  = 7;
static constexpr size_t GCM_IV  = 12;

// ─────────────────────── Statistics ─────────────────────────────

struct Stats {
    double mean_ms;
    double median_ms;
    double stddev_ms;
    double ci95_ms;     // half-width of 95% CI
    double throughput;  // MB/s based on mean
    size_t payload;
};

struct RawSample {
    string operation;   // "encrypt" hoặc "decrypt"
    string mode;
    string size_label;
    size_t payload;
    int run_index;
    double time_s;
};

static Stats ComputeStats(vector<double>& samples_ms, size_t payload_bytes)
{
    int n = (int)samples_ms.size();
    sort(samples_ms.begin(), samples_ms.end());

    double sum = accumulate(samples_ms.begin(), samples_ms.end(), 0.0);
    double mean = sum / n;

    double var = 0;
    for (auto v : samples_ms) var += (v - mean) * (v - mean);
    var /= (n - 1);
    double sd = sqrt(var);

    double median = (n % 2 == 0)
        ? (samples_ms[n/2-1] + samples_ms[n/2]) / 2.0
        : samples_ms[n/2];

    // t critical value for 95% CI, df ≥ 30 ≈ 2.042 (df=30), use 2.0
    double t95 = (n >= 30) ? 2.042 : 2.776; // df=4 for small n
    double ci  = t95 * sd / sqrt((double)n);

    double throughput_MBs = (payload_bytes / 1e6) / (mean / 1e3);

    return {mean, median, sd, ci, throughput_MBs, payload_bytes};
}

// ─────────────────────── Crypto helpers ─────────────────────────

static void DoEncrypt(const string& mode,
                      const SecByteBlock& key,
                      const SecByteBlock& iv,
                      const string& pt,
                      string& ct)
{
    if (mode == "cbc") {
        CBC_Mode<AES>::Encryption e;
        e.SetKeyWithIV(key, key.size(), iv);
        StringSource(pt, true, new StreamTransformationFilter(e, new StringSink(ct)));
    } else if (mode == "cfb") {
        CFB_Mode<AES>::Encryption e;
        e.SetKeyWithIV(key, key.size(), iv);
        StringSource(pt, true, new StreamTransformationFilter(e, new StringSink(ct)));
    } else if (mode == "ofb") {
        OFB_Mode<AES>::Encryption e;
        e.SetKeyWithIV(key, key.size(), iv);
        StringSource(pt, true, new StreamTransformationFilter(e, new StringSink(ct)));
    } else if (mode == "ctr") {
        CTR_Mode<AES>::Encryption e;
        e.SetKeyWithIV(key, key.size(), iv);
        StringSource(pt, true, new StreamTransformationFilter(e, new StringSink(ct)));
    } else if (mode == "gcm") {
        GCM<AES>::Encryption e;
        e.SetKeyWithIV(key, key.size(), iv, iv.size());
        AuthenticatedEncryptionFilter f(e, new StringSink(ct), false, GCM_TAG);
        f.ChannelMessageEnd(AAD_CHANNEL);
        f.Put(reinterpret_cast<const CryptoPP::byte*>(pt.data()), pt.size());
        f.MessageEnd();
    } else if (mode == "ccm") {
        CCM<AES, CCM_TAG>::Encryption e;
        e.SetKeyWithIV(key, key.size(), iv, iv.size());
        e.SpecifyDataLengths(0, pt.size(), 0);
        AuthenticatedEncryptionFilter f(e, new StringSink(ct));
        f.ChannelMessageEnd(AAD_CHANNEL);
        f.Put(reinterpret_cast<const CryptoPP::byte*>(pt.data()), pt.size());
        f.MessageEnd();
    } else if (mode == "xts") {
        XTS_Mode<AES>::Encryption e;
        SecByteBlock tweak(AES::BLOCKSIZE);
        memset(tweak, 0, tweak.size());
        e.SetKeyWithIV(key, key.size(), tweak, tweak.size());
        StringSource(pt, true, new StreamTransformationFilter(e, new StringSink(ct)));
    }
}

static void DoDecrypt(const string& mode,
                      const SecByteBlock& key,
                      const SecByteBlock& iv,
                      const string& ct,
                      string& recovered)
{
    if (mode == "cbc") {
        CBC_Mode<AES>::Decryption d;
        d.SetKeyWithIV(key, key.size(), iv);
        StringSource(ct, true, new StreamTransformationFilter(d, new StringSink(recovered)));

    } else if (mode == "cfb") {
        CFB_Mode<AES>::Decryption d;
        d.SetKeyWithIV(key, key.size(), iv);
        StringSource(ct, true, new StreamTransformationFilter(d, new StringSink(recovered)));

    } else if (mode == "ofb") {
        OFB_Mode<AES>::Decryption d;
        d.SetKeyWithIV(key, key.size(), iv);
        StringSource(ct, true, new StreamTransformationFilter(d, new StringSink(recovered)));

    } else if (mode == "ctr") {
        CTR_Mode<AES>::Decryption d;
        d.SetKeyWithIV(key, key.size(), iv);
        StringSource(ct, true, new StreamTransformationFilter(d, new StringSink(recovered)));

    } else if (mode == "gcm") {
        GCM<AES>::Decryption d;
        d.SetKeyWithIV(key, key.size(), iv, iv.size());

        AuthenticatedDecryptionFilter f(
            d,
            new StringSink(recovered),
            AuthenticatedDecryptionFilter::MAC_AT_END |
            AuthenticatedDecryptionFilter::THROW_EXCEPTION,
            GCM_TAG
        );

        f.ChannelMessageEnd(AAD_CHANNEL);
        f.Put(reinterpret_cast<const CryptoPP::byte*>(ct.data()), ct.size());
        f.MessageEnd();

    } else if (mode == "ccm") {
        CCM<AES, CCM_TAG>::Decryption d;
        d.SetKeyWithIV(key, key.size(), iv, iv.size());

        size_t pt_len = ct.size() > CCM_TAG ? ct.size() - CCM_TAG : 0;
        d.SpecifyDataLengths(0, pt_len, 0);

        AuthenticatedDecryptionFilter f(
            d,
            new StringSink(recovered),
            AuthenticatedDecryptionFilter::MAC_AT_END |
            AuthenticatedDecryptionFilter::THROW_EXCEPTION
        );

        f.ChannelMessageEnd(AAD_CHANNEL);
        f.Put(reinterpret_cast<const CryptoPP::byte*>(ct.data()), ct.size());
        f.MessageEnd();

    } else if (mode == "xts") {
        XTS_Mode<AES>::Decryption d;
        SecByteBlock tweak(AES::BLOCKSIZE);
        memset(tweak, 0, tweak.size());

        d.SetKeyWithIV(key, key.size(), tweak, tweak.size());
        StringSource(ct, true, new StreamTransformationFilter(d, new StringSink(recovered)));
    }
}

// ─────────────────────── Single benchmark ───────────────────────

static Stats BenchmarkMode(const string& mode,
                           const SecByteBlock& key,
                           size_t payload_bytes,
                           const string& size_label,
                           vector<RawSample>& raw_rows)
{
    AutoSeededRandomPool prng;

    // Generate random plaintext once
    string plaintext(payload_bytes, '\0');
    prng.GenerateBlock(reinterpret_cast<CryptoPP::byte*>(&plaintext[0]), payload_bytes);

    // Pad to block boundary if needed (for block modes)
    // (Crypto++ StreamTransformationFilter adds PKCS7 by default for CBC/ECB)

    // Generate IV
    SecByteBlock iv;
    if (mode == "gcm") {
        iv.CleanNew(GCM_IV);
        prng.GenerateBlock(iv, iv.size());
    } else if (mode == "ccm") {
        iv.CleanNew(CCM_IV);
        prng.GenerateBlock(iv, iv.size());
    } else if (mode != "xts") {
        iv.CleanNew(AES::BLOCKSIZE);
        prng.GenerateBlock(iv, iv.size());
    }

    vector<double> samples;
    samples.reserve(N_WARMUP + N_RUNS);

    // Warm-up
    for (int i = 0; i < N_WARMUP; ++i) {
        string ct;
        DoEncrypt(mode, key, iv, plaintext, ct);
    }

    // Timed runs
    for (int i = 0; i < N_RUNS; ++i) {
        string ct;
        auto t0 = Clock::now();
        DoEncrypt(mode, key, iv, plaintext, ct);
        auto t1 = Clock::now();

        double ms = chrono::duration<double, milli>(t1 - t0).count();
        samples.push_back(ms);

        raw_rows.push_back({
            "encrypt",
            mode,
            size_label,
            payload_bytes,
            i + 1,
            ms / 1000.0
        });
    }
    // Prepare one ciphertext for decrypt benchmark
        string fixed_ct;
        DoEncrypt(mode, key, iv, plaintext, fixed_ct);

        // Warm-up decrypt
        for (int i = 0; i < N_WARMUP; ++i) {
            string recovered;
            DoDecrypt(mode, key, iv, fixed_ct, recovered);
        }

        // Timed decrypt runs
        for (int i = 0; i < N_RUNS; ++i) {
            string recovered;

            auto t0 = Clock::now();
            DoDecrypt(mode, key, iv, fixed_ct, recovered);
            auto t1 = Clock::now();

            double ms = chrono::duration<double, milli>(t1 - t0).count();

            raw_rows.push_back({
                "decrypt",
                mode,
                size_label,
                payload_bytes,
                i + 1,
                ms / 1000.0
            });
        }

    return ComputeStats(samples, payload_bytes);
}

// ─────────────────────── Reporting ──────────────────────────────

static void PrintTableHeader()
{
    cout << "\n"
         << left  << setw(8)  << "Mode"
         << right << setw(10) << "Size"
         << right << setw(12) << "Mean(ms)"
         << right << setw(12) << "Median(ms)"
         << right << setw(10) << "SD(ms)"
         << right << setw(14) << "95% CI ±(ms)"
         << right << setw(14) << "Throughput"
         << "\n";
    cout << string(80, '-') << "\n";
}

static void PrintRow(const string& mode, const string& size_label, const Stats& s)
{
    cout << left  << setw(8)  << mode
         << right << setw(10) << size_label
         << right << setw(12) << fixed << setprecision(3) << s.mean_ms
         << right << setw(12) << fixed << setprecision(3) << s.median_ms
         << right << setw(10) << fixed << setprecision(3) << s.stddev_ms
         << right << setw(14) << fixed << setprecision(3) << s.ci95_ms
         << right << setw(12) << fixed << setprecision(2) << s.throughput
         << " MB/s\n";
}

// CSV writer
static void WriteCSV(const string& path,
                     const vector<tuple<string,string,Stats>>& rows)
{
    ofstream f(path);
    f << "mode,size_label,payload_bytes,mean_ms,median_ms,stddev_ms,ci95_ms,throughput_MBs\n";
    for (auto& [mode, label, s] : rows) {
        f << mode      << ","
          << label     << ","
          << s.payload << ","
          << fixed << setprecision(4)
          << s.mean_ms       << ","
          << s.median_ms     << ","
          << s.stddev_ms     << ","
          << s.ci95_ms       << ","
          << s.throughput    << "\n";
    }
    cout << "\nCSV saved → " << path << "\n";
}

static void WriteRawCSV(const string& path, const vector<RawSample>& rows)
{
    ofstream f(path);
    f << "operation,mode,size_label,payload_bytes,run_index,time_s\n";

    for (const auto& r : rows) {
        f << r.operation << ","
          << r.mode << ","
          << r.size_label << ","
          << r.payload << ","
          << r.run_index << ","
          << fixed << setprecision(6) << r.time_s << "\n";
    }

    cout << "\nRaw CSV saved → " << path << "\n";
}
// ─────────────────────── Main ───────────────────────────────────

int main(int argc, char* argv[])
{
    // Parse CLI
    string csv_path;
    string raw_csv_path;
    size_t key_bits = 256;
    vector<RawSample> raw_rows;

    for (int i = 1; i < argc; ++i) {
        string a = argv[i];
        if (a == "--runs"   && i+1 < argc) N_RUNS   = stoi(argv[++i]);
        else if (a == "--warmup" && i+1 < argc) N_WARMUP = stoi(argv[++i]);
        else if (a == "--bits"   && i+1 < argc) key_bits = stoul(argv[++i]);
        else if (a == "--csv"    && i+1 < argc) csv_path = argv[++i];
        else if (a == "--rawcsv" && i+1 < argc) raw_csv_path = argv[++i];
    }

    if (key_bits != 128 && key_bits != 192 && key_bits != 256)
        key_bits = 256;

    size_t key_bytes = key_bits / 8;

    // Generate keys
    AutoSeededRandomPool prng;

    SecByteBlock key(key_bytes);
    prng.GenerateBlock(key, key.size());

    // XTS uses 2× key
    SecByteBlock key_xts(key_bytes * 2);
    prng.GenerateBlock(key_xts, key_xts.size());

    // Modes to benchmark
    // XTS requires block-aligned input (we'll skip sizes < 16 bytes, all are fine here)
    vector<pair<string, SecByteBlock*>> modes = {
        {"cbc", &key},
        {"cfb", &key},
        {"ofb", &key},
        {"ctr", &key},
        {"gcm", &key},
        {"ccm", &key},
        {"xts", &key_xts},
    };

    cout << "____________________________________________________\n";
    cout << "|  AES Benchmark — Lab 1                           |\n";
    cout << "|__________________________________________________|\n";
    cout << "|  Key size  : AES-" << key_bits
         << "                              |\n";
    cout << "|  Warm-up   : " << N_WARMUP
         << " runs                              |\n";
    cout << "|  Runs      : " << N_RUNS
         << " runs per case                        |\n";
    cout << "|__________________________________________________|\n";

    PrintTableHeader();

    vector<tuple<string,string,Stats>> all_rows;

    for (auto& [mname, pkey] : modes) {
        for (size_t si = 0; si < PAYLOAD_SIZES.size(); ++si) {
            size_t sz = PAYLOAD_SIZES[si];
            try {
                Stats s = BenchmarkMode(mname, *pkey, sz, SIZE_LABELS[si], raw_rows);
                PrintRow(mname, SIZE_LABELS[si], s);
                all_rows.emplace_back(mname, SIZE_LABELS[si], s);
            } catch (const exception& e) {
                cout << "[SKIP] " << mname << " / " << SIZE_LABELS[si]
                    << " — " << e.what() << "\n";
            }
        }
        cout << "\n";
    }

    // Summary: fastest throughput per mode (at 8 MB)
    cout << "\n=== Summary: Throughput at 8 MB (MB/s) ===\n";
    cout << string(40, '-') << "\n";
    for (auto& [mode, pkey] : modes) {
        for (auto& [m, l, s] : all_rows) {
            if (m == mode && l == "8 MB") {
                cout << left << setw(6) << mode
                     << " : " << fixed << setprecision(2)
                     << s.throughput << " MB/s\n";
            }
        }
    }

    // Comparison note
    cout << "\n=== AEAD overhead at 1 MB (GCM vs CTR) ===\n";
    cout << string(40, '-') << "\n";
    double ctr_tp = 0, gcm_tp = 0;
    for (auto& [m, l, s] : all_rows) {
        if (m == "ctr" && l == "1 MB") ctr_tp = s.throughput;
        if (m == "gcm" && l == "1 MB") gcm_tp = s.throughput;
    }
    if (ctr_tp > 0 && gcm_tp > 0) {
        double overhead = (ctr_tp - gcm_tp) / ctr_tp * 100.0;
        cout << "CTR : " << fixed << setprecision(2) << ctr_tp << " MB/s\n";
        cout << "GCM : " << fixed << setprecision(2) << gcm_tp << " MB/s\n";
        cout << "AEAD overhead ≈ " << fixed << setprecision(1) << overhead << "%\n";
    }

    if (!csv_path.empty())
        WriteCSV(csv_path, all_rows);
    if (!raw_csv_path.empty()) {
    WriteRawCSV(raw_csv_path, raw_rows);
    }
    return 0;
}
