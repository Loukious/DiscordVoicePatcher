#include <napi.h>
#include <Windows.h>
#include <Psapi.h>
#include <fstream>
#include <sstream>
#include <string>
#include <vector>
#include <map>
#include <cstdint>
#include <climits>
#include <cstring>
#include <algorithm>

// ─── Types ─────────────────────────────────────────────────────
struct PatternData {
    std::vector<uint8_t> bytes;
    std::vector<bool>    mask;   // true = must match, false = wildcard
    int                  offset = 0;
};

struct PatchEntry {
    std::string  name;
    PatternData  primary;
    PatternData  alt;            // fallback if primary fails
    std::string  derive_from;
    int          derive_offset     = 0;
    int          alt_derive_offset = INT_MIN; // INT_MIN = not set
    std::vector<uint8_t> expected;
    std::vector<uint8_t> patch;
    std::vector<uint8_t> alt_expected;
    std::vector<uint8_t> alt_patch;
    uintptr_t    resolved_rva = 0;
};

struct PatchSnapshot {
    std::string          name;
    uintptr_t            module_base = 0;
    uintptr_t            rva = 0;
    std::vector<uint8_t> original;
    std::vector<uint8_t> patched;
};

// Exact original bytes captured immediately before each successful write.
// Keyed by absolute patch address so patches can be restored without rescanning.
static std::map<uintptr_t, PatchSnapshot> g_snapshots;

// ─── Helpers ───────────────────────────────────────────────────
static std::string Trim(const std::string& s) {
    size_t a = s.find_first_not_of(" \t\r\n");
    if (a == std::string::npos) return "";
    size_t b = s.find_last_not_of(" \t\r\n");
    return s.substr(a, b - a + 1);
}

static std::string StripComment(const std::string& s) {
    auto p = s.find(';');
    return Trim(p != std::string::npos ? s.substr(0, p) : s);
}

static std::string ToLower(std::string s) {
    std::transform(s.begin(), s.end(), s.begin(), ::tolower);
    return s;
}

static void ParsePattern(const std::string& s, PatternData& out) {
    std::istringstream ss(s);
    std::string token;
    while (ss >> token) {
        if (token == "??") {
            out.bytes.push_back(0x00);
            out.mask.push_back(false);
        } else {
            try {
                out.bytes.push_back((uint8_t)std::stoul(token, nullptr, 16));
                out.mask.push_back(true);
            } catch (...) {}
        }
    }
}

static std::vector<uint8_t> ParseHexBytes(const std::string& s) {
    std::vector<uint8_t> out;
    std::istringstream ss(s);
    std::string token;
    while (ss >> token) {
        if (token == "??") continue;
        try { out.push_back((uint8_t)std::stoul(token, nullptr, 16)); }
        catch (...) {}
    }
    return out;
}

static std::string HexStr(uintptr_t v) {
    std::ostringstream ss;
    ss << "0x" << std::hex << std::uppercase << v;
    return ss.str();
}

static bool IsAltTier(const std::string& tier) {
    return tier == "alt" || tier == "derived-alt";
}

static const std::vector<uint8_t>& ExpectedForTier(const PatchEntry& e, const std::string& tier) {
    if (IsAltTier(tier) && !e.alt_expected.empty()) return e.alt_expected;
    return e.expected;
}

static const std::vector<uint8_t>& PatchForTier(const PatchEntry& e, const std::string& tier) {
    if (IsAltTier(tier) && !e.alt_patch.empty()) return e.alt_patch;
    return e.patch;
}

static bool BytesEqual(const uint8_t* site, const std::vector<uint8_t>& bytes) {
    if (bytes.empty()) return true;
    return std::memcmp(site, bytes.data(), bytes.size()) == 0;
}

static bool WriteBytes(uint8_t* site, const std::vector<uint8_t>& bytes) {
    if (bytes.empty()) return false;

    DWORD old_protect = 0;
    if (!VirtualProtect(site, bytes.size(), PAGE_EXECUTE_READWRITE, &old_protect))
        return false;

    std::memcpy(site, bytes.data(), bytes.size());

    DWORD ignored = 0;
    VirtualProtect(site, bytes.size(), old_protect, &ignored);
    FlushInstructionCache(GetCurrentProcess(), site, bytes.size());
    return true;
}

// ─── INI Parser ────────────────────────────────────────────────
static std::vector<PatchEntry> ParseIni(const std::string& path, std::string& err_out) {
    std::vector<PatchEntry> entries;
    std::ifstream file(path);
    if (!file.is_open()) {
        err_out = "Cannot open: " + path;
        return entries;
    }

    std::string line, current_section;
    std::map<std::string, std::string> kv;

    auto flush = [&]() {
        if (current_section.empty()) return;

        PatchEntry e;
        e.name = current_section;

        if (kv.count("pattern") && !kv["pattern"].empty())
            ParsePattern(kv["pattern"], e.primary);

        if (kv.count("sig_offset") && !kv["sig_offset"].empty())
            try { e.primary.offset = (int)std::stoll(kv["sig_offset"], nullptr, 0); }
            catch (...) {}

        if (kv.count("alt_pattern") && !kv["alt_pattern"].empty())
            ParsePattern(kv["alt_pattern"], e.alt);

        if (kv.count("alt_offset") && !kv["alt_offset"].empty())
            try { e.alt.offset = (int)std::stoll(kv["alt_offset"], nullptr, 0); }
            catch (...) {}

        if (kv.count("derive_from") && !kv["derive_from"].empty())
            e.derive_from = kv["derive_from"];

        if (kv.count("derive_offset") && !kv["derive_offset"].empty())
            try { e.derive_offset = (int)std::stoll(kv["derive_offset"], nullptr, 0); }
            catch (...) {}

        if (kv.count("alt_derive_offset") && !kv["alt_derive_offset"].empty())
            try { e.alt_derive_offset = (int)std::stoll(kv["alt_derive_offset"], nullptr, 0); }
            catch (...) {}

        if (kv.count("expected") && !kv["expected"].empty())
            e.expected = ParseHexBytes(kv["expected"]);

        if (kv.count("patch") && !kv["patch"].empty())
            e.patch = ParseHexBytes(kv["patch"]);

        if (kv.count("alt_expected") && !kv["alt_expected"].empty())
            e.alt_expected = ParseHexBytes(kv["alt_expected"]);

        if (kv.count("alt_patch") && !kv["alt_patch"].empty())
            e.alt_patch = ParseHexBytes(kv["alt_patch"]);

        bool has_pattern = !e.primary.bytes.empty();
        bool has_alt     = !e.alt.bytes.empty();
        bool has_derive  = !e.derive_from.empty();
        bool has_patch   = !e.patch.empty() || !e.alt_patch.empty();

        if ((has_pattern || has_alt || has_derive) && has_patch)
            entries.push_back(e);

        current_section.clear();
        kv.clear();
    };

    while (std::getline(file, line)) {
        line = Trim(line);
        if (line.empty() || line[0] == ';' || line[0] == '#') continue;

        if (line[0] == '[') {
            flush();
            auto close = line.find(']');
            if (close != std::string::npos)
                current_section = Trim(line.substr(1, close - 1));
            continue;
        }

        auto eq = line.find('=');
        if (eq == std::string::npos) continue;
        std::string key = ToLower(Trim(line.substr(0, eq)));
        std::string val = StripComment(line.substr(eq + 1));
        kv[key] = val;
    }
    flush();
    return entries;
}

// ─── Signature Scanner ─────────────────────────────────────────
static uintptr_t SigScan(uint8_t* base, size_t size, const PatternData& p) {
    if (p.bytes.empty() || p.bytes.size() != p.mask.size()) return 0;
    size_t pat_len = p.bytes.size();

    size_t first_fixed = SIZE_MAX;
    for (size_t i = 0; i < pat_len; i++)
        if (p.mask[i]) { first_fixed = i; break; }
    if (first_fixed == SIZE_MAX) return 0;

    uint8_t needle = p.bytes[first_fixed];

    for (size_t i = 0; i + pat_len <= size; i++) {
        if (base[i + first_fixed] != needle) continue;

        bool match = true;
        for (size_t j = 0; j < pat_len; j++) {
            if (p.mask[j] && base[i + j] != p.bytes[j]) {
                match = false;
                break;
            }
        }

        if (match) {
            intptr_t site = (intptr_t)i + p.offset;
            if (site >= 0 && (size_t)site < size)
                return (uintptr_t)site;
        }
    }
    return 0;
}

static bool VerifyExpectedAt(uint8_t* base, uintptr_t mod_size, uintptr_t rva,
                             const std::vector<uint8_t>& expected) {
    if (expected.empty()) return true;
    if (rva >= mod_size || expected.size() > mod_size - rva) return false;
    return BytesEqual(base + rva, expected);
}

// ─── Patch Application ─────────────────────────────────────────
static std::string ApplyPatch(uint8_t* base, uintptr_t mod_size,
                              const PatchEntry& e, const std::string& tier) {
    if (e.resolved_rva == 0)        return "not_resolved";
    if (e.resolved_rva >= mod_size) return "rva_out_of_bounds";

    const auto& expected = ExpectedForTier(e, tier);
    const auto& patch = PatchForTier(e, tier);
    if (patch.empty()) return "no_patch_bytes";

    if (patch.size() > mod_size - e.resolved_rva)
        return "patch_out_of_bounds";
    if (!expected.empty() && expected.size() > mod_size - e.resolved_rva)
        return "expected_out_of_bounds";

    uint8_t* site = base + e.resolved_rva;

    if (BytesEqual(site, patch))
        return "already_patched";

    if (!expected.empty() && !BytesEqual(site, expected))
        return "expected_mismatch";

    // Capture the complete original byte range, not only `expected`.
    // This makes reversion exact even when expected is shorter than patch.
    PatchSnapshot snapshot;
    snapshot.name = e.name;
    snapshot.module_base = reinterpret_cast<uintptr_t>(base);
    snapshot.rva = e.resolved_rva;
    snapshot.original.assign(site, site + patch.size());
    snapshot.patched = patch;

    const uintptr_t absolute_site = reinterpret_cast<uintptr_t>(site);
    g_snapshots[absolute_site] = std::move(snapshot);

    if (!WriteBytes(site, patch)) {
        g_snapshots.erase(absolute_site);
        return "write_failed";
    }

    return "ok";
}

// ─── NAPI Entry ────────────────────────────────────────────────
Napi::Object ApplyPatches(const Napi::CallbackInfo& info) {
    Napi::Env    env    = info.Env();
    Napi::Object result = Napi::Object::New(env);

    if (info.Length() < 1 || !info[0].IsString()) {
        result.Set("error", Napi::String::New(env, "Expected ini_path as argument"));
        return result;
    }

    std::string ini_path = info[0].As<Napi::String>().Utf8Value();
    std::string parse_err;
    auto entries = ParseIni(ini_path, parse_err);

    if (!parse_err.empty()) {
        result.Set("error", Napi::String::New(env, parse_err));
        return result;
    }

    result.Set("patches_in_ini", Napi::Number::New(env, (double)entries.size()));

    HMODULE hmod = GetModuleHandleW(L"discord_voice.node");
    if (!hmod) {
        result.Set("error", Napi::String::New(env, "discord_voice.node not found in process"));
        return result;
    }

    MODULEINFO mi{};
    GetModuleInformation(GetCurrentProcess(), hmod, &mi, sizeof(mi));
    uint8_t*  base     = reinterpret_cast<uint8_t*>(hmod);
    uintptr_t mod_size = mi.SizeOfImage;

    result.Set("module_base", Napi::String::New(env, HexStr((uintptr_t)base)));
    result.Set("module_size", Napi::String::New(env, HexStr(mod_size)));

    std::map<std::string, size_t> name_idx;
    for (size_t i = 0; i < entries.size(); i++)
        name_idx[entries[i].name] = i;

    // ── Phase 1: Signature scan ───────────────────────────────
    std::map<std::string, std::string> tiers;

    for (auto& e : entries) {
        if (!e.primary.bytes.empty()) {
            e.resolved_rva = SigScan(base, mod_size, e.primary);
            if (e.resolved_rva) { tiers[e.name] = "primary"; continue; }
        }
        if (!e.alt.bytes.empty()) {
            e.resolved_rva = SigScan(base, mod_size, e.alt);
            if (e.resolved_rva) { tiers[e.name] = "alt"; continue; }
        }
    }

    // ── Phase 2: Derivation (3 passes for chains) ────────────
    for (int pass = 0; pass < 3; pass++) {
        for (auto& e : entries) {
            if (e.derive_from.empty() || e.resolved_rva != 0) continue;

            auto it = name_idx.find(e.derive_from);
            if (it == name_idx.end()) continue;

            uintptr_t anchor = entries[it->second].resolved_rva;
            if (anchor == 0) continue;

            intptr_t rva = (intptr_t)anchor + e.derive_offset;
            if (rva > 0 && (uintptr_t)rva < mod_size &&
                VerifyExpectedAt(base, mod_size, (uintptr_t)rva, ExpectedForTier(e, "derived"))) {
                e.resolved_rva = (uintptr_t)rva;
                tiers[e.name] = "derived";
                continue;
            }

            if (e.alt_derive_offset != INT_MIN) {
                intptr_t rva_alt = (intptr_t)anchor + e.alt_derive_offset;
                if (rva_alt > 0 && (uintptr_t)rva_alt < mod_size &&
                    VerifyExpectedAt(base, mod_size, (uintptr_t)rva_alt, ExpectedForTier(e, "derived-alt"))) {
                    e.resolved_rva = (uintptr_t)rva_alt;
                    tiers[e.name] = "derived-alt";
                }
            }
        }
    }

    // ── Phase 3: Apply patches ───────────────────────────────
    Napi::Array arr = Napi::Array::New(env);
    int ok = 0, failed = 0, skipped = 0;

    for (size_t i = 0; i < entries.size(); i++) {
        const auto& e = entries[i];
        Napi::Object r = Napi::Object::New(env);
        r.Set("name", Napi::String::New(env, e.name));

        if (e.resolved_rva)
            r.Set("rva", Napi::String::New(env, HexStr(e.resolved_rva)));

        std::string tier;
        auto tier_it = tiers.find(e.name);
        if (tier_it != tiers.end()) {
            tier = tier_it->second;
            r.Set("tier", Napi::String::New(env, tier));
        }

        std::string status = ApplyPatch(base, mod_size, e, tier);
        r.Set("status", Napi::String::New(env, status));

        if      (status == "ok" || status == "already_patched") ok++;
        else if (status == "not_resolved")                      skipped++;
        else                                                    failed++;

        arr.Set((uint32_t)i, r);
    }

    result.Set("patches", arr);
    result.Set("ok",      Napi::Number::New(env, ok));
    result.Set("failed",  Napi::Number::New(env, failed));
    result.Set("skipped", Napi::Number::New(env, skipped));
    result.Set("tracked", Napi::Number::New(env, (double)g_snapshots.size()));
    return result;
}

Napi::Object RevertPatches(const Napi::CallbackInfo& info) {
    Napi::Env    env    = info.Env();
    Napi::Object result = Napi::Object::New(env);

    HMODULE hmod = GetModuleHandleW(L"discord_voice.node");
    if (!hmod) {
        result.Set("error", Napi::String::New(env, "discord_voice.node not found in process"));
        return result;
    }

    MODULEINFO mi{};
    GetModuleInformation(GetCurrentProcess(), hmod, &mi, sizeof(mi));
    uint8_t*  base     = reinterpret_cast<uint8_t*>(hmod);
    uintptr_t mod_size = mi.SizeOfImage;
    uintptr_t module_base = reinterpret_cast<uintptr_t>(base);

    result.Set("module_base", Napi::String::New(env, HexStr(module_base)));
    result.Set("module_size", Napi::String::New(env, HexStr(mod_size)));
    result.Set("tracked_before", Napi::Number::New(env, (double)g_snapshots.size()));

    Napi::Array arr = Napi::Array::New(env);
    uint32_t out_index = 0;
    int ok = 0, failed = 0, skipped = 0;

    for (auto it = g_snapshots.begin(); it != g_snapshots.end();) {
        const PatchSnapshot snapshot = it->second;
        Napi::Object r = Napi::Object::New(env);
        r.Set("name", Napi::String::New(env, snapshot.name));
        r.Set("rva", Napi::String::New(env, HexStr(snapshot.rva)));

        std::string status;
        bool erase_snapshot = false;

        if (snapshot.module_base != module_base) {
            status = "stale_module";
            skipped++;
            erase_snapshot = true;
        } else if (snapshot.rva >= mod_size || snapshot.original.size() > mod_size - snapshot.rva) {
            status = "rva_out_of_bounds";
            failed++;
        } else {
            uint8_t* site = base + snapshot.rva;

            if (BytesEqual(site, snapshot.original)) {
                status = "already_reverted";
                ok++;
                erase_snapshot = true;
            } else if (!BytesEqual(site, snapshot.patched)) {
                // Do not overwrite bytes changed by somebody else after us.
                status = "current_bytes_mismatch";
                failed++;
            } else if (!WriteBytes(site, snapshot.original)) {
                status = "write_failed";
                failed++;
            } else {
                status = "ok";
                ok++;
                erase_snapshot = true;
            }
        }

        r.Set("status", Napi::String::New(env, status));
        arr.Set(out_index++, r);

        if (erase_snapshot)
            it = g_snapshots.erase(it);
        else
            ++it;
    }

    result.Set("patches", arr);
    result.Set("ok",      Napi::Number::New(env, ok));
    result.Set("failed",  Napi::Number::New(env, failed));
    result.Set("skipped", Napi::Number::New(env, skipped));
    result.Set("tracked_after", Napi::Number::New(env, (double)g_snapshots.size()));
    return result;
}

Napi::Object Init(Napi::Env env, Napi::Object exports) {
    exports.Set("applyPatches", Napi::Function::New(env, ApplyPatches));
    exports.Set("revertPatches", Napi::Function::New(env, RevertPatches));
    return exports;
}

NODE_API_MODULE(discord_voice_patcher, Init)
