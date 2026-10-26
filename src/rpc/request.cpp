// Copyright (c) 2010 Satoshi Nakamoto
// Copyright (c) 2009-2022 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#if defined(HAVE_CONFIG_H)
#include <config/bitcoin-config.h>
#endif

#include <rpc/request.h>
#include <haskell/bridge.h>

#include <common/args.h>
#include <crypto/common.h>
#include <logging.h>
#include <random.h>
#include <rpc/protocol.h>
#include <util/fs.h>
#include <util/fs_helpers.h>
#include <util/strencodings.h>

#include <array>
#include <cerrno>
#include <cstring>
#include <fstream>
#include <memory>
#include <stdexcept>
#include <string>
#include <vector>
#include <bitcoin-build-config.h> // IWYU pragma: keep

#ifndef WIN32
#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>
#endif

/**
 * JSON-RPC protocol.  Bitcoin speaks version 1.0 for maximum compatibility,
 * but uses JSON-RPC 1.1/2.0 standards for parts of the 1.0 standard that were
 * unspecified (HTTP errors and contents of 'error').
 *
 * 1.0 spec: http://json-rpc.org/wiki/specification
 * 1.2 spec: http://jsonrpc.org/historical/json-rpc-over-http.html
 *
 * If the server receives a request with the JSON-RPC 2.0 marker `{"jsonrpc": "2.0"}`
 * then Bitcoin will respond with a strictly specified response.
 * It will only return an HTTP error code if an actual HTTP error is encountered
 * such as the endpoint is not found (404) or the request is not formatted correctly (500).
 * Otherwise the HTTP code is always OK (200) and RPC errors will be included in the
 * response body.
 *
 * 2.0 spec: https://www.jsonrpc.org/specification
 *
 * Also see http://www.simple-is-better.org/rpc/#differences-between-1-0-and-2-0
 */

UniValue JSONRPCRequestObj(const std::string& strMethod, const UniValue& params, const UniValue& id)
{
    UniValue request(UniValue::VOBJ);
    request.pushKV("method", strMethod);
    request.pushKV("params", params);
    request.pushKV("id", id);
    request.pushKV("jsonrpc", "2.0");
    return request;
}

UniValue JSONRPCReplyObj(UniValue result, UniValue error, std::optional<UniValue> id, JSONRPCVersion jsonrpc_version)
{
    UniValue reply(UniValue::VOBJ);
    // Add JSON-RPC version number field in v2 only.
    if (jsonrpc_version == JSONRPCVersion::V2) reply.pushKV("jsonrpc", "2.0");

    // Add both result and error fields in v1, even though one will be null.
    // Omit the null field in v2.
    if (error.isNull()) {
        reply.pushKV("result", std::move(result));
        if (jsonrpc_version == JSONRPCVersion::V1_LEGACY) reply.pushKV("error", NullUniValue);
    } else {
        if (jsonrpc_version == JSONRPCVersion::V1_LEGACY) reply.pushKV("result", NullUniValue);
        reply.pushKV("error", std::move(error));
    }
    if (id.has_value()) reply.pushKV("id", std::move(id.value()));
    return reply;
}

UniValue JSONRPCError(int code, const std::string& message)
{
    UniValue error(UniValue::VOBJ);
    error.pushKV("code", code);
    error.pushKV("message", message);
    return error;
}

/** Username used when cookie authentication is in use (arbitrary, only for
 * recognizability in debugging/logging purposes)
 */
static const std::string COOKIEAUTH_USER = "__cookie__";
/** Default name for auth cookie file */
static const char* const COOKIEAUTH_FILE = ".cookie";

/** Get name of RPC authentication cookie file */
static fs::path GetAuthCookieFile(bool temp=false)
{
    fs::path arg = gArgs.GetPathArg("-rpccookiefile", COOKIEAUTH_FILE);
    if (arg.empty()) {
        return {}; // -norpccookiefile was specified
    }
    if (temp) {
        arg += ".tmp";
    }
    return AbsPathForConfigVal(gArgs, arg);
}

static bool g_generated_cookie = false;

bool GenerateAuthCookie(std::string* cookie_out, std::optional<fs::perms> cookie_perms)
{
    const size_t COOKIE_SIZE = 32;
    unsigned char rand_pwd[COOKIE_SIZE];
    GetRandBytes(rand_pwd);
    std::string cookie = COOKIEAUTH_USER + ":" + HexStr(rand_pwd);

    /** the umask determines what permissions are used to create this file -
     * these are set to 0077 in common/system.cpp.
     */
    std::ofstream file;
    fs::path filepath_tmp = GetAuthCookieFile(true);
    if (filepath_tmp.empty()) {
        return true; // -norpccookiefile
    }
    file.open(filepath_tmp);
    if (!file.is_open()) {
        LogWarning("Unable to open cookie authentication file %s for writing", fs::PathToString(filepath_tmp));
        return false;
    }
    file << cookie;
    file.close();

    fs::path filepath = GetAuthCookieFile(false);
    if (!RenameOver(filepath_tmp, filepath)) {
        LogWarning("Unable to rename cookie authentication file %s to %s", fs::PathToString(filepath_tmp), fs::PathToString(filepath));
        return false;
    }
    if (cookie_perms) {
        std::error_code code;
        fs::permissions(filepath, cookie_perms.value(), fs::perm_options::replace, code);
        if (code) {
            LogWarning("Unable to set permissions on cookie authentication file %s", fs::PathToString(filepath));
            return false;
        }
    }

    g_generated_cookie = true;
    LogInfo("Generated RPC authentication cookie %s\n", fs::PathToString(filepath));
    LogInfo("Permissions used for cookie: %s\n", PermsToSymbolicString(fs::status(filepath).permissions()));

    if (cookie_out)
        *cookie_out = cookie;
    return true;
}

bool GetAuthCookie(std::string *cookie_out)
{
    std::ifstream file;
    std::string cookie;
    fs::path filepath = GetAuthCookieFile();
    if (filepath.empty()) {
        return true; // -norpccookiefile
    }
    file.open(filepath);
    if (!file.is_open())
        return false;
    std::getline(file, cookie);
    file.close();

    if (cookie_out)
        *cookie_out = cookie;
    return true;
}

//
// ELEMENTS:

std::string GetDefaultMainchainAuthCookieFile(const std::string& chain)
{
    return drivechain::haskell::MainchainCookieAtRoot(chain) ? ".cookie" : "regtest/.cookie";
}

/** Get name mainchain RPC authentication cookie file */
fs::path GetMainchainAuthCookieFile(const std::string& cookie_file)
{
    fs::path cookie_path = fs::PathFromString(gArgs.GetArg("-mainchainrpccookiefile", cookie_file));
    if (cookie_path.is_absolute())
        return cookie_path;
    return fsbridge::AbsPathJoin(GetMainchainDefaultDataDir(), cookie_path);
}

fs::path GetMainchainAuthCookieFile()
{
    return GetMainchainAuthCookieFile(GetDefaultMainchainAuthCookieFile(gArgs.GetChainName()));
}

namespace {
struct RpcAuthFileState {
    fs::path path;
    std::string& cookie;
    std::string* error;
    bool rotating;
    std::string native_path;
    std::array<char,4097> contents{};
#ifndef WIN32
    int descriptor=-1, saved_errno=0;
    static void Close(int* fd) noexcept {
        if (*fd>=0) close(*fd);
        *fd=-1;
    }
    std::unique_ptr<int,decltype(&Close)> descriptor_guard{&descriptor,Close};
    struct stat metadata {};
#else
    std::ifstream input;
#endif
    RpcAuthFileState(const fs::path& source, std::string& output, std::string* failure, bool cookie_mode)
        : path(source), cookie(output), error(failure), rotating(cookie_mode)
    {
        cookie.clear();
        if (error) error->clear();
        native_path = fs::PathToString(path);
    }

    std::vector<unsigned char> Read(uint32_t step,uint64_t index,std::span<const unsigned char> request) {
        if (step==50) {
            if (index || !request.empty()) throw std::logic_error("invalid credential record request");
            return std::vector<unsigned char>(cookie.begin(),cookie.end());
        }
        const auto scalar = [&]() -> uint64_t {
#ifndef WIN32
        if (step==40) {
            if (request.size()!=8 || index>contents.size()) throw std::logic_error("invalid credential read request");
            const uint64_t available=ReadLE64(request.data());
            if (!available || available>contents.size()-index) throw std::logic_error("invalid credential read bounds");
            const ssize_t count=read(descriptor,contents.data()+index,available);
            saved_errno=errno;
            return count>=0 ? static_cast<uint64_t>(count) : saved_errno==EINTR ? UINT64_MAX : UINT64_MAX-1;
        }
#endif
        if (!request.empty() || (step!=11 && index)) throw std::logic_error("invalid credential file request");
        switch (step) {
        case 1: return path.is_absolute();
        case 2: if (error) *error="RPC authentication file path must be absolute"; return 1;
#ifndef WIN32
        case 3: return 1;
        case 4:
            descriptor=open(native_path.c_str(),O_RDONLY | O_CLOEXEC | O_NOFOLLOW | O_NONBLOCK);
            saved_errno=errno; return descriptor>=0;
        case 5:
            if (error) *error=strprintf("cannot securely open mainchain RPC cookie %s: %s",native_path,std::strerror(saved_errno));
            return 1;
        case 31: return fstat(descriptor,&metadata)==0;
        case 38: return S_ISREG(metadata.st_mode);
        case 33: return metadata.st_uid;
        case 34: return geteuid();
        case 36: return metadata.st_mode & (S_IRWXG | S_IRWXO);
        case 32: case 35: case 37:
            if (error) *error=std::string(step==32 ? "mainchain RPC cookie is not a regular file: " :
                step==35 ? "mainchain RPC cookie must be owned by the Elements process user: " :
                "mainchain RPC cookie permissions must deny all group and other access: ")+native_path;
            descriptor_guard.reset(); return 1;
        case 8:
            if (error) *error=strprintf("cannot read mainchain RPC cookie %s: %s",native_path,std::strerror(saved_errno));
            descriptor_guard.reset(); return 1;
        case 9: descriptor_guard.reset(); return 1;
        case 10: if (error) *error="mainchain RPC cookie file is unexpectedly large"; return 1;
        case 11:
            if (index>contents.size()) throw std::logic_error("invalid credential publication size");
            cookie.assign(contents.data(),index); return 1;
#else
        case 3: return 0;
        case 12: return fs::is_symlink(path);
        case 13: return fs::exists(path);
        case 14: return fs::is_regular_file(path);
        case 15: if (error) *error="mainchain RPC cookie is not a regular file: "+native_path; return 1;
        case 16: input.open(path,std::ios::binary); return input.good();
        case 17: if (error) *error="cannot read mainchain RPC cookie: "+native_path; return 1;
        case 18: input.read(contents.data(),contents.size()); cookie.assign(contents.data(),input.gcount()); return 1;
        case 19: return input.bad();
        case 20: return cookie.size();
        case 22:
            cookie.clear();
            if (error) *error="mainchain RPC cookie file is unexpectedly large";
            return 1;
#endif
        case 23: case 25: return cookie.empty() ? 256 : static_cast<unsigned char>(cookie.back());
        case 24: case 26: cookie.pop_back(); return 1;
        case 60:
            cookie.clear();
            if (error) *error = rotating
                ? "mainchain RPC cookie is not a canonical rotating Bitcoin Core cookie"
                : "parent credential file must contain one bounded username:password record";
            return 1;
        default: throw std::logic_error("invalid credential file action");
        }
        };
        std::vector<unsigned char> reply(8);
        WriteLE64(reply.data(),scalar());
        return reply;
    }
};
} // namespace

RpcAuthFileReader MakeRpcAuthFileReader(
    const fs::path& path, std::string& contents, std::string* error, bool rotating)
{
    auto state = std::make_shared<RpcAuthFileState>(path, contents, error, rotating);
    return [state = std::move(state)](uint32_t step, uint64_t index, std::span<const unsigned char> request) {
        return state->Read(step, index, request);
    };
}

static bool ReadRpcAuthFile(
    const fs::path& path,
    std::string& cookie,
    std::string* error,
    drivechain::haskell::AuthFileMode mode)
{
    return drivechain::haskell::ReadAuthFile(mode,
        MakeRpcAuthFileReader(path, cookie, error, mode==drivechain::haskell::AuthFileMode::ROTATING_COOKIE));
}

bool ReadPrivateRpcAuthFile(const fs::path& path,std::string& record,std::string* error)
{
    return ReadRpcAuthFile(path,record,error,drivechain::haskell::AuthFileMode::RAW);
}

bool ReadMainchainAuthCookieFile(
    const fs::path& path, std::string& cookie, std::string* error)
{
    return ReadRpcAuthFile(path,cookie,error,drivechain::haskell::AuthFileMode::ROTATING_COOKIE);
}

bool ReadNativeDrivechainCookieFile(
    const fs::path& path, std::string& cookie, std::string* error)
{
    return ReadMainchainAuthCookieFile(path, cookie, error);
}

bool ReadMainchainRpcCredentialFile(
    const fs::path& path, std::string& credentials, std::string* error)
{
    credentials.clear();
#ifdef WIN32
    // This opt-in path promises POSIX ownership/mode enforcement. Do not
    // silently downgrade it to the Windows cookie compatibility path.
    if (error) *error = "private static parent credential files require POSIX file permissions";
    return false;
#else
    return ReadRpcAuthFile(path,credentials,error,drivechain::haskell::AuthFileMode::STATIC_RECORD);
#endif
}

bool GetMainchainAuthCookie(std::string *cookie_out)
{
    std::string cookie;
    std::string error;
    if (!ReadMainchainAuthCookieFile(
            GetMainchainAuthCookieFile(), cookie, &error)) {
        LogPrintf("Unable to read mainchain RPC authentication cookie: %s\n", error);
        return false;
    }

    if (cookie_out)
        *cookie_out = cookie;
    return true;
}

// END ELEMENTS
//

void DeleteAuthCookie()
{
    try {
        if (g_generated_cookie) {
            // Delete the cookie file if it was generated by this process
            fs::remove(GetAuthCookieFile());
        }
    } catch (const fs::filesystem_error& e) {
        LogPrintf("%s: Unable to remove random auth cookie file: %s\n", __func__, fsbridge::get_filesystem_error_message(e));
    }
}

std::vector<UniValue> JSONRPCProcessBatchReply(const UniValue& in)
{
    if (!in.isArray()) {
        throw std::runtime_error("Batch must be an array");
    }
    const size_t num {in.size()};
    std::vector<UniValue> batch(num);
    for (const UniValue& rec : in.getValues()) {
        if (!rec.isObject()) {
            throw std::runtime_error("Batch member must be an object");
        }
        size_t id = rec["id"].getInt<int>();
        if (id >= num) {
            throw std::runtime_error("Batch member id is larger than batch size");
        }
        batch[id] = rec;
    }
    return batch;
}

void JSONRPCRequest::parse(const UniValue& valRequest)
{
    // Parse request
    if (!valRequest.isObject())
        throw JSONRPCError(RPC_INVALID_REQUEST, "Invalid Request object");
    const UniValue& request = valRequest.get_obj();

    // Parse id now so errors from here on will have the id
    if (request.exists("id")) {
        id = request.find_value("id");
    } else {
        id = std::nullopt;
    }

    // Check for JSON-RPC 2.0 (default 1.1)
    m_json_version = JSONRPCVersion::V1_LEGACY;
    const UniValue& jsonrpc_version = request.find_value("jsonrpc");
    if (!jsonrpc_version.isNull()) {
        if (!jsonrpc_version.isStr()) {
            throw JSONRPCError(RPC_INVALID_REQUEST, "jsonrpc field must be a string");
        }
        // The "jsonrpc" key was added in the 2.0 spec, but some older documentation
        // incorrectly included {"jsonrpc":"1.0"} in a request object, so we
        // maintain that for backwards compatibility.
        if (jsonrpc_version.get_str() == "1.0") {
            m_json_version = JSONRPCVersion::V1_LEGACY;
        } else if (jsonrpc_version.get_str() == "2.0") {
            m_json_version = JSONRPCVersion::V2;
        } else {
            throw JSONRPCError(RPC_INVALID_REQUEST, "JSON-RPC version not supported");
        }
    }

    // Parse method
    const UniValue& valMethod{request.find_value("method")};
    if (valMethod.isNull())
        throw JSONRPCError(RPC_INVALID_REQUEST, "Missing method");
    if (!valMethod.isStr())
        throw JSONRPCError(RPC_INVALID_REQUEST, "Method must be a string");
    strMethod = valMethod.get_str();
    if (fLogIPs)
        LogDebug(BCLog::RPC, "ThreadRPCServer method=%s user=%s peeraddr=%s\n", SanitizeString(strMethod),
            this->authUser, this->peerAddr);
    else
        LogDebug(BCLog::RPC, "ThreadRPCServer method=%s user=%s\n", SanitizeString(strMethod), this->authUser);

    // Parse params
    const UniValue& valParams{request.find_value("params")};
    if (valParams.isArray() || valParams.isObject())
        params = valParams;
    else if (valParams.isNull())
        params = UniValue(UniValue::VARR);
    else
        throw JSONRPCError(RPC_INVALID_REQUEST, "Params must be an array or object");
}
