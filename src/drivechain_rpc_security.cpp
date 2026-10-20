// Copyright (c) 2026 The Elements Core developers
// Distributed under the MIT software license.
#include <init.h>
#include <chainparamsbase.h>
#include <mainchainrpc.h>
#include <drivechain_settings.h>
#include <haskell/bridge.h>
#include <haskell/rpc_security_constants.h>
#include <netbase.h>
#include <common/args.h>
#include <util/fs_helpers.h>
#include <util/strencodings.h>
#include <algorithm>
#include <array>
#include <fstream>
#include <limits>
#include <stdexcept>
#ifndef WIN32
#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>
#endif

namespace {

struct DrivechainGrpcTLSConfig {
    std::string address;
    fs::path ca_certificate;
    fs::path client_certificate;
    fs::path client_key;
    std::string authority;
};

bool IsEnforcerHostAllowed(const std::string& host, bool allow_remote)
{
    if (IsMainchainRPCHostAllowed(host, /*native_drivechain=*/true)) return true;
    if (!allow_remote) return false;
    // Admit only IP literals or DNS names, never gRPC resolver URIs or paths.
    if (const auto ip = LookupHost(host, /*fAllowLookup=*/false)) {
        return ip->IsIPv4() || ip->IsIPv6();
    }
    if (host.empty() || host.size() > 253) return false;
    size_t label_start{0};
    for (size_t i = 0; i <= host.size(); ++i) {
        if (i == host.size() || host[i] == '.') {
            if (i == label_start || i - label_start > 63 ||
                host[label_start] == '-' || host[i - 1] == '-') return false;
            label_start = i + 1;
        } else if (!IsDigit(host[i]) && !(ToLower(host[i]) >= 'a' && ToLower(host[i]) <= 'z') && host[i] != '-') {
            return false;
        }
    }
    return true;
}

fs::path ResolveDrivechainGrpcCredentialPath(const ArgsManager& args,
                                             const std::string& argument,
                                             const std::string& fallback)
{
    fs::path path = fs::PathFromString(args.GetArg(argument, fallback));
    if (path.is_absolute()) return path;
    return fsbridge::AbsPathJoin(args.GetDataDirNet(), path);
}

DrivechainGrpcTLSConfig GetDrivechainGrpcTLSConfig(const ArgsManager& args)
{
    return {
        args.GetArg("-drivechainbmmgrpcaddr", DEFAULT_DRIVECHAIN_GRPC_ENDPOINT),
        ResolveDrivechainGrpcCredentialPath(
            args, "-drivechainbmmgrpcca", drivechain::GRPC_CA_FILE),
        ResolveDrivechainGrpcCredentialPath(
            args, "-drivechainbmmgrpccert", drivechain::GRPC_CLIENT_CERT_FILE),
        ResolveDrivechainGrpcCredentialPath(
            args, "-drivechainbmmgrpckey", drivechain::GRPC_CLIENT_KEY_FILE),
        args.GetArg("-drivechainbmmgrpcauthority", ""),
    };
}

bool ValidateReadableRegularFile(const fs::path& path,
                                 const bool private_key,
                                 std::string* error)
{
#ifndef WIN32
    struct stat metadata {}, parent_metadata {}, opened_metadata {};
    std::string native_path, native_parent;
    int descriptor=-1;
#endif
    try {
      return drivechain::haskell::AdmitTlsCredentialFile(private_key,[&](uint32_t action) -> uint64_t {
        switch (action) {
        case 1: {
            std::error_code status_error;
            const auto status = fs::symlink_status(path,status_error);
            if (status_error || !fs::is_regular_file(status)) return 0;
#ifdef WIN32
            return 2;
#else
            return 1;
#endif
        }
        case 2:
            if (error) *error = strprintf("required %s must be a non-symlink regular file: %s",
                private_key ? "mTLS client key" : "mTLS certificate",fs::PathToString(path));
            return 1;
#ifndef WIN32
        case 3:
            native_path = fs::PathToString(path);
            return lstat(native_path.c_str(),&metadata)==0 && S_ISREG(metadata.st_mode);
        case 4:
            if (error) *error = strprintf("mTLS credential must be a non-symlink regular file: %s",native_path);
            return 1;
        case 5: return metadata.st_uid;
        case 15: return geteuid();
        case 6:
            if (error) *error = strprintf("mTLS credential must be owned by the Elements process user: %s",native_path);
            return 1;
        case 7: {
            const auto parent_path = path.parent_path();
            native_parent = fs::PathToString(parent_path);
            return !parent_path.empty();
        }
        case 16: return lstat(native_parent.c_str(),&parent_metadata)==0 && S_ISDIR(parent_metadata.st_mode);
        case 17: return parent_metadata.st_uid;
        case 18: return geteuid();
        case 19: return parent_metadata.st_mode & (S_IWGRP | S_IWOTH);
        case 8:
            if (error) *error = strprintf(
                "mTLS credential directory must be owned by the Elements process user and deny group/other write access: %s",native_parent);
            return 1;
        case 9: return metadata.st_mode & (S_IRWXG | S_IRWXO);
        case 20: return metadata.st_mode & (S_IWGRP | S_IWOTH);
        case 10:
            if (error) *error = private_key
                ? strprintf("mTLS client key must deny all group and other access: %s",native_path)
                : strprintf("mTLS certificate must deny group and other write access: %s",native_path);
            return 1;
        case 11:
            descriptor=open(native_path.c_str(),O_RDONLY | O_CLOEXEC | O_NOFOLLOW | O_NONBLOCK);
            return descriptor>=0;
        case 21: return fstat(descriptor,&opened_metadata)==0 && S_ISREG(opened_metadata.st_mode);
        case 22: return opened_metadata.st_uid;
        case 23: return geteuid();
        case 24: return opened_metadata.st_mode & (S_IRWXG | S_IRWXO);
        case 25: return opened_metadata.st_mode & (S_IWGRP | S_IWOTH);
        case 26: return opened_metadata.st_dev;
        case 27: return metadata.st_dev;
        case 28: return opened_metadata.st_ino;
        case 29: return metadata.st_ino;
        case 30:
            if (descriptor>=0) close(descriptor);
            descriptor=-1; return 1;
        case 12:
            if (error) *error = "mTLS credential could not be securely opened: " + native_path;
            return 1;
#else
        case 13: {
            std::ifstream input(path);
            return input.good();
        }
        case 14:
            if (error) *error = "required mTLS credential is not readable: " + fs::PathToString(path);
            return 1;
#endif
        default: throw std::logic_error("invalid credential validation action");
        }
      });
    } catch (...) {
#ifndef WIN32
        if (descriptor>=0) close(descriptor);
#endif
        throw;
    }
}

} // namespace

DrivechainGrpcStatus ClassifyDrivechainGrpcResult(const BoundedCommandResult& child,
    bool accept_duplicate, std::string& error)
{
    std::vector<unsigned char> input{2,static_cast<unsigned char>(
        child.cancelled | (child.started << 1) | (child.timed_out << 2) |
        (child.output_truncated << 3) | (!child.error.empty() << 4) |
        (child.exited << 5) | ((child.exit_code == 0) << 6)),static_cast<unsigned char>(accept_duplicate && child.exit_code == 6)};
    input.insert(input.end(),child.output.begin(),child.output.end());
    std::vector<unsigned char> output;
    if (!drivechain::haskell::WithdrawalBytes(drivechain::haskell::WithdrawalOp::SUBMISSION_POLICY,input,output,nullptr))
        throw std::runtime_error("Invalid Haskell gRPC result policy input");
    error.clear();
    switch (output.at(0)) {
    case 0: return DrivechainGrpcStatus::SUCCESS;
    case 4: error = "enforcer gRPC cancelled during shutdown"; break;
    case 5: error = strprintf("enforcer gRPC request rejected: %s",child.error); break;
    case 6: error = "enforcer gRPC exceeded its deadline"; break;
    case 7: error = "enforcer gRPC exceeded its output limit"; break;
    case 8: error = strprintf("enforcer gRPC transport failed: %s",child.error); break;
    case 9: error = "enforcer gRPC did not complete"; break;
    case 10:
        error = strprintf("enforcer gRPC status %d: %s",child.exit_code,child.output);
        return DrivechainGrpcStatus::NONZERO_EXIT;
    default: throw std::runtime_error("Invalid Haskell gRPC result policy response");
    }
    return DrivechainGrpcStatus::PROCESS_FAILURE;
}

bool ValidateDrivechainGrpcTLSConfig(const ArgsManager& args, std::string* error)
{
    if (error) error->clear();
    const DrivechainGrpcTLSConfig config = GetDrivechainGrpcTLSConfig(args);
    static constexpr const char* errors[]{
        "-drivechainbmmgrpcaddr must be a host:port endpoint without a URL scheme",
        "-drivechainbmmgrpcaddr contains whitespace, control characters, or excessive data",
        "-drivechainbmmgrpcaddr must contain a non-empty host and nonzero port",
        "-drivechainbmmgrpcaddr requires numeric loopback unless -drivechainenforcerremote=1; remote endpoints must be IP literals or DNS names",
        "-drivechainpegoutenforcer and -drivechainbmmgrpcaddr must select the same authenticated endpoint",
        "-drivechainbmmwalletaddr and -drivechainbmmgrpcaddr must select the same authenticated endpoint",
        "Connect bearer authentication is no longer supported; configure enforcer mTLS",
        "-drivechainbmmgrpcauthority contains whitespace or control characters"};
    const auto text=drivechain::haskell::AdmitGrpcText(config.address,config.authority);
    uint16_t port{0};
    std::string host;
    return drivechain::haskell::ParentReplayStore(drivechain::haskell::ReplayStoreFlow::GRPC_CONFIG,
        [&](uint32_t action) -> uint32_t {
        if (action>=2 && action<=16 && action%2==0) {
            if (error) *error=errors[action/2-1];
            return 1;
        }
        switch (action) {
        case 1: return text.address_shape;
        case 3: return text.address_characters;
        case 5:
            SplitHostPort(config.address,port,host);
            return !host.empty() | (!host.starts_with('-') << 1) | ((port!=0) << 2);
        case 7: return IsEnforcerHostAllowed(host, args.GetBoolArg("-drivechainenforcerremote", false));
        // Compatibility endpoints must identify the same authenticated enforcer.
        case 9: return args.IsArgSet("-drivechainpegoutenforcer");
        case 20: return args.GetArg("-drivechainpegoutenforcer","")==config.address;
        case 11: return args.IsArgSet("-drivechainbmmwalletaddr");
        case 21: return args.GetArg("-drivechainbmmwalletaddr","")==config.address;
        case 13: return !args.IsArgSet("-drivechainbmmconnectauthcookie");
        case 15: return text.authority_characters;
        case 17: return ValidateReadableRegularFile(config.ca_certificate,false,error);
        case 18: return ValidateReadableRegularFile(config.client_certificate,false,error);
        case 19: return ValidateReadableRegularFile(config.client_key,true,error);
        default: throw std::logic_error("invalid enforcer TLS configuration action");
        }
    }) != 0;
}

BoundedCommandResult RunAuthenticatedDrivechainGrpc(
    const ArgsManager& args,
    const std::string& method,
    const std::string& json_payload,
    const std::chrono::milliseconds timeout,
    const size_t max_output,
    const std::function<bool()>& should_cancel)
{
    BoundedCommandResult failure;
    std::string config_error;
    UniValue parsed_payload;
    drivechain::haskell::ParentReplayStore(drivechain::haskell::ReplayStoreFlow::GRPC_REQUEST_ADMISSION,
        [&](uint32_t action) -> uint32_t {
        switch (action) {
        case 1:
            try {
                // Keep method rejection ahead of payload size/JSON validation.
                drivechain::haskell::GrpcPlan(std::array<std::string,1>{method});
                return 1;
            } catch (const std::invalid_argument&) { return 0; }
        case 2: failure.error = "refusing an unrecognized enforcer gRPC method"; return 1;
        case 11: return std::min<size_t>(method.size(),UINT32_MAX);
        case 12: return std::min<size_t>(json_payload.size(),UINT32_MAX);
        case 4: failure.error = "enforcer gRPC payload must contain 1..1048576 bytes"; return 1;
        case 5: return parsed_payload.read(json_payload) && parsed_payload.isObject();
        case 6: failure.error = "enforcer gRPC payload must be one JSON object"; return 1;
        case 7: return ValidateDrivechainGrpcTLSConfig(args, &config_error);
        case 8:
            config_error = "invalid enforcer gRPC deadline or output bound";
            return timeout.count() > 0 && timeout.count() <= 600000 && max_output > 0 && max_output <= 16777216;
        case 9: failure.error = config_error; return 1;
        case 10: break;
        default: throw std::logic_error("invalid enforcer gRPC request action");
        }
        const DrivechainGrpcTLSConfig config = GetDrivechainGrpcTLSConfig(args);
        const auto reply=drivechain::haskell::GrpcRequest(std::array<std::string,7>{
            method,json_payload,config.address,
            fs::PathToString(config.ca_certificate),fs::PathToString(config.client_certificate),
            fs::PathToString(config.client_key),config.authority}, timeout.count(), max_output, should_cancel);
        failure.started = true;
        failure.exited = true;
        failure.exit_code = reply.status;
        failure.cancelled = reply.status == -2;
        failure.timed_out = reply.status == -3;
        failure.output_truncated = reply.status == -4;
        if (reply.status < 0) failure.error = reply.output;
        else failure.output = reply.output;
        return 1;
    });
    return failure;
}

BoundedCommandResult RunAuthenticatedDrivechainGrpc(
    const std::string& method,
    const std::string& json_payload,
    const std::chrono::milliseconds timeout,
    const size_t max_output,
    const std::function<bool()>& should_cancel)
{
    return RunAuthenticatedDrivechainGrpc(
        gArgs, method, json_payload, timeout, max_output, should_cancel);
}


std::string GetDrivechainGrpcAddress(const ArgsManager& args)
{
    return GetDrivechainGrpcTLSConfig(args).address;
}

bool ValidateNativeDrivechainRpcServerConfig(const ArgsManager& args,
                                             std::string* error)
{
    if (error) error->clear();
    int64_t configured_port{0};
    std::vector<std::string> bindings;
    std::string host;
    size_t index{0};
    return drivechain::haskell::ParentReplayStore(drivechain::haskell::ReplayStoreFlow::RPC_SERVER,
        [&](uint32_t action) -> uint32_t {
        switch (action) {
        case 1: return args.GetBoolArg("-rest", false);
        case 2:
            if (error) *error = "unauthenticated REST is not permitted on a native drivechain node";
            return 1;
        case 3:
            configured_port = args.GetIntArg("-rpcport", BaseParams().RPCPort());
            return drivechain::haskell::DepositPreflight(0,configured_port,65535);
        case 4:
            if (error) *error = "-rpcport must be between 1 and 65535";
            return 1;
        case 5: bindings = args.GetArgs("-rpcbind"); return 1;
        case 6: return index<bindings.size();
        case 7: {
            uint16_t port = static_cast<uint16_t>(configured_port);
            SplitHostPort(bindings.at(index),port,host);
            return (port!=0) | (!host.empty() << 1);
        }
        case 10: return IsMainchainRPCHostAllowed(host, /*native_drivechain=*/true);
        case 8:
            if (error) *error = strprintf("native drivechain JSON-RPC requires a numeric IPv4 127/8 or IPv6 ::1 binding, not %s",bindings.at(index));
            return 1;
        case 9: ++index; return 1;
        default: throw std::logic_error("invalid RPC server configuration action");
        }
    }) != 0;
}
