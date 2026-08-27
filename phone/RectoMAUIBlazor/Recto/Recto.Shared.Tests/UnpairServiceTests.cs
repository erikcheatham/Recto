using System;
using System.Collections.Generic;
using System.Threading;
using System.Threading.Tasks;
using Recto.Shared.Common;
using Recto.Shared.Models;
using Recto.Shared.Services;
using Xunit;

namespace Recto.Shared.Tests;

/// <summary>
/// The unpair-all guard's red-build suite: a genesis member's key must be
/// unreachable by the full wipe. Remove the guard from UnpairService and
/// the first three tests go red by construction — that is their job.
/// </summary>
public class UnpairServiceTests
{
    private const string Alias = "recto.phone.identity";

    // ── fakes ────────────────────────────────────────────────────────────

    private sealed class FakeGenesisState : IGenesisStateService
    {
        public bool? Member;              // null => the read FAILS
        public Task<Result<bool>> IsGenesisMemberAsync(CancellationToken ct)
            => Task.FromResult(Member is null
                ? Result.Failure<bool>(Error.Failure("storage unreadable"))
                : Result.Success(Member.Value));
        public Task<Result> MarkGenesisMemberAsync(string id, CancellationToken ct)
            => Task.FromResult(Result.Success());
        public Task<Result> ClearAsync(CancellationToken ct)
            => Task.FromResult(Result.Success());
    }

    private sealed class FakePairingState : IPairingStateService
    {
        public List<string> Calls = new();
        public Task<Result<PairingState?>> GetCurrentAsync(CancellationToken ct)
            => Task.FromResult(Result.Success<PairingState?>(null));
        public Task<Result> SaveAsync(PairingState state, CancellationToken ct)
        {
            Calls.Add(state is null ? "save(null)" : "save");
            return Task.FromResult(Result.Success());
        }
        public Task<Result> ClearAsync(CancellationToken ct)
        {
            Calls.Add("clear");
            return Task.FromResult(Result.Success());
        }
        public Task<Result<string>> GetOrCreatePhoneIdAsync(CancellationToken ct)
            => Task.FromResult(Result.Success("phone-id"));
    }

    private sealed class FakeTotp : ITotpService
    {
        public int ClearAllCalls;
        public Task<Result> ProvisionAsync(string a, string s, int p, int d, string alg, CancellationToken ct)
            => Task.FromResult(Result.Success());
        public Task<Result<bool>> ExistsAsync(string a, CancellationToken ct)
            => Task.FromResult(Result.Success(false));
        public Task<Result<string>> GenerateAsync(string a, CancellationToken ct)
            => Task.FromResult(Result.Success("000000"));
        public Task<Result> DeleteAsync(string a, CancellationToken ct)
            => Task.FromResult(Result.Success());
        public Task<Result> ClearAllAsync(CancellationToken ct)
        {
            ClearAllCalls++;
            return Task.FromResult(Result.Success());
        }
    }

    private sealed class FakeEnclaveKeys : IEnclaveKeyService
    {
        public List<string> Deleted = new();
        public string Algorithm => "ecdsa-p256";
        public Task<Result<EnclavePublicKey>> GenerateAsync(string keyAlias, CancellationToken ct)
            => throw new NotSupportedException();
        public Task<Result<bool>> KeyExistsAsync(string keyAlias, CancellationToken ct)
            => Task.FromResult(Result.Success(true));
        public Task<Result<EnclavePublicKey>> GetPublicKeyAsync(string keyAlias, CancellationToken ct)
            => throw new NotSupportedException();
        public Task<Result<byte[]>> SignAsync(string keyAlias, byte[] message, CancellationToken ct)
            => throw new NotSupportedException();
        public Task<Result> DeleteAsync(string keyAlias, CancellationToken ct)
        {
            Deleted.Add(keyAlias);
            return Task.FromResult(Result.Success());
        }
    }

    private static (UnpairService Sut, FakeGenesisState Genesis, FakePairingState Pairing, FakeTotp Totp, FakeEnclaveKeys Keys) Build(bool? member)
    {
        var genesis = new FakeGenesisState { Member = member };
        var pairing = new FakePairingState();
        var totp = new FakeTotp();
        var keys = new FakeEnclaveKeys();
        return (new UnpairService(pairing, totp, keys, genesis), genesis, pairing, totp, keys);
    }

    // ── the guard (red-builds the violation) ─────────────────────────────

    [Fact]
    public async Task GenesisMember_Refuses_AndTouchesNothing()
    {
        var (sut, _, pairing, totp, keys) = Build(member: true);

        var result = await sut.UnpairAllAsync(Alias, CancellationToken.None);

        Assert.Equal(UnpairAllStatus.RefusedGenesisMember, result.Status);
        Assert.Empty(keys.Deleted);          // the enclave key was NOT deleted
        Assert.Empty(pairing.Calls);         // pairing record untouched
        Assert.Equal(0, totp.ClearAllCalls); // secrets untouched
    }

    [Fact]
    public async Task GenesisMember_RefusalNamesTheRecoveryCeremony()
    {
        var (sut, _, _, _, _) = Build(member: true);

        var result = await sut.UnpairAllAsync(Alias, CancellationToken.None);

        // The refusal must NAME the ceremony: a refusal without a route
        // gets worked around, not respected.
        Assert.NotNull(result.Message);
        Assert.Contains("recovery ceremony", result.Message);
        Assert.Contains("recovery phrase", result.Message);
        Assert.Contains("re-enrol", result.Message);
    }

    [Fact]
    public async Task UnreadableMembership_FailsClosed_RefusesAndTouchesNothing()
    {
        var (sut, _, pairing, totp, keys) = Build(member: null); // read FAILS

        var result = await sut.UnpairAllAsync(Alias, CancellationToken.None);

        Assert.Equal(UnpairAllStatus.RefusedGenesisMember, result.Status);
        Assert.Empty(keys.Deleted);
        Assert.Empty(pairing.Calls);
        Assert.Equal(0, totp.ClearAllCalls);
    }

    // ── the pre-genesis path (today's behavior, preserved) ───────────────

    [Fact]
    public async Task NonMember_WipeCompletes_InTheHistoricalOrder()
    {
        var (sut, _, pairing, totp, keys) = Build(member: false);

        var result = await sut.UnpairAllAsync(Alias, CancellationToken.None);

        Assert.Equal(UnpairAllStatus.Completed, result.Status);
        // Order preserved from the pre-guard sequence: pairing cleared
        // FIRST (via the historical SaveAsync(null)), then TOTP, then the
        // enclave key — so in-flight poll loops see "no longer paired"
        // before their backing keys go.
        Assert.Equal(new[] { "save(null)" }, pairing.Calls);
        Assert.Equal(1, totp.ClearAllCalls);
        Assert.Equal(new[] { Alias }, keys.Deleted);
    }

    [Fact]
    public async Task NonMember_KeyDeletionFailure_ReportsFailed()
    {
        var genesis = new FakeGenesisState { Member = false };
        var pairing = new FakePairingState();
        var totp = new FakeTotp();
        var keys = new ThrowingEnclaveKeys();
        var sut = new UnpairService(pairing, totp, keys, genesis);

        var result = await sut.UnpairAllAsync(Alias, CancellationToken.None);

        Assert.Equal(UnpairAllStatus.Failed, result.Status);
        Assert.NotNull(result.Message);
    }

    private sealed class ThrowingEnclaveKeys : IEnclaveKeyService
    {
        public string Algorithm => "ecdsa-p256";
        public Task<Result<EnclavePublicKey>> GenerateAsync(string keyAlias, CancellationToken ct)
            => throw new NotSupportedException();
        public Task<Result<bool>> KeyExistsAsync(string keyAlias, CancellationToken ct)
            => Task.FromResult(Result.Success(true));
        public Task<Result<EnclavePublicKey>> GetPublicKeyAsync(string keyAlias, CancellationToken ct)
            => throw new NotSupportedException();
        public Task<Result<byte[]>> SignAsync(string keyAlias, byte[] message, CancellationToken ct)
            => throw new NotSupportedException();
        public Task<Result> DeleteAsync(string keyAlias, CancellationToken ct)
            => throw new InvalidOperationException("enclave unavailable");
    }
}
