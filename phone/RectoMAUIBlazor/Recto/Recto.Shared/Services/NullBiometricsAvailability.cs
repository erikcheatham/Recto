using System.Threading;
using System.Threading.Tasks;

namespace Recto.Shared.Services;

// ---------------------------------------------------------------------------
// NullBiometricsAvailability — fallback for Windows + Mac Catalyst dev hosts.
// ---------------------------------------------------------------------------
//
// On dev hosts (Windows + Mac Catalyst), there's no hardware Secure Enclave
// or StrongBox. MauiProgram.cs registers SoftwareEnclaveKeyService on those
// platforms, which doesn't require biometric. This null impl reports
// Available so the Pair button stays enabled for dev workflows.
//
// Banked Build 5 (2026-06-02) alongside the new IBiometricsAvailability
// interface.

public sealed class NullBiometricsAvailability : IBiometricsAvailability
{
    public Task<BiometricsStatus> CheckAsync(CancellationToken ct) =>
        Task.FromResult(BiometricsStatus.Available);
}
