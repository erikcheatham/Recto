using System.Threading;
using System.Threading.Tasks;
using Recto.Shared.Common;
using Recto.Shared.Protocol.V04;

namespace Recto.Shared.Services;

/// <summary>
/// Thin client over the Recto bootloader's HTTPS surface. Per-call
/// <c>bootloaderUrl</c> rather than a baked-in BaseAddress so a single
/// instance can talk to whichever bootloader the operator points it at.
/// </summary>
public interface IBootloaderClient
{
    /// <summary>
    /// Pairing-flow step 1: phone -&gt; bootloader exchange of a
    /// 6-digit pairing code for a fresh challenge to sign.
    /// </summary>
    Task<Result<RegistrationChallengeResponse>> GetRegistrationChallengeAsync(
        string bootloaderUrl, string pairingCode, CancellationToken ct);

    /// <summary>
    /// Pairing-flow step 2: phone -&gt; bootloader registration with
    /// the public key + signed challenge. Bootloader stores the public
    /// key + algorithm and returns the list of managed secrets the
    /// operator has authorized this phone to gate.
    /// </summary>
    Task<Result<RegistrationResponse>> RegisterAsync(
        string bootloaderUrl, RegistrationRequest request, CancellationToken ct);

    /// <summary>
    /// Polled by the phone (every few seconds while foreground, or on
    /// push wakeup) to fetch the current list of pending sign
    /// requests for this phone. Empty list when nothing is queued.
    /// </summary>
    Task<Result<PendingRequestsResponse>> GetPendingAsync(
        string bootloaderUrl, string phoneId, CancellationToken ct);

    /// <summary>
    /// Phone's response to one pending request. <c>approved</c>
    /// includes the per-kind result field (signature_b64u for
    /// single_sign, totp_code for totp_generate, session_jwt for
    /// session_issuance); <c>denied</c> includes an optional
    /// <see cref="RespondRequest.Reason"/>.
    /// </summary>
    Task<Result<RespondResponse>> RespondAsync(
        string bootloaderUrl, string requestId, RespondRequest request, CancellationToken ct);

    /// <summary>
    /// v0.5+ phone-management: returns the list of phones registered with
    /// this bootloader OTHER than <paramref name="phoneId"/> (the caller
    /// already knows about itself). Used by the surviving phone's UI to
    /// render the "Registered phones" section.
    /// </summary>
    Task<Result<RegisteredPhonesResponse>> ListRegisteredPhonesAsync(
        string bootloaderUrl, string phoneId, CancellationToken ct);

    /// <summary>
    /// v0.5+ phone-management: fetches a single-use 60-second-TTL challenge
    /// the phone must sign as part of a revocation request. Same shape
    /// as the pairing challenge; isolating the endpoint by purpose lets
    /// the bootloader reject reuse (a pairing challenge can't be replayed
    /// to authorize a revocation).
    /// </summary>
    Task<Result<RevokeChallengeResponse>> GetRevokeChallengeAsync(
        string bootloaderUrl, string phoneId, CancellationToken ct);

    /// <summary>
    /// v0.5+ phone-management: revokes a target phone's registration.
    /// The request body includes a signature from the revoking phone
    /// over the bootloader-issued challenge; the bootloader verifies it
    /// against the revoking phone's stored public key.
    /// </summary>
    Task<Result<RevokeResponse>> RevokePhoneAsync(
        string bootloaderUrl, RevokeRequest request, CancellationToken ct);

    /// <summary>
    /// v0.5+ push-notification token rotation. The phone calls this when
    /// it detects its FCM (Android) or APNs (iOS) token has changed.
    /// Bootloader updates its per-phone push-token field in place; the
    /// next pending-request push uses the new token.
    /// </summary>
    Task<Result<PushTokenUpdateResponse>> UpdatePushTokenAsync(
        string bootloaderUrl, PushTokenUpdateRequest request, CancellationToken ct);

    /// <summary>
    /// v0.5+ audit log: returns the most-recent <paramref name="limit"/>
    /// events the bootloader has recorded for this phone, newest-first.
    /// Surfaced phone-side as a History view so the operator can verify
    /// what they've authorized recently.
    /// </summary>
    Task<Result<AuditLogResponse>> GetAuditLogAsync(
        string bootloaderUrl, string phoneId, int limit, CancellationToken ct);

    /// <summary>
    /// Phase H end-user device pairing (2026-05-19). POSTs to the
    /// bootloader's <c>/v0.4/devices/pair</c> relay endpoint with the
    /// signed JWS the phone produced in the "Pair a service" flow.
    ///
    /// <para>
    /// The bootloader is a THIN RELAY: it looks up the consumer's
    /// webhook token in its registered-consumers table (operator-
    /// registered at deploy time via the
    /// <c>devices_pair_consumer_webhook_tokens</c> launcher manifest),
    /// POSTs to <c>{ConsumerBaseUrl}/api/v1/devices/pairing/complete</c>
    /// with the looked-up <c>X-Openclaw-Token</c> header, and returns
    /// the consumer's HTTP status + JSON body verbatim. Consumer-side
    /// verification (signature recovery against the caller-supplied
    /// master pubkey, action allow-list, scope.pairing_code binding,
    /// expiry check) is the authoritative gate.
    /// </para>
    ///
    /// <para>
    /// No agent-token authentication on the incoming request — the JWS
    /// in <see cref="DevicesPairRequest.UserJws"/> IS the authentication
    /// primitive. Sister of the operator-driven capability_request flow
    /// but for end-user-fired authority binding rather than agent-fired
    /// action approval.
    /// </para>
    /// </summary>
    Task<Result<DevicesPairResponse>> PairDeviceAsync(
        string bootloaderUrl, DevicesPairRequest request, CancellationToken ct);

    /// <summary>
    /// POST <c>/v0.4/devices/unpair</c> — the cryptographic teardown of a
    /// <see cref="PairDeviceAsync"/> binding (per-service unpair v1.x).
    /// Sister of the pair relay: the phone-signed
    /// <see cref="DevicesUnpairRequest.UserJws"/> (carrying
    /// <c>allow_actions: ["devices:pairing_revoke"]</c>) IS the
    /// authentication primitive; the bootloader relays to the consumer's
    /// <c>/api/v1/devices/pairing/revoke</c> verbatim.
    /// </summary>
    Task<Result<DevicesUnpairResponse>> UnpairDeviceAsync(
        string bootloaderUrl, DevicesUnpairRequest request, CancellationToken ct);
}
