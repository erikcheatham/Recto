using System;
using System.Net.Http;
using System.Net.Http.Json;
using System.Text;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Extensions.Logging;
using Recto.Shared.Common;
using Recto.Shared.Protocol.V04;

namespace Recto.Shared.Services;

/// <summary>
/// HTTPS client for the Recto bootloader's v0.4 surface. Wraps the
/// typed HttpClient registered in <c>AddSharedServices</c>, maps every
/// HTTP / network outcome to a <see cref="Result{T}"/>, and never throws.
/// Cert pinning is round-3 work; today we trust whatever the system trust
/// store accepts (Cloudflare Tunnel deployments work as-is; self-signed
/// LAN bootloaders need pinning to come online).
/// </summary>
public sealed class BootloaderClient : IBootloaderClient
{
    // Build 12 multi-URL failover: connection-LEVEL failures (unreachable /
    // timed out) are the failover triggers; HTTP-level rejections are NOT
    // (a 4xx/5xx answered by THIS instance would be answered identically by
    // its siblings behind the same state store). The two message prefixes
    // below are the canonical shapes SendAsync emits for the trigger class;
    // IsNetworkUnreachable is the single discriminator callers use so the
    // strings never get matched ad-hoc elsewhere.
    private const string UnreachablePrefix = "Could not reach the bootloader";
    private const string TimedOutMessage = "Bootloader request timed out.";

    /// <summary>True when the failed <see cref="Result{T}"/> error represents
    /// a connection-level failure (candidate for multi-URL failover) rather
    /// than an HTTP-level rejection.</summary>
    public static bool IsNetworkUnreachable(Error error)
        => error.Message is { } m
           && (m.StartsWith(UnreachablePrefix, StringComparison.Ordinal)
               || m.StartsWith(TimedOutMessage, StringComparison.Ordinal));

    private readonly HttpClient _http;
    private readonly ILogger<BootloaderClient> _log;

    public BootloaderClient(HttpClient http, ILogger<BootloaderClient> log)
    {
        _http = http;
        _log = log;
    }

    public Task<Result<RegistrationChallengeResponse>> GetRegistrationChallengeAsync(
        string bootloaderUrl, string pairingCode, CancellationToken ct)
    {
        if (string.IsNullOrWhiteSpace(bootloaderUrl))
        {
            return Task.FromResult(Result.Failure<RegistrationChallengeResponse>(
                Error.Validation([new ValidationErrors("bootloaderUrl", "Bootloader URL is required.")])));
        }

        if (string.IsNullOrWhiteSpace(pairingCode))
        {
            return Task.FromResult(Result.Failure<RegistrationChallengeResponse>(
                Error.Validation([new ValidationErrors("pairingCode", "Pairing code is required.")])));
        }

        var url = $"{bootloaderUrl.TrimEnd('/')}/v0.4/registration_challenge?code={Uri.EscapeDataString(pairingCode)}";
        return SendAsync<RegistrationChallengeResponse>(HttpMethod.Get, url, body: null, ct);
    }

    public Task<Result<RegistrationResponse>> RegisterAsync(
        string bootloaderUrl, RegistrationRequest request, CancellationToken ct)
    {
        if (string.IsNullOrWhiteSpace(bootloaderUrl))
        {
            return Task.FromResult(Result.Failure<RegistrationResponse>(
                Error.Validation([new ValidationErrors("bootloaderUrl", "Bootloader URL is required.")])));
        }

        var url = $"{bootloaderUrl.TrimEnd('/')}/v0.4/register";
        return SendAsync<RegistrationResponse>(HttpMethod.Post, url, request, ct);
    }

    public Task<Result<PendingRequestsResponse>> GetPendingAsync(
        string bootloaderUrl, string phoneId, CancellationToken ct)
    {
        if (string.IsNullOrWhiteSpace(bootloaderUrl))
        {
            return Task.FromResult(Result.Failure<PendingRequestsResponse>(
                Error.Validation([new ValidationErrors("bootloaderUrl", "Bootloader URL is required.")])));
        }

        if (string.IsNullOrWhiteSpace(phoneId))
        {
            return Task.FromResult(Result.Failure<PendingRequestsResponse>(
                Error.Validation([new ValidationErrors("phoneId", "Phone ID is required.")])));
        }

        var url = $"{bootloaderUrl.TrimEnd('/')}/v0.4/pending?phone_id={Uri.EscapeDataString(phoneId)}";
        return SendAsync<PendingRequestsResponse>(HttpMethod.Get, url, body: null, ct);
    }

    public Task<Result<RespondResponse>> RespondAsync(
        string bootloaderUrl, string requestId, RespondRequest request, CancellationToken ct)
    {
        if (string.IsNullOrWhiteSpace(bootloaderUrl))
        {
            return Task.FromResult(Result.Failure<RespondResponse>(
                Error.Validation([new ValidationErrors("bootloaderUrl", "Bootloader URL is required.")])));
        }

        if (string.IsNullOrWhiteSpace(requestId))
        {
            return Task.FromResult(Result.Failure<RespondResponse>(
                Error.Validation([new ValidationErrors("requestId", "Request ID is required.")])));
        }

        var url = $"{bootloaderUrl.TrimEnd('/')}/v0.4/respond/{Uri.EscapeDataString(requestId)}";
        return SendAsync<RespondResponse>(HttpMethod.Post, url, request, ct);
    }

    public Task<Result<RegisteredPhonesResponse>> ListRegisteredPhonesAsync(
        string bootloaderUrl, string phoneId, CancellationToken ct)
    {
        if (string.IsNullOrWhiteSpace(bootloaderUrl))
        {
            return Task.FromResult(Result.Failure<RegisteredPhonesResponse>(
                Error.Validation([new ValidationErrors("bootloaderUrl", "Bootloader URL is required.")])));
        }
        if (string.IsNullOrWhiteSpace(phoneId))
        {
            return Task.FromResult(Result.Failure<RegisteredPhonesResponse>(
                Error.Validation([new ValidationErrors("phoneId", "Phone ID is required.")])));
        }

        var url = $"{bootloaderUrl.TrimEnd('/')}/v0.4/manage/phones?phone_id={Uri.EscapeDataString(phoneId)}";
        return SendAsync<RegisteredPhonesResponse>(HttpMethod.Get, url, body: null, ct);
    }

    public Task<Result<RevokeChallengeResponse>> GetRevokeChallengeAsync(
        string bootloaderUrl, string phoneId, CancellationToken ct)
    {
        if (string.IsNullOrWhiteSpace(bootloaderUrl))
        {
            return Task.FromResult(Result.Failure<RevokeChallengeResponse>(
                Error.Validation([new ValidationErrors("bootloaderUrl", "Bootloader URL is required.")])));
        }
        if (string.IsNullOrWhiteSpace(phoneId))
        {
            return Task.FromResult(Result.Failure<RevokeChallengeResponse>(
                Error.Validation([new ValidationErrors("phoneId", "Phone ID is required.")])));
        }

        // DEFECT #4 of the dead revoke lane (2026-08-23): this method aimed at
        // /v0.4/manage/revoke_challenge, an endpoint that has NEVER existed on
        // the server — it answered {"error":"unknown_endpoint"} and the client
        // failed at step 1 of every revoke, before biometric, before POST. The
        // server's revoke contract names its challenge source explicitly:
        // GET /v0.4/registration_challenge (single-use, consumed by the revoke
        // POST like any other challenge). The phone_id query is kept purely for
        // access-log attribution; the server ignores it.
        var url = $"{bootloaderUrl.TrimEnd('/')}/v0.4/registration_challenge?phone_id={Uri.EscapeDataString(phoneId)}";
        return SendAsync<RevokeChallengeResponse>(HttpMethod.Get, url, body: null, ct);
    }

    public Task<Result<RevokeResponse>> RevokePhoneAsync(
        string bootloaderUrl, RevokeRequest request, CancellationToken ct)
    {
        if (string.IsNullOrWhiteSpace(bootloaderUrl))
        {
            return Task.FromResult(Result.Failure<RevokeResponse>(
                Error.Validation([new ValidationErrors("bootloaderUrl", "Bootloader URL is required.")])));
        }

        // Route pinned by RevokeContractTests: the server handler lives at
        // /v0.4/manage/phones/revoke (server.py). This client shipped once
        // aiming at /v0.4/manage/revoke, which does not exist — the 404 was
        // swallowed into a polling-error field and overwritten by the next
        // poll, so the dead lane looked like a no-op instead of a defect.
        var url = $"{bootloaderUrl.TrimEnd('/')}/v0.4/manage/phones/revoke";
        return SendAsync<RevokeResponse>(HttpMethod.Post, url, request, ct);
    }

    public Task<Result<PushTokenUpdateResponse>> UpdatePushTokenAsync(
        string bootloaderUrl, PushTokenUpdateRequest request, CancellationToken ct)
    {
        if (string.IsNullOrWhiteSpace(bootloaderUrl))
        {
            return Task.FromResult(Result.Failure<PushTokenUpdateResponse>(
                Error.Validation([new ValidationErrors("bootloaderUrl", "Bootloader URL is required.")])));
        }

        var url = $"{bootloaderUrl.TrimEnd('/')}/v0.4/manage/push_token";
        return SendAsync<PushTokenUpdateResponse>(HttpMethod.Post, url, request, ct);
    }

    public Task<Result<AuditLogResponse>> GetAuditLogAsync(
        string bootloaderUrl, string phoneId, int limit, CancellationToken ct)
    {
        if (string.IsNullOrWhiteSpace(bootloaderUrl))
        {
            return Task.FromResult(Result.Failure<AuditLogResponse>(
                Error.Validation([new ValidationErrors("bootloaderUrl", "Bootloader URL is required.")])));
        }
        if (string.IsNullOrWhiteSpace(phoneId))
        {
            return Task.FromResult(Result.Failure<AuditLogResponse>(
                Error.Validation([new ValidationErrors("phoneId", "Phone ID is required.")])));
        }

        var url = $"{bootloaderUrl.TrimEnd('/')}/v0.4/manage/audit?phone_id={Uri.EscapeDataString(phoneId)}&limit={limit}";
        return SendAsync<AuditLogResponse>(HttpMethod.Get, url, body: null, ct);
    }

    public Task<Result<DevicesPairResponse>> PairDeviceAsync(
        string bootloaderUrl, DevicesPairRequest request, CancellationToken ct)
    {
        if (string.IsNullOrWhiteSpace(bootloaderUrl))
        {
            return Task.FromResult(Result.Failure<DevicesPairResponse>(
                Error.Validation([new ValidationErrors("bootloaderUrl", "Bootloader URL is required.")])));
        }
        if (request is null)
        {
            return Task.FromResult(Result.Failure<DevicesPairResponse>(
                Error.Validation([new ValidationErrors("request", "DevicesPairRequest is required.")])));
        }
        if (string.IsNullOrWhiteSpace(request.ConsumerBaseUrl))
        {
            return Task.FromResult(Result.Failure<DevicesPairResponse>(
                Error.Validation([new ValidationErrors("ConsumerBaseUrl", "Consumer base URL is required.")])));
        }
        if (string.IsNullOrWhiteSpace(request.PairingCode))
        {
            return Task.FromResult(Result.Failure<DevicesPairResponse>(
                Error.Validation([new ValidationErrors("PairingCode", "Pairing code is required.")])));
        }
        if (string.IsNullOrWhiteSpace(request.UserPubkeyHex))
        {
            return Task.FromResult(Result.Failure<DevicesPairResponse>(
                Error.Validation([new ValidationErrors("UserPubkeyHex", "Master pubkey hex is required.")])));
        }
        if (string.IsNullOrWhiteSpace(request.UserJws))
        {
            return Task.FromResult(Result.Failure<DevicesPairResponse>(
                Error.Validation([new ValidationErrors("UserJws", "Signed JWS is required.")])));
        }

        var url = $"{bootloaderUrl.TrimEnd('/')}/v0.4/devices/pair";
        return SendAsync<DevicesPairResponse>(HttpMethod.Post, url, request, ct);
    }

    public Task<Result<DevicesUnpairResponse>> UnpairDeviceAsync(
        string bootloaderUrl, DevicesUnpairRequest request, CancellationToken ct)
    {
        if (string.IsNullOrWhiteSpace(bootloaderUrl))
        {
            return Task.FromResult(Result.Failure<DevicesUnpairResponse>(
                Error.Validation([new ValidationErrors("bootloaderUrl", "Bootloader URL is required.")])));
        }
        if (request is null)
        {
            return Task.FromResult(Result.Failure<DevicesUnpairResponse>(
                Error.Validation([new ValidationErrors("request", "DevicesUnpairRequest is required.")])));
        }
        if (string.IsNullOrWhiteSpace(request.ConsumerBaseUrl))
        {
            return Task.FromResult(Result.Failure<DevicesUnpairResponse>(
                Error.Validation([new ValidationErrors("ConsumerBaseUrl", "Consumer base URL is required.")])));
        }
        if (string.IsNullOrWhiteSpace(request.UserPubkeyHex))
        {
            return Task.FromResult(Result.Failure<DevicesUnpairResponse>(
                Error.Validation([new ValidationErrors("UserPubkeyHex", "Master pubkey hex is required.")])));
        }
        if (string.IsNullOrWhiteSpace(request.UserJws))
        {
            return Task.FromResult(Result.Failure<DevicesUnpairResponse>(
                Error.Validation([new ValidationErrors("UserJws", "Signed JWS is required.")])));
        }

        var url = $"{bootloaderUrl.TrimEnd('/')}/v0.4/devices/unpair";
        return SendAsync<DevicesUnpairResponse>(HttpMethod.Post, url, request, ct);
    }

    private static readonly JsonSerializerOptions _serializerOptions = new()
    {
        // Honors [JsonPropertyName] on positional record properties; the default
        // (JsonContent.Create with lazy serialization) was emitting Content-Length: 0
        // bodies in this MAUI HttpClient pipeline. Pre-serializing to a string +
        // StringContent buffers the body fully so Content-Length reflects reality.
        WriteIndented = false,
    };

    private async Task<Result<T>> SendAsync<T>(
        HttpMethod method, string url, object? body, CancellationToken ct) where T : class
    {
        try
        {
            using var request = new HttpRequestMessage(method, url);
            if (body is not null)
            {
                var json = JsonSerializer.Serialize(body, body.GetType(), _serializerOptions);
                request.Content = new StringContent(json, Encoding.UTF8, "application/json");
                _log.LogInformation("Bootloader {Method} {Url} body: {Json}", method, url, json);
            }

            using var response = await _http.SendAsync(request, ct).ConfigureAwait(false);

            if (!response.IsSuccessStatusCode)
            {
                var errorBody = await response.Content.ReadAsStringAsync(ct).ConfigureAwait(false);
                _log.LogWarning(
                    "Bootloader {Method} {Url} returned {Status}: {Body}",
                    method, url, (int)response.StatusCode, Truncate(errorBody, 500));

                // Try to surface the bootloader's own error message if it
                // returned a JSON body with an "error" field. Falls back to
                // the generic HTTP status line if the body isn't JSON or
                // doesn't carry an error field. Friendlier than just
                // "HTTP 404 Not Found" when the actual cause was something
                // specific like an expired pairing code or a missing phone.
                var friendlyMessage = TryExtractServerErrorMessage(errorBody);
                if (!string.IsNullOrEmpty(friendlyMessage))
                {
                    var statusHint = (int)response.StatusCode == 404
                        ? "Not found"
                        : $"HTTP {(int)response.StatusCode}";
                    return Result.Failure<T>(Error.Failure($"{statusHint}: {friendlyMessage}"));
                }

                return Result.Failure<T>(Error.Failure(
                    $"Bootloader returned HTTP {(int)response.StatusCode} {response.ReasonPhrase}."));
            }

            var parsed = await response.Content.ReadFromJsonAsync<T>(cancellationToken: ct).ConfigureAwait(false);
            if (parsed is null)
            {
                return Result.Failure<T>(Error.Failure("Bootloader returned an empty response body."));
            }

            return Result.Success(parsed);
        }
        catch (OperationCanceledException) when (ct.IsCancellationRequested)
        {
            return Result.Failure<T>(Error.Failure("Operation was canceled."));
        }
        catch (TaskCanceledException)
        {
            return Result.Failure<T>(Error.Failure(TimedOutMessage));
        }
        catch (HttpRequestException ex)
        {
            _log.LogWarning(ex, "Bootloader {Method} {Url} network error", method, url);
            return Result.Failure<T>(Error.Failure($"{UnreachablePrefix}: {ex.Message}"));
        }
        catch (Exception ex)
        {
            _log.LogError(ex, "Bootloader {Method} {Url} unexpected error", method, url);
            return Result.Failure<T>(Error.Failure(
                $"Unexpected error contacting bootloader: {ex.GetType().Name}: {ex.Message}"));
        }
    }

    private static string Truncate(string s, int max) =>
        string.IsNullOrEmpty(s) || s.Length <= max ? s : s.Substring(0, max) + "...";

    /// <summary>
    /// Tries to parse the bootloader's error-response body as JSON and
    /// extract a meaningful message. The mock bootloader returns
    /// <c>{"error": "..."}</c> for every error path; production
    /// bootloaders SHOULD do the same. If the body isn't JSON, isn't an
    /// object, or doesn't have an <c>error</c> field, returns null and
    /// the caller falls back to the generic HTTP-status message.
    /// </summary>
    private static string? TryExtractServerErrorMessage(string body)
    {
        if (string.IsNullOrWhiteSpace(body)) return null;
        try
        {
            using var doc = JsonDocument.Parse(body);
            if (doc.RootElement.ValueKind != JsonValueKind.Object) return null;
            if (!doc.RootElement.TryGetProperty("error", out var errorProp)) return null;
            if (errorProp.ValueKind != JsonValueKind.String) return null;
            var message = errorProp.GetString();
            return string.IsNullOrWhiteSpace(message) ? null : message;
        }
        catch (JsonException)
        {
            return null;
        }
    }
}
