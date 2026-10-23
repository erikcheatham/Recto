using System.Collections.Generic;
using System.Text.Json.Serialization;

namespace Recto.Shared.Protocol.V04;

/// <summary>
/// The user-vault grant request a platform raised on this phone (kinds
/// <c>user_vault_grant</c> / <c>user_vault_revoke</c>, hard rule 15.z).
/// The record fields are the PROPOSAL the phone signs from: the phone
/// adds the nonce and may shorten <see cref="NotAfter"/>, never lengthen
/// it. <see cref="Purpose"/> and <see cref="AgentName"/> are the
/// service's words: shown on the card, labelled as the service's, never
/// signed, and dropped with the card (hard rule 15.y).
/// </summary>
public sealed record UserVaultGrantContext(
    [property: JsonPropertyName("action")] string Action,
    [property: JsonPropertyName("bootloader_id")] string BootloaderId,
    [property: JsonPropertyName("consumer")] string Consumer,
    [property: JsonPropertyName("subject")] string Subject,
    [property: JsonPropertyName("agent_handle")] string AgentHandle,
    [property: JsonPropertyName("key")] string Key,
    [property: JsonPropertyName("scope")] string Scope,
    [property: JsonPropertyName("not_after")] long NotAfter,
    [property: JsonPropertyName("expires_at_unix")] long ExpiresAtUnix,
    [property: JsonPropertyName("grant_id")] string? GrantId = null,
    [property: JsonPropertyName("admitted_at_unix")] long? AdmittedAtUnix = null,
    [property: JsonPropertyName("purpose")] string? Purpose = null,
    [property: JsonPropertyName("agent_name")] string? AgentName = null);

/// <summary>A phone-signed user-vault record: POST /v0.4/user-vault/grant, /revoke, /revoke-key.</summary>
public sealed record UserVaultSignedRecord(
    [property: JsonPropertyName("record")] IReadOnlyDictionary<string, object?> Record,
    [property: JsonPropertyName("signature_b64u")] string SignatureB64u);

/// <summary>A phone-signed grants-list read: POST /v0.4/user-vault/grants (hard rule 15.aa).</summary>
public sealed record UserVaultGrantsListRequest(
    [property: JsonPropertyName("request")] IReadOnlyDictionary<string, object?> Request,
    [property: JsonPropertyName("signature_b64u")] string SignatureB64u);

public sealed record UserVaultGrantAdmitted(
    [property: JsonPropertyName("status")] string Status,
    [property: JsonPropertyName("grant_id")] string GrantId,
    [property: JsonPropertyName("not_after")] long NotAfter);

public sealed record UserVaultRevokeResponse(
    [property: JsonPropertyName("revoked")] bool Revoked,
    [property: JsonPropertyName("grant_id")] string GrantId);

public sealed record UserVaultRevokeKeyResponse(
    [property: JsonPropertyName("revoked")] IReadOnlyList<string> Revoked);

public sealed record UserVaultDenyResponse(
    [property: JsonPropertyName("denied")] bool Denied);

/// <summary>One live grant as Recto holds it: handles, key, scope, dates - no display name (Recto never holds one).</summary>
public sealed record UserVaultGrantRow(
    [property: JsonPropertyName("grant_id")] string GrantId,
    [property: JsonPropertyName("consumer")] string Consumer,
    [property: JsonPropertyName("subject")] string Subject,
    [property: JsonPropertyName("agent_handle")] string AgentHandle,
    [property: JsonPropertyName("key")] string Key,
    [property: JsonPropertyName("scope")] string Scope,
    [property: JsonPropertyName("not_after")] long NotAfter,
    [property: JsonPropertyName("admitted_at_unix")] long? AdmittedAtUnix = null);

public sealed record UserVaultGrantsListResponse(
    [property: JsonPropertyName("grants")] IReadOnlyList<UserVaultGrantRow> Grants,
    [property: JsonPropertyName("bootloader_id")] string BootloaderId);
