using System;
using System.Collections.Generic;
using System.Linq;
using System.Reflection;
using System.Text;
using System.Text.Json;
using Recto.Shared.Capability;
using Recto.Shared.Protocol.V04;
using Xunit;

namespace Recto.Shared.Tests.Capability;

/// <summary>
/// The user-vault grant and revoke cards (R-series step 3): hard rules
/// 15.x (a card that cannot render a signed field refuses to sign; the
/// window chips only shorten) and 15.y (nothing from a card persists after
/// the tap), and byte parity with the bootloader's records in
/// <c>recto/user_vault/grant_record.py</c> - the golden vectors below were
/// printed by that module.
/// </summary>
public class UserVaultCardTests
{
    private const string Subject = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
    private const string AgentHandle = "QQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQA";
    private const string Nonce = "n0nce-0123456789ab";
    private const string Consumer = "https://consumer.example";
    private const string GoldenGrantId = "bc9d1ef35513a8b33c04a04e6109ffe140e5e87fd418ea9889aedb0a0d910d01";

    private static readonly long Now = DateTimeOffset.UtcNow.ToUnixTimeSeconds();

    private static PendingRequest Card(string kind = PendingRequestKind.UserVaultGrant, string? action = null,
        long? notAfter = null, string? grantId = null, string subject = Subject, string agent = AgentHandle,
        string consumer = Consumer, string key = "user-ai-xai", long? expires = null,
        string? purpose = "answers with your own key", string? agentName = "Agent One")
    {
        var uv = new UserVaultGrantContext(
            Action: action ?? (kind == PendingRequestKind.UserVaultRevoke ? "revoke" : "grant"),
            BootloaderId: "rb1-test", Consumer: consumer, Subject: subject, AgentHandle: agent, Key: key,
            Scope: "AgentChat", NotAfter: notAfter ?? Now + 90L * 86400, ExpiresAtUnix: expires ?? Now + 300,
            GrantId: grantId ?? (kind == PendingRequestKind.UserVaultRevoke ? GoldenGrantId : null),
            Purpose: purpose, AgentName: agentName);
        var ctx = new PendingRequestContext(0, "", Now, "user-vault grant", UserVaultGrant: uv);
        return new PendingRequest("uvreq-1", kind, consumer, key, ctx);
    }

    private static UserVaultCardModel Build(PendingRequest req)
        => UserVaultCardModel.TryBuild(req, Now, out var refusal) ?? throw new Xunit.Sdk.XunitException(refusal);

    // ---- parity with the bootloader --------------------------------------------------------------------------

    [Fact]
    public void Grant_record_signs_the_bootloaders_exact_bytes_and_id()
    {
        var model = Build(Card(notAfter: 1800000000));
        var rec = model.GrantRecord(1800000000, Nonce);
        Assert.Equal(GoldenGrantId, UserVaultCardModel.GrantIdOf(rec));
        Assert.Equal(
            "recto-user-vault-grant-v1|{\"agent_handle\":\"" + AgentHandle + "\",\"bootloader_id\":\"rb1-test\","
            + "\"consumer\":\"https://consumer.example\",\"key\":\"user-ai-xai\",\"nonce\":\"" + Nonce + "\","
            + "\"not_after\":1800000000,\"scope\":\"AgentChat\",\"subject\":\"" + Subject + "\"}",
            Encoding.UTF8.GetString(UserVaultCardModel.SignedMessage(UserVaultCardModel.GrantPrefix, rec)));
    }

    [Fact]
    public void Revoke_revoke_key_and_list_records_match_the_bootloader()
    {
        Assert.Equal(
            "recto-user-vault-revoke-v1|{\"bootloader_id\":\"rb1-test\",\"consumer\":\"https://consumer.example\","
            + "\"grant_id\":\"" + GoldenGrantId + "\",\"nonce\":\"" + Nonce + "\",\"subject\":\"" + Subject + "\"}",
            Encoding.UTF8.GetString(UserVaultCardModel.SignedMessage(UserVaultCardModel.RevokePrefix,
                UserVaultCardModel.BuildRevokeRecord("rb1-test", Consumer, Subject, GoldenGrantId, Nonce))));
        Assert.Equal(
            "recto-user-vault-revoke-key-v1|{\"bootloader_id\":\"rb1-test\",\"consumer\":\"https://consumer.example\","
            + "\"key\":\"user-ai-xai\",\"nonce\":\"" + Nonce + "\",\"not_after\":1800000000,\"subject\":\"" + Subject + "\"}",
            Encoding.UTF8.GetString(UserVaultCardModel.SignedMessage(UserVaultCardModel.RevokeKeyPrefix,
                UserVaultCardModel.BuildRevokeKeyRecord("rb1-test", Consumer, Subject, "user-ai-xai", 1800000000, Nonce))));
        Assert.Equal(
            "recto-user-vault-grants-v1|{\"bootloader_id\":\"rb1-test\",\"issued_at\":1800000000,\"nonce\":\"" + Nonce
            + "\",\"phone_id\":\"pk_0123456789abcdef\"}",
            Encoding.UTF8.GetString(UserVaultCardModel.SignedMessage(UserVaultCardModel.GrantsListPrefix,
                UserVaultCardModel.BuildGrantsListRequest("rb1-test", "pk_0123456789abcdef", 1800000000, Nonce))));
    }

    [Fact]
    public void The_wire_card_deserializes_from_the_bootloaders_shape()
    {
        var json = "{\"request_id\":\"uvreq-1\",\"kind\":\"user_vault_grant\",\"service\":\"" + Consumer + "\","
            + "\"secret\":\"user-ai-xai\",\"context\":{\"child_pid\":0,\"child_argv0\":\"\",\"requested_at_unix\":1,"
            + "\"operation_description\":\"user-vault grant\",\"user_vault_grant\":{\"action\":\"grant\","
            + "\"bootloader_id\":\"rb1-test\",\"consumer\":\"" + Consumer + "\",\"subject\":\"" + Subject + "\","
            + "\"agent_handle\":\"" + AgentHandle + "\",\"key\":\"user-ai-xai\",\"scope\":\"AgentChat\","
            + "\"not_after\":1800000000,\"expires_at_unix\":1800000300,\"purpose\":\"p\",\"agent_name\":\"n\"}}}";
        var req = JsonSerializer.Deserialize<PendingRequest>(json)!;
        Assert.Equal(PendingRequestKind.UserVaultGrant, req.Kind);
        Assert.Equal(AgentHandle, req.Context.UserVaultGrant!.AgentHandle);
        Assert.Equal("n", req.Context.UserVaultGrant.AgentName);
    }

    // ---- hard rule 15.x: a card that cannot render a signed field refuses to sign -------------------------------

    [Fact]
    public void Rule15x_every_signed_field_of_a_grant_is_a_row()
    {
        var model = Build(Card());
        var rec = model.GrantRecord(model.ProposedNotAfter, Nonce);
        var rows = UserVaultCardModel.RowsFor(rec)!;
        Assert.Equal(rec.Keys.OrderBy(k => k, StringComparer.Ordinal),
                     rows.Select(r => r.Field).OrderBy(k => k, StringComparer.Ordinal));
    }

    [Fact]
    public void Rule15x_every_signed_field_of_a_revoke_is_a_row()
    {
        var model = Build(Card(PendingRequestKind.UserVaultRevoke));
        var rec = model.RevokeRecord(Nonce);
        Assert.Equal(rec.Count, UserVaultCardModel.RowsFor(rec)!.Count);
    }

    [Fact]
    public void Rule15x_a_field_with_no_renderer_refuses_the_whole_card()
    {
        var model = Build(Card());
        var rec = new Dictionary<string, object?>(model.GrantRecord(model.ProposedNotAfter, Nonce)) { ["extra"] = "x" };
        Assert.Null(UserVaultCardModel.RowsFor(rec));
    }

    [Theory]
    [InlineData("not-a-handle", AgentHandle, Consumer, "user-ai-xai")]
    [InlineData(Subject, "QQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQB", Consumer, "user-ai-xai")] // not canonical
    [InlineData(Subject, AgentHandle, "http://consumer.example", "user-ai-xai")]                // plain http, not loopback
    [InlineData(Subject, AgentHandle, Consumer, "User AI")]
    public void Rule15x_a_value_that_cannot_be_shown_offers_no_card(string subject, string agent, string consumer, string key)
    {
        Assert.Null(UserVaultCardModel.TryBuild(Card(subject: subject, agent: agent, consumer: consumer, key: key),
            Now, out var refusal));
        Assert.False(string.IsNullOrEmpty(refusal));
    }

    [Fact]
    public void Rule15x_a_kind_and_action_that_disagree_offer_no_card()
    {
        Assert.Null(UserVaultCardModel.TryBuild(Card(PendingRequestKind.UserVaultGrant, action: "revoke"), Now, out _));
    }

    [Fact]
    public void Rule15x_a_closed_window_or_a_proposal_past_the_cap_offers_no_card()
    {
        Assert.Null(UserVaultCardModel.TryBuild(Card(expires: Now - 1), Now, out _));
        Assert.Null(UserVaultCardModel.TryBuild(Card(notAfter: Now + UserVaultCardModel.GrantMaxSeconds + 3600), Now, out _));
        Assert.Null(UserVaultCardModel.TryBuild(Card(notAfter: Now - 1), Now, out _));
    }

    [Fact]
    public void Rule15x_the_chips_only_shorten_the_proposal()
    {
        var model = Build(Card(notAfter: Now + 45L * 86400));
        var choices = model.WindowChoices(Now);
        Assert.Equal(Now + 45L * 86400, choices[0]);
        Assert.All(choices, t => Assert.True(t <= model.ProposedNotAfter));
        Assert.Equal(new[] { Now + 45L * 86400, Now + 30L * 86400, Now + 7L * 86400 }, choices);
        Assert.Throws<ArgumentOutOfRangeException>(() => model.GrantRecord(model.ProposedNotAfter + 1, Nonce));
    }

    [Fact]
    public void Rule15x_the_services_words_are_never_signed()
    {
        var model = Build(Card(purpose: "PURPOSE-MARK", agentName: "NAME-MARK"));
        var message = Encoding.UTF8.GetString(
            UserVaultCardModel.SignedMessage(UserVaultCardModel.GrantPrefix, model.GrantRecord(model.ProposedNotAfter, Nonce)));
        Assert.DoesNotContain("PURPOSE-MARK", message);
        Assert.DoesNotContain("NAME-MARK", message);
    }

    // ---- hard rule 15.y: nothing from a card persists after the tap ---------------------------------------------

    [Fact]
    public void Rule15y_drop_clears_the_services_words()
    {
        var model = Build(Card());
        Assert.Equal("Agent One", model.AgentName);
        model.Drop();
        Assert.Null(model.AgentName);
        Assert.Null(model.Purpose);
        Assert.True(model.IsDropped);
    }

    [Fact]
    public void Rule15y_the_card_and_its_views_take_no_storage()
    {
        // The model has no dependencies at all; the two components inject only the bootloader client and the
        // enclave key service. A storage service (pairing, registry, preferences, secure storage) never reaches them.
        Assert.Empty(typeof(UserVaultCardModel).GetConstructors(BindingFlags.Public | BindingFlags.Instance));
        var asm = typeof(UserVaultCardModel).Assembly;
        foreach (var name in new[] { "Recto.Shared.Pages.UserVaultCardView", "Recto.Shared.Pages.UserVaultGrantsPanel" })
        {
            var t = asm.GetType(name) ?? throw new Xunit.Sdk.XunitException($"{name} not found");
            var injected = t.GetProperties(BindingFlags.NonPublic | BindingFlags.Public | BindingFlags.Instance)
                .Where(p => p.GetCustomAttributes().Any(a => a.GetType().Name == "InjectAttribute"))
                .Select(p => p.PropertyType.Name)
                .OrderBy(n => n, StringComparer.Ordinal)
                .ToArray();
            Assert.Equal(new[] { "IBootloaderClient", "IEnclaveKeyService" }, injected);
        }
    }
}
