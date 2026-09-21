using System.Collections.Generic;
using System.Text;
using Recto.Shared.Capability;
using Xunit;

namespace Recto.Shared.Tests.Capability;

/// <summary>
/// Pins canonical-JSON byte output against Python's
/// <c>json.dumps(obj, sort_keys=True, separators=(",", ":"),
/// ensure_ascii=True)</c>. Cross-language signature verification depends
/// on byte-identical canonical JSON; if these tests drift from Python's
/// pinned outputs in <c>tests/test_capability.py</c>, capability JWTs
/// minted on one runtime will fail to verify on the other.
/// <para>
/// Mirrors the Python tests
/// <c>test_canonical_json_sorts_keys</c> /
/// <c>test_canonical_json_minimal_separators</c> /
/// <c>test_canonical_json_unicode</c> &mdash; same input, same expected
/// byte sequence pinned as a literal string.
/// </para>
/// </summary>
public class CanonicalJsonTests
{
    private static byte[] Encode(object? value) => CanonicalJson.Encode(value);

    [Fact]
    public void Encode_SortsObjectKeysAscending()
    {
        // Python pin: _canonical_json({"b": 1, "a": 2}) == b'{"a":2,"b":1}'
        var input = new Dictionary<string, object?>
        {
            ["b"] = 1L,
            ["a"] = 2L,
        };
        var bytes = Encode(input);
        Assert.Equal("{\"a\":2,\"b\":1}", Encoding.UTF8.GetString(bytes));
    }

    [Fact]
    public void Encode_OutputsMinimalSeparators()
    {
        // Python pin: _canonical_json({"a": 1, "b": [1, 2, 3]}) ==
        //   b'{"a":1,"b":[1,2,3]}'
        var input = new Dictionary<string, object?>
        {
            ["a"] = 1L,
            ["b"] = new List<object?> { 1L, 2L, 3L },
        };
        var bytes = Encode(input);
        Assert.Equal("{\"a\":1,\"b\":[1,2,3]}", Encoding.UTF8.GetString(bytes));
    }

    [Fact]
    public void Encode_NoWhitespace()
    {
        var input = new Dictionary<string, object?>
        {
            ["a"] = 1L,
            ["b"] = new List<object?> { 1L, 2L, 3L },
        };
        var bytes = Encode(input);
        var s = Encoding.UTF8.GetString(bytes);
        Assert.DoesNotContain(" ", s);
        Assert.DoesNotContain("\t", s);
        Assert.DoesNotContain("\n", s);
    }

    [Fact]
    public void Encode_EscapesUnicodeWithLowercaseHex()
    {
        // Python pin: _canonical_json({"x": "café"}) == b'{"x":"caf\\u00e9"}'
        // (the é in the b'' literal is the two-byte text é, not
        // an actual U+00E9 char — Python's json.dumps escapes non-ASCII
        // as \uXXXX with lowercase hex when ensure_ascii=True, the default).
        var input = new Dictionary<string, object?>
        {
            ["x"] = "café",
        };
        var bytes = Encode(input);
        Assert.Equal("{\"x\":\"caf\\u00e9\"}", Encoding.UTF8.GetString(bytes));
    }

    [Fact]
    public void Encode_PreservesAsciiPrintableUnescaped()
    {
        // Forward slash is NOT escaped in Python's json.dumps (it's not in
        // the always-escape set). STJ would escape it by default; our
        // encoder must NOT.
        var input = new Dictionary<string, object?>
        {
            ["path"] = "https://example.com/foo",
        };
        var bytes = Encode(input);
        var s = Encoding.UTF8.GetString(bytes);
        Assert.Contains("https://example.com/foo", s);
        Assert.DoesNotContain("\\/", s);
    }

    [Fact]
    public void Encode_EscapesShortFormControlChars()
    {
        // \b \f \n \r \t use the two-char escape forms.
        var input = new Dictionary<string, object?>
        {
            ["s"] = "a\nb\tc\rd\bf\fg",
        };
        var bytes = Encode(input);
        var s = Encoding.UTF8.GetString(bytes);
        Assert.Equal("{\"s\":\"a\\nb\\tc\\rd\\bf\\fg\"}", s);
    }

    [Fact]
    public void Encode_EscapesQuoteAndBackslash()
    {
        var input = new Dictionary<string, object?>
        {
            ["s"] = "a\"b\\c",
        };
        var bytes = Encode(input);
        Assert.Equal("{\"s\":\"a\\\"b\\\\c\"}", Encoding.UTF8.GetString(bytes));
    }

    [Fact]
    public void Encode_EscapesOtherControlCharsAsLowercaseHex()
    {
        // 0x01 has no two-char escape; must emit  (lowercase).
        var input = new Dictionary<string, object?>
        {
            ["s"] = "\x01",
        };
        var bytes = Encode(input);
        Assert.Equal("{\"s\":\"\\u0001\"}", Encoding.UTF8.GetString(bytes));
    }

    [Fact]
    public void Encode_EmptyObjectAndArray()
    {
        Assert.Equal("{}", Encoding.UTF8.GetString(
            Encode(new Dictionary<string, object?>())));
        Assert.Equal("[]", Encoding.UTF8.GetString(
            Encode(new List<object?>())));
    }

    [Fact]
    public void Encode_NullAndBoolean()
    {
        var input = new Dictionary<string, object?>
        {
            ["a"] = null,
            ["b"] = true,
            ["c"] = false,
        };
        var bytes = Encode(input);
        Assert.Equal("{\"a\":null,\"b\":true,\"c\":false}",
            Encoding.UTF8.GetString(bytes));
    }

    [Fact]
    public void Encode_NestedSorting()
    {
        // Sort applies recursively at every object level.
        var input = new Dictionary<string, object?>
        {
            ["z"] = new Dictionary<string, object?>
            {
                ["b"] = 2L,
                ["a"] = 1L,
            },
            ["a"] = 1L,
        };
        var bytes = Encode(input);
        Assert.Equal("{\"a\":1,\"z\":{\"a\":1,\"b\":2}}",
            Encoding.UTF8.GetString(bytes));
    }

    // -----------------------------------------------------------------
    // Base64url helpers (CapabilityJws.Base64UrlEncode/Decode public
    // surface — RFC 7515 §2 conformance).
    // -----------------------------------------------------------------

    [Fact]
    public void Base64Url_NoPadding()
    {
        // RFC 7515 base64url MUST NOT include trailing '=' padding.
        Assert.DoesNotContain("=", CapabilityJws.Base64UrlEncode(new byte[] { 0x78 }));
        Assert.DoesNotContain("=",
            CapabilityJws.Base64UrlEncode(new byte[] { 0x78, 0x79 }));
        Assert.DoesNotContain("=",
            CapabilityJws.Base64UrlEncode(new byte[] { 0x78, 0x79, 0x7A }));
    }

    [Fact]
    public void Base64Url_RoundTrip()
    {
        byte[][] cases =
        {
            System.Array.Empty<byte>(),
            new byte[] { 0x78 },
            Encoding.UTF8.GetBytes("hello world"),
        };
        // 0..255 byte sweep
        var sweep = new byte[256];
        for (int i = 0; i < 256; i++) sweep[i] = (byte)i;
        var allCases = new System.Collections.Generic.List<byte[]>(cases) { sweep };
        foreach (var data in allCases)
        {
            var encoded = CapabilityJws.Base64UrlEncode(data);
            var decoded = CapabilityJws.Base64UrlDecode(encoded);
            Assert.Equal(data, decoded);
        }
    }

    [Fact]
    public void Base64Url_DecodesUnpaddedInput()
    {
        // 'aGVsbG8' is base64url for 'hello' (5 bytes — would normally
        // need '=' padding to 8 chars; our decoder restores it).
        var decoded = CapabilityJws.Base64UrlDecode("aGVsbG8");
        Assert.Equal(Encoding.UTF8.GetBytes("hello"), decoded);
    }
}
