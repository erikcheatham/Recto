using System;
using System.Collections.Generic;
using System.Globalization;
using System.Text;

namespace Recto.Shared.Capability;

/// <summary>
/// Canonical JSON encoder used to build the JWS signing input for
/// capability JWTs. Produces byte-identical output to Python's
/// <c>json.dumps(obj, sort_keys=True, separators=(",", ":"),
/// ensure_ascii=True)</c> &mdash; that byte-level parity is the contract
/// that lets a JWT minted on one runtime verify on the other.
/// <para>
/// This encoder is INTENTIONALLY narrow: it handles only the value
/// types that appear in <see cref="CapabilityClaims"/> &mdash; strings,
/// non-negative integers (Python ints fit in <c>long</c> here),
/// booleans, null, lists, and nested dictionaries with string keys.
/// Doubles, dates, and arbitrary objects are not supported &mdash; we
/// don't want a footgun where a future field type silently produces
/// non-canonical output.
/// </para>
/// <para>
/// Escape rules match Python's <c>json.dumps</c> defaults:
/// <list type="bullet">
/// <item><c>"</c> &rarr; <c>\"</c></item>
/// <item><c>\</c> &rarr; <c>\\</c></item>
/// <item><c>\b \t \n \f \r</c> &rarr; the two-char escape forms</item>
/// <item>Other control chars (0x00&ndash;0x1F) &rarr; <c>\u00xx</c> lowercase</item>
/// <item>ASCII printable (0x20&ndash;0x7E) &rarr; as-is (forward slash NOT escaped)</item>
/// <item>BMP non-ASCII &rarr; <c>\uXXXX</c> lowercase</item>
/// <item>Supplementary plane &rarr; UTF-16 surrogate pair <c>\uXXXX\uXXXX</c> lowercase</item>
/// </list>
/// (Python's default <c>ensure_ascii=True</c> produces the same shape;
/// caf&eacute; serializes as <c>café</c>.)
/// </para>
/// </summary>
public static class CanonicalJson
{
    /// <summary>
    /// Encode the supplied object tree as canonical JSON bytes
    /// (UTF-8). The supported value types are: <see cref="string"/>,
    /// <see cref="long"/> / <see cref="int"/>, <see cref="bool"/>,
    /// <c>null</c>, <see cref="IReadOnlyList{T}"/> of supported values,
    /// and <see cref="IReadOnlyDictionary{TKey, TValue}"/> with
    /// <see cref="string"/> keys and supported values. Any other type
    /// throws <see cref="InvalidOperationException"/>.
    /// </summary>
    public static byte[] Encode(object? value)
    {
        var sb = new StringBuilder();
        WriteValue(sb, value);
        // The output is ASCII-only (every non-ASCII char is \u-escaped),
        // so UTF-8 and ASCII produce identical byte sequences. Use UTF-8
        // for parity with Python's .encode("utf-8") at the call site.
        return Encoding.UTF8.GetBytes(sb.ToString());
    }

    private static void WriteValue(StringBuilder sb, object? value)
    {
        switch (value)
        {
            case null:
                sb.Append("null");
                return;
            case bool b:
                sb.Append(b ? "true" : "false");
                return;
            case string s:
                WriteString(sb, s);
                return;
            case int i:
                sb.Append(i.ToString(CultureInfo.InvariantCulture));
                return;
            case long l:
                sb.Append(l.ToString(CultureInfo.InvariantCulture));
                return;
            case IReadOnlyDictionary<string, object?> dict:
                WriteObject(sb, dict);
                return;
            case IReadOnlyList<object?> list:
                // Note: this case also matches IReadOnlyList<string> /
                // IReadOnlyList<TRef> for any reference type via
                // IReadOnlyList<out T> covariance &mdash; runtime ignores
                // nullable annotations, so the JIT sees IReadOnlyList<object>
                // and the cast succeeds. WriteArray's recursive WriteValue
                // dispatch handles each element by its own runtime type.
                // Value-type lists (IReadOnlyList<int> etc.) would NOT
                // match here; we don't currently use any so the explicit
                // throw in default is the right behavior.
                WriteArray(sb, list);
                return;
            default:
                throw new InvalidOperationException(
                    $"CanonicalJson does not support values of type "
                    + $"{value.GetType().FullName}. Supported: string, int, "
                    + $"long, bool, null, IReadOnlyList of reference-type "
                    + $"values, and IReadOnlyDictionary<string, object?>.");
        }
    }

    private static void WriteObject(
        StringBuilder sb,
        IReadOnlyDictionary<string, object?> dict)
    {
        // Sort keys ordinal-ascending. Python's sort_keys uses default
        // string ordering which IS ordinal for ASCII; ordinal is the
        // safe choice across runtimes.
        var sorted = new List<string>(dict.Keys);
        sorted.Sort(StringComparer.Ordinal);
        sb.Append('{');
        bool first = true;
        foreach (var key in sorted)
        {
            if (!first) sb.Append(',');
            WriteString(sb, key);
            sb.Append(':');
            WriteValue(sb, dict[key]);
            first = false;
        }
        sb.Append('}');
    }

    private static void WriteArray(
        StringBuilder sb,
        IReadOnlyList<object?> list)
    {
        sb.Append('[');
        for (int i = 0; i < list.Count; i++)
        {
            if (i > 0) sb.Append(',');
            WriteValue(sb, list[i]);
        }
        sb.Append(']');
    }

    private static void WriteString(StringBuilder sb, string value)
    {
        sb.Append('"');
        // Iterate code points. C# strings are UTF-16; surrogate pairs
        // get joined into a single int code point, then re-emitted as
        // a UTF-16 surrogate-pair escape (matching Python's escape of
        // supra-BMP code points in ensure_ascii mode).
        for (int i = 0; i < value.Length; i++)
        {
            char c = value[i];
            switch (c)
            {
                case '"':
                    sb.Append("\\\"");
                    break;
                case '\\':
                    sb.Append("\\\\");
                    break;
                case '\b':
                    sb.Append("\\b");
                    break;
                case '\f':
                    sb.Append("\\f");
                    break;
                case '\n':
                    sb.Append("\\n");
                    break;
                case '\r':
                    sb.Append("\\r");
                    break;
                case '\t':
                    sb.Append("\\t");
                    break;
                default:
                    if (c < 0x20)
                    {
                        AppendUnicodeEscape(sb, c);
                    }
                    else if (c < 0x7F)
                    {
                        // ASCII printable, including '/' (NOT escaped).
                        sb.Append(c);
                    }
                    else
                    {
                        // 0x7F (DEL) and everything above goes through
                        // \u escape. For 0x7F itself, Python escapes as
                        // ; the surrogate-pair handling below
                        // handles supplementary-plane code points.
                        if (char.IsHighSurrogate(c) && i + 1 < value.Length
                            && char.IsLowSurrogate(value[i + 1]))
                        {
                            // Emit both halves of the surrogate pair as
                            // separate \uXXXX escapes &mdash; matches
                            // Python's ensure_ascii=True for chars above
                            // U+FFFF.
                            AppendUnicodeEscape(sb, c);
                            AppendUnicodeEscape(sb, value[i + 1]);
                            i++;
                        }
                        else
                        {
                            AppendUnicodeEscape(sb, c);
                        }
                    }
                    break;
            }
        }
        sb.Append('"');
    }

    private static void AppendUnicodeEscape(StringBuilder sb, char c)
    {
        // Lowercase hex matches Python's json.dumps output.
        sb.Append("\\u");
        sb.Append(((int)c).ToString("x4", CultureInfo.InvariantCulture));
    }
}
