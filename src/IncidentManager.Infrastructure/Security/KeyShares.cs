using System.Security.Cryptography;
using System.Text;

namespace IncidentManager.Infrastructure.Security;

/// <summary>
/// PROD-57: splits a secret (the evidence key, with the audit chain key when it's on) into <c>n</c> shares, any
/// <c>k</c> of which rebuild it and fewer reveal nothing about it: Shamir's secret sharing over GF(2^8), byte by byte.
/// Each share is text for paper or a USB stick: "CBS1-" and base32 in groups of five, carrying its own number, k, the key
/// id it belongs to and a checksum, so a holder can check their share alone, on any machine, and a mistyped or mixed-up
/// share is refused rather than rebuilding the wrong key.
/// </summary>
public static class KeyShares
{
    private const byte Version = 1;
    private const string Prefix = "CBS1-";
    private const int ChecksumSize = 4;

    /// <summary>One share, decoded: its number (1 to 255), the threshold, the key id and its bytes of the secret.</summary>
    public sealed record Share(byte Number, byte Threshold, string KeyId, byte[] Bytes);

    /// <summary>
    /// Splits <paramref name="secret"/> into <paramref name="count"/> shares, any <paramref name="threshold"/> of which
    /// rebuild it. <paramref name="random"/> is for tests; otherwise the system's secure random source.
    /// </summary>
    public static IReadOnlyList<string> Split(byte[] secret, string keyId, int threshold, int count, Func<int, byte[]>? random = null)
    {
        if (threshold is < 2 or > 255) throw new ArgumentOutOfRangeException(nameof(threshold), "At least 2 shares must be needed.");
        if (count < threshold || count > 255) throw new ArgumentOutOfRangeException(nameof(count), "There must be at least as many shares as are needed.");
        if (secret.Length is 0 or > 128) throw new ArgumentException("The secret must be 1 to 128 bytes.", nameof(secret));
        random ??= RandomNumberGenerator.GetBytes;
        var ys = new byte[count][];
        for (var i = 0; i < count; i++) ys[i] = new byte[secret.Length];
        var coefficients = new byte[threshold];
        for (var b = 0; b < secret.Length; b++)
        {
            coefficients[0] = secret[b];
            random(threshold - 1).CopyTo(coefficients, 1);
            for (var i = 0; i < count; i++) ys[i][b] = Evaluate(coefficients, (byte)(i + 1));
        }
        CryptographicOperations.ZeroMemory(coefficients);
        return ys.Select((y, i) => Encode(new Share((byte)(i + 1), (byte)threshold, keyId, y))).ToList();
    }

    /// <summary>
    /// Rebuilds the secret from at least the threshold of distinct shares of the same key. Throws with a reason a person
    /// can act on if a share is mistyped, from another key, repeated, or too few were given.
    /// </summary>
    public static byte[] Combine(IEnumerable<string> shares)
    {
        var decoded = shares.Select(Decode).ToList();
        if (decoded.Count == 0) throw new ArgumentException("No shares were given.");
        var first = decoded[0];
        if (decoded.Any(s => s.KeyId != first.KeyId))
            throw new ArgumentException("These shares belong to different keys.");
        if (decoded.Any(s => s.Threshold != first.Threshold || s.Bytes.Length != first.Bytes.Length))
            throw new ArgumentException("These shares come from different splits of the key.");
        if (decoded.Select(s => s.Number).Distinct().Count() != decoded.Count)
            throw new ArgumentException("The same share was given twice.");
        if (decoded.Count < first.Threshold)
            throw new ArgumentException($"{first.Threshold} shares are needed; {decoded.Count} were given.");
        var used = decoded.Take(first.Threshold).ToList();
        var secret = new byte[first.Bytes.Length];
        for (var b = 0; b < secret.Length; b++)
        {
            byte value = 0;
            for (var i = 0; i < used.Count; i++)
            {
                // Lagrange basis at x = 0: the product of x_j / (x_j - x_i) over j != i (subtraction is XOR in GF(2^8)).
                byte basis = 1;
                for (var j = 0; j < used.Count; j++)
                    if (j != i) basis = Mul(basis, Div(used[j].Number, (byte)(used[j].Number ^ used[i].Number)));
                value ^= Mul(used[i].Bytes[b], basis);
            }
            secret[b] = value;
        }
        return secret;
    }

    /// <summary>Reads one share's text (spaces, dashes and case don't matter); throws if it's mistyped.</summary>
    public static Share Decode(string text)
    {
        var compact = new string((text ?? "").Where(c => !char.IsWhiteSpace(c) && c != '-').ToArray()).ToUpperInvariant();
        if (!compact.StartsWith("CBS1", StringComparison.Ordinal))
            throw new ArgumentException("That isn't a CaseBook key share (it should start CBS1-).");
        var raw = Base32Decode(compact[4..]) ?? throw new ArgumentException("That share has a character that can't be in one; check it was typed correctly.");
        if (raw.Length < 1 + 8 + 2 + 1 + ChecksumSize)
            throw new ArgumentException("That share is too short; check none of it is missing.");
        var body = raw.AsSpan(0, raw.Length - ChecksumSize);
        if (!SHA256.HashData(body)[..ChecksumSize].AsSpan().SequenceEqual(raw.AsSpan(raw.Length - ChecksumSize)))
            throw new ArgumentException("That share doesn't check out: a character is wrong or missing.");
        if (body[0] != Version) throw new ArgumentException("That share was made by a version of CaseBook this one doesn't read.");
        var keyId = Convert.ToHexString(body.Slice(1, 8)).ToLowerInvariant();
        var threshold = body[9];
        var number = body[10];
        if (number == 0 || threshold < 2) throw new ArgumentException("That share is damaged.");
        return new Share(number, threshold, keyId, body[11..].ToArray());
    }

    private static string Encode(Share s)
    {
        var body = new byte[1 + 8 + 2 + s.Bytes.Length];
        body[0] = Version;
        Convert.FromHexString(s.KeyId).CopyTo(body, 1);
        body[9] = s.Threshold;
        body[10] = s.Number;
        s.Bytes.CopyTo(body, 11);
        byte[] raw = [.. body, .. SHA256.HashData(body)[..ChecksumSize]];
        var b32 = Base32Encode(raw);
        var groups = Enumerable.Range(0, (b32.Length + 4) / 5).Select(i => b32.Substring(i * 5, Math.Min(5, b32.Length - i * 5)));
        return Prefix + string.Join("-", groups);
    }

    // ---- GF(2^8), the AES field (x^8 + x^4 + x^3 + x + 1), by log and exp tables over the generator 3 ----

    private static readonly byte[] Exp = new byte[512];
    private static readonly byte[] Log = new byte[256];

    static KeyShares()
    {
        byte x = 1;
        for (var i = 0; i < 255; i++)
        {
            Exp[i] = x;
            Log[x] = (byte)i;
            x = (byte)(x ^ XTime(x));   // x * 3
        }
        for (var i = 255; i < 512; i++) Exp[i] = Exp[i - 255];
    }

    private static byte XTime(byte a) => (byte)((a << 1) ^ ((a & 0x80) != 0 ? 0x1B : 0));

    internal static byte Mul(byte a, byte b) => a == 0 || b == 0 ? (byte)0 : Exp[Log[a] + Log[b]];

    internal static byte Div(byte a, byte b)
    {
        if (b == 0) throw new DivideByZeroException();
        return a == 0 ? (byte)0 : Exp[Log[a] + 255 - Log[b]];
    }

    private static byte Evaluate(byte[] coefficients, byte x)
    {
        byte y = 0;
        for (var i = coefficients.Length - 1; i >= 0; i--) y = (byte)(Mul(y, x) ^ coefficients[i]);   // Horner's rule
        return y;
    }

    // ---- RFC 4648 base32, no padding: no 0/O or 1/I confusion on paper ----

    private const string Alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";

    private static string Base32Encode(byte[] data)
    {
        var sb = new StringBuilder((data.Length * 8 + 4) / 5);
        int buffer = 0, bits = 0;
        foreach (var b in data)
        {
            buffer = (buffer << 8) | b;
            bits += 8;
            while (bits >= 5) { sb.Append(Alphabet[(buffer >> (bits - 5)) & 31]); bits -= 5; }
        }
        if (bits > 0) sb.Append(Alphabet[(buffer << (5 - bits)) & 31]);
        return sb.ToString();
    }

    private static byte[]? Base32Decode(string text)
    {
        var bytes = new List<byte>(text.Length * 5 / 8);
        int buffer = 0, bits = 0;
        foreach (var c in text)
        {
            var v = Alphabet.IndexOf(c);
            if (v < 0) return null;
            buffer = (buffer << 5) | v;
            bits += 5;
            if (bits >= 8) { bytes.Add((byte)(buffer >> (bits - 8))); bits -= 8; }
        }
        return bytes.ToArray();
    }
}
