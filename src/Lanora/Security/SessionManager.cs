using System.Security.Cryptography;
using System.Text;

namespace Lanora.Security;

/// <summary>
/// SEC02: Single-use launch secret (≥256 bits, 60 s) and session tokens kept only in memory.
/// Secrets and tokens themselves are never stored, only their SHA-256 hashes. All become invalid when the process restarts (SEC06).
/// </summary>
public sealed class SessionManager
{
    public static readonly TimeSpan SecretLifetime = TimeSpan.FromSeconds(60);
    private const int MaxTokens = 16;
    private const int MaxPendingSecrets = 8;

    private readonly object _gate = new();
    private readonly Dictionary<string, DateTimeOffset> _secrets = new(StringComparer.Ordinal);
    private readonly Dictionary<string, DateTimeOffset> _tokens = new(StringComparer.Ordinal);
    private readonly Func<DateTimeOffset> _now;

    public SessionManager(Func<DateTimeOffset>? now = null) => _now = now ?? (() => DateTimeOffset.UtcNow);

    public string CreateBootstrapSecret()
    {
        var secret = NewRandom();
        lock (_gate)
        {
            Purge();
            while (_secrets.Count >= MaxPendingSecrets)
                _secrets.Remove(_secrets.MinBy(kv => kv.Value).Key);
            _secrets[Digest(secret)] = _now() + SecretLifetime;
        }
        return secret;
    }

    /// <summary>Exchanges the secret for a session token. A missing, wrong, expired or reused secret returns null.</summary>
    public string? Redeem(string? secret)
    {
        if (!LooksValid(secret)) return null;
        lock (_gate)
        {
            if (!_secrets.Remove(Digest(secret!), out var expires)) return null;
            if (expires < _now()) return null;
            var token = NewRandom();
            while (_tokens.Count >= MaxTokens)
                _tokens.Remove(_tokens.MinBy(kv => kv.Value).Key);
            _tokens[Digest(token)] = _now();
            return token;
        }
    }

    public bool Validate(string? token)
    {
        if (!LooksValid(token)) return false;
        lock (_gate)
        {
            var key = Digest(token!);
            if (!_tokens.ContainsKey(key)) return false;
            _tokens[key] = _now();
            return true;
        }
    }

    public void RevokeAll()
    {
        lock (_gate)
        {
            _tokens.Clear();
            _secrets.Clear();
        }
    }

    private void Purge()
    {
        var now = _now();
        foreach (var k in _secrets.Where(kv => kv.Value < now).Select(kv => kv.Key).ToList())
            _secrets.Remove(k);
    }

    private static bool LooksValid(string? value) =>
        value is { Length: 43 } && value.All(c => char.IsAsciiLetterOrDigit(c) || c == '-' || c == '_');

    private static string NewRandom() => Base64Url(RandomNumberGenerator.GetBytes(32));

    private static string Digest(string value) => Convert.ToHexString(SHA256.HashData(Encoding.ASCII.GetBytes(value)));

    private static string Base64Url(byte[] bytes) =>
        Convert.ToBase64String(bytes).TrimEnd('=').Replace('+', '-').Replace('/', '_');
}
