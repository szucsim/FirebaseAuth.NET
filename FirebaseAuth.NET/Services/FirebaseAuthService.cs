using System.Net.Http.Json;
using System.Text.Json;
using Microsoft.Extensions.Logging;
using Polly;
using Polly.Retry;
using FirebaseAuth.NET.Storage;

namespace FirebaseAuth.NET.Services;

public sealed class FirebaseAuthService : IFirebaseAuthService
{
    private readonly HttpClient _http;
    private readonly ILogger<FirebaseAuthService> _logger;
    private readonly ISecureStorage _storage;
    private readonly string _apiKey;

    private const string BaseUrl = "https://identitytoolkit.googleapis.com/v1";
    private const string RefreshUrl = "https://securetoken.googleapis.com/v1/token";
    private const string StoredUserKey = "firebase_user";

    private readonly AsyncRetryPolicy<HttpResponseMessage> _retryPolicy = Policy
        .HandleResult<HttpResponseMessage>(r => !r.IsSuccessStatusCode)
        .WaitAndRetryAsync(
            3,
            attempt => TimeSpan.FromSeconds(Math.Pow(2, attempt)),
            (outcome, delay, attempt, _) =>
                Console.WriteLine($"[FirebaseAuthService] Retrying request (attempt {attempt}) after {delay.TotalSeconds}s")
        );

    public FirebaseAuthService(HttpClient http, ILogger<FirebaseAuthService> logger, ISecureStorage storage, string apiKey)
    {
        _http = http;
        _logger = logger;
        _storage = storage;
        _apiKey = apiKey;
    }

    public async Task<FirebaseUser?> LoginAsync(string email, string password, CancellationToken ct = default)
    {
        try
        {
            var payload = new { email, password, returnSecureToken = true };
            var response = await _retryPolicy.ExecuteAsync(() =>
                _http.PostAsJsonAsync($"{BaseUrl}/accounts:signInWithPassword?key={_apiKey}", payload, ct));

            if (!response.IsSuccessStatusCode)
            {
                _logger.LogWarning("Firebase login failed for {Email}. Status: {StatusCode}", email, response.StatusCode);
                return null;
            }

            var user = await response.Content.ReadFromJsonAsync<FirebaseUser>(cancellationToken: ct);
            if (user == null) return null;

            user.ExpiryUtc = DateTime.UtcNow.AddSeconds(int.Parse(user.ExpiresIn ?? "3600"));
            await SaveUserAsync(user);
            return user;
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error logging in user {Email}", email);
            return null;
        }
    }

    public async Task<FirebaseUser?> RegisterAsync(string email, string password, CancellationToken ct = default)
    {
        try
        {
            var payload = new { email, password, returnSecureToken = true };
            var response = await _retryPolicy.ExecuteAsync(() =>
                _http.PostAsJsonAsync($"{BaseUrl}/accounts:signUp?key={_apiKey}", payload, ct));

            if (!response.IsSuccessStatusCode)
            {
                _logger.LogWarning("Firebase registration failed for {Email}", email);
                return null;
            }

            var user = await response.Content.ReadFromJsonAsync<FirebaseUser>(cancellationToken: ct);
            if (user == null) return null;

            user.ExpiryUtc = DateTime.UtcNow.AddSeconds(int.Parse(user.ExpiresIn ?? "3600"));
            await SaveUserAsync(user);
            return user;
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error registering user {Email}", email);
            return null;
        }
    }

    public async Task<FirebaseUser?> GetCurrentUserAsync(CancellationToken ct = default)
    {
        try
        {
            var json = await _storage.GetAsync(StoredUserKey);
            if (string.IsNullOrEmpty(json)) return null;

            var user = JsonSerializer.Deserialize<FirebaseUser>(json);
            if (user == null) return null;

            if (user.IsExpired)
            {
                var refreshed = await RefreshTokenAsync(user.RefreshToken, ct);
                if (refreshed != null)
                {
                    await SaveUserAsync(refreshed);
                    return refreshed;
                }
            }

            return user;
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error fetching current user");
            return null;
        }
    }

    public async Task<bool> SendPasswordResetEmailAsync(string email, CancellationToken ct = default)
    {
        try
        {
            var payload = new { requestType = "PASSWORD_RESET", email };
            var response = await _retryPolicy.ExecuteAsync(() =>
                _http.PostAsJsonAsync($"{BaseUrl}/accounts:sendOobCode?key={_apiKey}", payload, ct));

            if (!response.IsSuccessStatusCode)
            {
                _logger.LogWarning("Password reset failed for {Email}", email);
                return false;
            }

            return true;
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error sending password reset email for {Email}", email);
            return false;
        }
    }

    private async Task<FirebaseUser?> RefreshTokenAsync(string refreshToken, CancellationToken ct)
    {
        try
        {
            var form = new FormUrlEncodedContent(new Dictionary<string, string>
            {
                ["grant_type"] = "refresh_token",
                ["refresh_token"] = refreshToken
            });

            var response = await _retryPolicy.ExecuteAsync(() =>
                _http.PostAsync($"{RefreshUrl}?key={_apiKey}", form, ct));

            if (!response.IsSuccessStatusCode)
            {
                _logger.LogWarning("Token refresh failed. Status: {StatusCode}", response.StatusCode);
                return null;
            }

            using var doc = JsonDocument.Parse(await response.Content.ReadAsStringAsync(ct));
            var root = doc.RootElement;

            return new FirebaseUser
            {
                IdToken = root.GetProperty("id_token").GetString() ?? "",
                RefreshToken = root.GetProperty("refresh_token").GetString() ?? "",
                LocalId = root.GetProperty("user_id").GetString() ?? "",
                ExpiryUtc = DateTime.UtcNow.AddSeconds(int.Parse(root.GetProperty("expires_in").GetString() ?? "3600"))
            };
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error refreshing token");
            return null;
        }
    }

    public void Logout()
    {
        try
        {
            _storage.Remove(StoredUserKey);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error clearing stored user data");
        }
    }

    private async Task SaveUserAsync(FirebaseUser user)
    {
        var json = JsonSerializer.Serialize(user);
        await _storage.SetAsync(StoredUserKey, json);
    }
}
