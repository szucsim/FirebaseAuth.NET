﻿using System.Net.Http.Json;
using System.Text.Json;
using Microsoft.Extensions.Logging;
using Polly;
using Polly.Retry;
using FirebaseAuth.NET.Storage;

namespace FirebaseAuth.NET.Services;

/// <summary>
/// Default implementation of <see cref="IFirebaseAuthService"/> using Firebase Identity Toolkit REST APIs.
/// Handles login, registration, password reset, account deletion, password change, token refresh and persistence.
/// </summary>
public sealed class FirebaseAuthService : IFirebaseAuthService
{
    private readonly HttpClient _http;
    private readonly ILogger<FirebaseAuthService> _logger;
    private readonly ISecureStorage _storage;
    private readonly string _apiKey;
    private readonly FirebaseAuthOptions _options;

    private const string BaseUrl = "https://identitytoolkit.googleapis.com/v1";
    private const string RefreshUrl = "https://securetoken.googleapis.com/v1/token";
    private const string StoredUserKey = "firebase_user";

    private readonly AsyncRetryPolicy<HttpResponseMessage> _retryPolicy;

    /// <summary>
    /// Creates a new service instance (registration allowed by default).
    /// </summary>
    public FirebaseAuthService(HttpClient http, ILogger<FirebaseAuthService> logger, ISecureStorage storage, string apiKey)
        : this(http, logger, storage, apiKey, new FirebaseAuthOptions())
    { }

    /// <summary>
    /// Creates a new service instance with configurable options.
    /// </summary>
    public FirebaseAuthService(HttpClient http, ILogger<FirebaseAuthService> logger, ISecureStorage storage, string apiKey, FirebaseAuthOptions options)
    {
        _http = http;
        _logger = logger;
        _storage = storage;
        _apiKey = apiKey;
        _options = options ?? new FirebaseAuthOptions();

        _retryPolicy = Policy
            .HandleResult<HttpResponseMessage>(r => !r.IsSuccessStatusCode)
            .WaitAndRetryAsync(
                3,
                attempt => TimeSpan.FromSeconds(Math.Pow(2, attempt)),
                (outcome, delay, attempt, _) =>
                    _logger.LogDebug(
                        "Retrying HTTP request (attempt {Attempt}) after {DelaySeconds}s. Status: {StatusCode}",
                        attempt,
                        delay.TotalSeconds,
                        outcome.Result?.StatusCode)
            );
    }

    /// <inheritdoc />
    public async Task<FirebaseUser?> LoginAsync(string email, string password, CancellationToken ct = default)
    {
        try
        {
            var payload = new { email, password, returnSecureToken = true };
            var response = await _retryPolicy.ExecuteAsync(() =>
                _http.PostAsJsonAsync($"{BaseUrl}/accounts:signInWithPassword?key={_apiKey}", payload, ct));

            if (!response.IsSuccessStatusCode)
            {
                await ThrowIfConfiguredAsync(response, "Firebase login failed");
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
            RethrowIfConfigured(ex, "Error logging in user");
            _logger.LogError(ex, "Error logging in user {Email}", email);
            return null;
        }
    }

    /// <inheritdoc />
    public async Task<FirebaseUser?> RegisterAsync(string email, string password, CancellationToken ct = default)
    {
        try
        {
            if (!_options.AllowRegistration)
            {
                _logger.LogInformation("Registration is disabled. Skipping RegisterAsync for {Email}", email);
                return null;
            }

            var payload = new { email, password, returnSecureToken = true };
            var response = await _retryPolicy.ExecuteAsync(() =>
                _http.PostAsJsonAsync($"{BaseUrl}/accounts:signUp?key={_apiKey}", payload, ct));

            if (!response.IsSuccessStatusCode)
            {
                await ThrowIfConfiguredAsync(response, "Firebase registration failed");
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
            RethrowIfConfigured(ex, "Error registering user");
            _logger.LogError(ex, "Error registering user {Email}", email);
            return null;
        }
    }

    /// <inheritdoc />
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
            RethrowIfConfigured(ex, "Error fetching current user");
            _logger.LogError(ex, "Error fetching current user");
            return null;
        }
    }

    /// <inheritdoc />
    public async Task<bool> SendPasswordResetEmailAsync(string email, CancellationToken ct = default)
    {
        try
        {
            var payload = new { requestType = "PASSWORD_RESET", email };
            var response = await _retryPolicy.ExecuteAsync(() =>
                _http.PostAsJsonAsync($"{BaseUrl}/accounts:sendOobCode?key={_apiKey}", payload, ct));

            if (!response.IsSuccessStatusCode)
            {
                await ThrowIfConfiguredAsync(response, "Password reset failed");
                _logger.LogWarning("Password reset failed for {Email}", email);
                return false;
            }

            return true;
        }
        catch (Exception ex)
        {
            RethrowIfConfigured(ex, "Error sending password reset email");
            _logger.LogError(ex, "Error sending password reset email for {Email}", email);
            return false;
        }
    }

    /// <inheritdoc />
    public async Task<bool> UnregisterAsync(CancellationToken ct = default)
    {
        try
        {
            var current = await GetCurrentUserAsync(ct);
            if (current == null || string.IsNullOrWhiteSpace(current.IdToken))
            {
                _logger.LogWarning("Unregister failed: no authenticated user.");
                return false;
            }

            var payload = new { idToken = current.IdToken };
            var response = await _retryPolicy.ExecuteAsync(() =>
                _http.PostAsJsonAsync($"{BaseUrl}/accounts:delete?key={_apiKey}", payload, ct));

            if (!response.IsSuccessStatusCode)
            {
                await ThrowIfConfiguredAsync(response, "Unregister failed");
                _logger.LogWarning("Unregister failed. Status: {StatusCode}", response.StatusCode);
                return false;
            }

            // Clear local state after successful deletion
            Logout();
            return true;
        }
        catch (Exception ex)
        {
            RethrowIfConfigured(ex, "Error unregistering current user");
            _logger.LogError(ex, "Error unregistering current user");
            return false;
        }
    }

    /// <inheritdoc />
    public async Task<bool> ChangePasswordAsync(string newPassword, CancellationToken ct = default)
    {
        try
        {
            var current = await GetCurrentUserAsync(ct);
            if (current == null || string.IsNullOrWhiteSpace(current.IdToken))
            {
                _logger.LogWarning("ChangePassword failed: no authenticated user.");
                return false;
            }

            var payload = new { idToken = current.IdToken, password = newPassword, returnSecureToken = true };
            var response = await _retryPolicy.ExecuteAsync(() =>
                _http.PostAsJsonAsync($"{BaseUrl}/accounts:update?key={_apiKey}", payload, ct));

            if (!response.IsSuccessStatusCode)
            {
                await ThrowIfConfiguredAsync(response, "ChangePassword failed");
                var body = await response.Content.ReadAsStringAsync(ct);
                _logger.LogWarning("ChangePassword failed. Status: {StatusCode}. Body: {Body}", response.StatusCode, body);
                return false;
            }

            // Update local user with new tokens from response
            var updated = await response.Content.ReadFromJsonAsync<FirebaseUser>(cancellationToken: ct);
            if (updated == null)
            {
                _logger.LogWarning("ChangePassword failed: invalid response.");
                return false;
            }

            updated.ExpiryUtc = DateTime.UtcNow.AddSeconds(int.Parse(updated.ExpiresIn ?? "3600"));
            await SaveUserAsync(updated);
            return true;
        }
        catch (Exception ex)
        {
            RethrowIfConfigured(ex, "Error changing password");
            _logger.LogError(ex, "Error changing password");
            return false;
        }
    }

    /// <summary>
    /// Changes the email of the currently authenticated user.
    /// </summary>
    /// <param name="newEmail">The new email address to set.</param>
    /// <param name="ct">Cancellation token.</param>
    /// <returns>True on success; false otherwise.</returns>
    public async Task<bool> ChangeEmailAsync(string newEmail, CancellationToken ct = default)
    {
        try
        {
            var current = await GetCurrentUserAsync(ct);
            if (current == null || string.IsNullOrWhiteSpace(current.IdToken))
            {
                _logger.LogWarning("ChangeEmail failed: no authenticated user.");
                return false;
            }

            var payload = new { idToken = current.IdToken, email = newEmail, returnSecureToken = true };
            var response = await _retryPolicy.ExecuteAsync(() =>
                _http.PostAsJsonAsync($"{BaseUrl}/accounts:update?key={_apiKey}", payload, ct));

            if (!response.IsSuccessStatusCode)
            {
                await ThrowIfConfiguredAsync(response, "ChangeEmail failed");
                var body = await response.Content.ReadAsStringAsync(ct);
                _logger.LogWarning("ChangeEmail failed. Status: {StatusCode}. Body: {Body}", response.StatusCode, body);
                return false;
            }

            // Update local user info and tokens from response
            var updated = await response.Content.ReadFromJsonAsync<FirebaseUser>(cancellationToken: ct);
            if (updated == null)
            {
                _logger.LogWarning("ChangeEmail failed: invalid response.");
                return false;
            }

            updated.ExpiryUtc = DateTime.UtcNow.AddSeconds(int.Parse(updated.ExpiresIn ?? "3600"));
            await SaveUserAsync(updated);
            return true;
        }
        catch (Exception ex)
        {
            RethrowIfConfigured(ex, "Error changing email");
            _logger.LogError(ex, "Error changing email");
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
            RethrowIfConfigured(ex, "Error refreshing token");
            _logger.LogError(ex, "Error refreshing token");
            return null;
        }
    }

    /// <summary>
    /// Clears persisted user state and tokens from secure storage.
    /// </summary>
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

    private static AuthErrorReason MapErrorCode(string? code)
    {
        if (string.IsNullOrWhiteSpace(code)) return AuthErrorReason.Unknown;
        code = code.Trim();
        // Normalize common variants
        if (code.Contains(':')) code = code.Split(':')[0].Trim();
        if (code.Contains(' ')) code = code.Split(' ')[0].Trim();

        return code switch
        {
            "EMAIL_EXISTS" => AuthErrorReason.EmailExists,
            "INVALID_EMAIL" => AuthErrorReason.InvalidEmailAddress,
            "WEAK_PASSWORD" => AuthErrorReason.WeakPassword,
            "EMAIL_NOT_FOUND" => AuthErrorReason.EmailNotFound,
            "INVALID_PASSWORD" => AuthErrorReason.InvalidPassword,
            "USER_DISABLED" => AuthErrorReason.UserDisabled,
            "TOO_MANY_ATTEMPTS_TRY_LATER" => AuthErrorReason.TooManyAttempts,
            "INVALID_ID_TOKEN" => AuthErrorReason.InvalidIdToken,
            "TOKEN_EXPIRED" => AuthErrorReason.TokenExpired,
            "MISSING_PASSWORD" => AuthErrorReason.MissingPassword,
            "OPERATION_NOT_ALLOWED" => AuthErrorReason.OperationNotAllowed,
            "CREDENTIAL_TOO_OLD_LOGIN_AGAIN" => AuthErrorReason.RequiresRecentLogin,
            _ => AuthErrorReason.Unknown
        };
    }

    private async Task ThrowIfConfiguredAsync(HttpResponseMessage response, string context)
    {
        if (!_options.ThrowOnError) return;

        string? message = null;
        string? code = null;
        try
        {
            var body = await response.Content.ReadAsStringAsync();
            using var doc = JsonDocument.Parse(body);
            if (doc.RootElement.TryGetProperty("error", out var errorEl))
            {
                if (errorEl.TryGetProperty("message", out var msgEl))
                {
                    message = msgEl.GetString();
                }
                if (errorEl.TryGetProperty("status", out var statusEl) && string.IsNullOrEmpty(message))
                {
                    message = statusEl.GetString();
                }
            }
            code = message;
        }
        catch
        {
            // ignore parse errors, fall back to status code
        }

        var reason = MapErrorCode(code);
        var status = (int)response.StatusCode;
        var fullMessage = string.IsNullOrWhiteSpace(message) ? context : $"{context}: {message}";
        throw new FirebaseAuthException(reason, fullMessage, code, status);
    }

    private void RethrowIfConfigured(Exception ex, string context)
    {
        if (!_options.ThrowOnError) return;
        var reason = ex is HttpRequestException ? AuthErrorReason.NetworkError : AuthErrorReason.Unknown;
        throw new FirebaseAuthException(reason, $"{context}: {ex.Message}", null, null, ex);
    }
}
