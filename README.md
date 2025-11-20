# 🔐 FirebaseAuth.NET

A simple, cross-platform **Firebase Authentication** library for MAUI, Blazor, Console, etc. targeting .NET 8, .NET 9, or .NET 10.
Supports **Email + Password** login, registration, password reset, token persistence with secure storage abstraction, account deletion (unregister), password change, email change flow, user profile refresh, and granular error mapping.

Current version: 1.7.1

---

## 📦 Install from NuGet

```bash
dotnet add package FirebaseAuth.NET
```

NuGet: https://www.nuget.org/packages/FirebaseAuth.NET

---

## 🧱 Features

✅ Email + Password Authentication  
✅ Registration (optional disable)  
✅ Password Reset  
✅ Change Password  
✅ Start Email Change Flow (verify & change)  
✅ Refresh User Info (accounts:lookup)  
✅ Auto Token Refresh  
✅ Reusable SecureStorage abstraction  
✅ Works in MAUI, Blazor, WPF, ASP.NET, or Console apps targeting .NET 8, .NET 9, or .NET 10  
✅ Account deletion (Unregister)  
✅ Typed errors via `FirebaseAuthException` and `AuthErrorReason`  
✅ Robust Firebase error payload parsing (nested message formats)

---

## 🔎 Error Reasons Overview
`AuthErrorReason` includes (non-exhaustive):
- `InvalidEmailAddress`, `EmailExists`, `EmailNotFound`
- `InvalidPassword`, `WeakPassword`, `InvalidLoginCredentials`
- `UserDisabled`, `TooManyAttempts`
- `InvalidIdToken`, `TokenExpired`
- `MissingRefreshToken`, `InvalidRefreshToken`
- `RequiresRecentLogin`, `OperationNotAllowed`

### TokenExpired vs InvalidIdToken vs Refresh Token Errors
- `TokenExpired`: ID token lifetime elapsed; library attempts refresh automatically using stored refresh token. On success you transparently continue.
- `InvalidIdToken`: Provided ID token rejected (revoked / changed context, e.g. after email change). Force re-login.
- `MissingRefreshToken`: Refresh attempted without token (corrupt / cleared state). Force logout + re-login.
- `InvalidRefreshToken`: Token revoked / malformed / deleted user. Force logout + re-login.

---

## ⚙️ Setup in a MAUI App

### 1️⃣ Create a Secure Storage Adapter

`Storage/MauiSecureStorage.cs`
```csharp
using FirebaseAuth.NET.Storage;

namespace MyApp.Storage;

public class MauiSecureStorage : ISecureStorage
{
    public Task SetAsync(string key, string value) => SecureStorage.Default.SetAsync(key, value);
    public Task<string?> GetAsync(string key) => SecureStorage.Default.GetAsync(key);
    public void Remove(string key) => SecureStorage.Default.Remove(key);
}
```

---

### 2️⃣ Register Dependencies

`MauiProgram.cs`
```csharp
using FirebaseAuth.NET.Services;
using FirebaseAuth.NET.Storage;
using MyApp.Storage;

public static class MauiProgram
{
    public static MauiApp CreateMauiApp()
    {
        var builder = MauiApp.CreateBuilder();

        builder.Services.AddSingleton<ISecureStorage, MauiSecureStorage>();
        builder.Services.AddSingleton<IFirebaseAuthService>(sp =>
        {
            var logger = sp.GetRequiredService<ILogger<FirebaseAuthService>>();
            var storage = sp.GetRequiredService<ISecureStorage>();
            var http = new HttpClient();
            var apiKey = "YOUR_FIREBASE_API_KEY"; // from Firebase Console
            var options = new FirebaseAuthOptions
            {
                ThrowOnError = true,
                // AllowRegistration = false // optional
            };
            return new FirebaseAuthService(http, logger, storage, apiKey, options);
        });

        return builder.Build();
    }
}
```

---

### 3️⃣ Use It Anywhere (Example Page)

```csharp
try
{
    var user = await _auth.LoginAsync("test@example.com", "password123");
    if (user != null)
        await DisplayAlert("Welcome", $"Logged in as {user.Email}", "OK");
    else
        await DisplayAlert("Error", "Login failed.", "OK");
}
catch (FirebaseAuthException ex)
{
    switch (ex.Reason)
    {
        case AuthErrorReason.InvalidEmailAddress:
            await DisplayAlert("Error", "Invalid email address.", "OK");
            break;
        case AuthErrorReason.InvalidPassword:
        case AuthErrorReason.InvalidLoginCredentials:
            await DisplayAlert("Error", "Invalid credentials.", "OK");
            break;
        case AuthErrorReason.MissingRefreshToken:
        case AuthErrorReason.InvalidRefreshToken:
            _auth.Logout();
            await DisplayAlert("Session", "Session expired. Please log in again.", "OK");
            break;
        default:
            await DisplayAlert("Error", ex.Message, "OK");
            break;
    }
}
```

Notes
- Changing password requires signed-in user and may need recent login.
- Email change flow invalidates old tokens; re-login then call `RefreshUserInfoAsync()`.

---

### Email Change Flow
1. Call `StartEmailChangeAsync(newEmail)` to send verification link.
2. User confirms link ⇒ Firebase updates email; old ID token may fail.
3. Handle `InvalidIdToken`, `MissingRefreshToken`, `InvalidRefreshToken` by forcing re-login.
4. Call `RefreshUserInfoAsync()` to obtain updated email.

---

### Refresh Token Failure Handling
```csharp
FirebaseUser? current = null;
try
{
    current = await _auth.GetCurrentUserAsync();
}
catch (FirebaseAuthException ex) when (
    ex.Reason == AuthErrorReason.TokenExpired ||
    ex.Reason == AuthErrorReason.InvalidIdToken ||
    ex.Reason == AuthErrorReason.InvalidRefreshToken ||
    ex.Reason == AuthErrorReason.MissingRefreshToken)
{
    _auth.Logout();
}
```
If refresh fails (missing/invalid) require manual login.

---

### 4️⃣ Logout Example
```csharp
_auth.Logout();
```

---

## 🧪 Full Console App Example
```csharp
using FirebaseAuth.NET.Services;
using FirebaseAuth.NET.Storage;
using Microsoft.Extensions.Logging;

// Minimal secure storage implementation (file-based) for demo
public class FileSecureStorage : ISecureStorage
{
    private readonly string _dir = Path.Combine(AppContext.BaseDirectory, "authstore");
    public FileSecureStorage() => Directory.CreateDirectory(_dir);
    public Task SetAsync(string key, string value)
    {
        File.WriteAllText(Path.Combine(_dir, key), value);
        return Task.CompletedTask;
    }
    public Task<string?> GetAsync(string key)
    {
        var path = Path.Combine(_dir, key);
        return Task.FromResult(File.Exists(path) ? File.ReadAllText(path) : null);
    }
    public void Remove(string key)
    {
        var path = Path.Combine(_dir, key);
        if (File.Exists(path)) File.Delete(path);
    }
}

var loggerFactory = LoggerFactory.Create(b => b.AddConsole());
var logger = loggerFactory.CreateLogger<FirebaseAuthService>();
var http = new HttpClient();
var storage = new FileSecureStorage();
var options = new FirebaseAuthOptions { ThrowOnError = true };
var auth = new FirebaseAuthService(http, logger, storage, "YOUR_FIREBASE_API_KEY", options);

try
{
    // Register (if enabled)
    var registered = await auth.RegisterAsync("user@example.com", "StrongP@ssw0rd!");
    Console.WriteLine($"Registered: {registered?.Email}");
}
catch (FirebaseAuthException ex)
{
    Console.WriteLine($"Registration failed ({ex.Reason}): {ex.Message}");
}

// Login
FirebaseUser? user = null;
try
{
    user = await auth.LoginAsync("user@example.com", "StrongP@ssw0rd!");
    Console.WriteLine($"Logged in: {user?.Email}");
}
catch (FirebaseAuthException ex)
{
    Console.WriteLine($"Login failed ({ex.Reason}): {ex.Message}");
}

// Start email change
var started = await auth.StartEmailChangeAsync("new.email@example.com", canHandleCodeInApp: true);
Console.WriteLine(started ? "Email change verification sent." : "Failed to send email change link.");
Console.WriteLine("(Simulate user clicking verification link in mailbox...)\n");

// Pretend some time passes & tokens may be invalid now
await Task.Delay(TimeSpan.FromSeconds(2));

try
{
    var refreshed = await auth.RefreshUserInfoAsync();
    Console.WriteLine(refreshed != null ? $"Refreshed email: {refreshed.Email}" : "Refresh failed");
}
catch (FirebaseAuthException ex) when (
    ex.Reason == AuthErrorReason.InvalidIdToken ||
    ex.Reason == AuthErrorReason.InvalidRefreshToken ||
    ex.Reason == AuthErrorReason.MissingRefreshToken)
{
    Console.WriteLine($"Session invalid ({ex.Reason}). Re-login required.");
    auth.Logout();
    user = await auth.LoginAsync("new.email@example.com", "StrongP@ssw0rd!");
    Console.WriteLine($"Re-logged in: {user?.Email}");
    var updated = await auth.RefreshUserInfoAsync();
    Console.WriteLine(updated != null ? $"Updated email after reauth: {updated.Email}" : "Refresh user info failed");
}

// Change password
var changedPwd = await auth.ChangePasswordAsync("An0therStr0ngP@ss!");
Console.WriteLine(changedPwd ? "Password changed." : "Password change failed.");

// Unregister
var deleted = await auth.UnregisterAsync();
Console.WriteLine(deleted ? "Account deleted." : "Account deletion failed.");
```

---

## 🧩 Advanced
- Provide custom `ISecureStorage` (KeyChain/Keystore, DPAPI, file, memory for tests).
- Disable registration: `new FirebaseAuthOptions { AllowRegistration = false }`.
- Fine-tune error strategy: `ThrowOnError = true` to receive typed exceptions instead of null/false.
- Wrap service behind your own auth facade for app-specific logic.

---

## 🌐 Cross-platform notes
- Uses `ILogger` and Polly for transient retry (timeouts, 5xx, 429).
- No platform-specific code in core library (pure .NET).
- Works in Blazor WASM (Google endpoints support CORS).

---

## 📘 API Surface
Key methods: `LoginAsync`, `RegisterAsync`, `GetCurrentUserAsync`, `SendPasswordResetEmailAsync`, `StartEmailChangeAsync`, `RefreshUserInfoAsync`, `ChangePasswordAsync`, `UnregisterAsync`, `Logout`.

---

## 🧑‍💻 Author
**Imre Szücs** – MIT License

---

## 🌟 Contribute
Issues & PRs welcome: https://github.com/szucsim/FirebaseAuth.NET/issues
