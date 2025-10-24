# 🔐 FirebaseAuth.NET

A simple, cross-platform **Firebase Authentication** library for .NET 9 apps (MAUI, Blazor, Console, etc.)  
Supports **Email + Password** login, registration, password reset, token persistence with custom secure storage abstraction, account deletion (unregister), and password change.

---

## 📦 Install from NuGet

```bash
dotnet add package FirebaseAuth.NET
```

NuGet: https://www.nuget.org/packages/FirebaseAuth.NET

---

## 🧱 Features

✅ Email + Password Authentication  
✅ Password Reset  
✅ Change Password  
✅ Auto Token Refresh  
✅ Reusable SecureStorage abstraction  
✅ Works in .NET 9 MAUI, Blazor, WPF, API, or Console  
✅ Account deletion (Unregister)  
✅ Optional typed errors via `FirebaseAuthException` and `AuthErrorReason`

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

        // Register Firebase Auth
        builder.Services.AddSingleton<ISecureStorage, MauiSecureStorage>();
        builder.Services.AddSingleton<IFirebaseAuthService>(sp =>
        {
            var logger = sp.GetRequiredService<ILogger<FirebaseAuthService>>();
            var storage = sp.GetRequiredService<ISecureStorage>();
            var http = new HttpClient();
            var apiKey = "YOUR_FIREBASE_API_KEY"; // from Firebase Console
            var options = new FirebaseAuthOptions
            {
                // Optional: throw typed errors that you can handle in UI
                ThrowOnError = true,
                // Optional: disable registration endpoints
                // AllowRegistration = false
            };
            return new FirebaseAuthService(http, logger, storage, apiKey, options);
        });

        return builder.Build();
    }
}
```

---

### 3️⃣ Use It Anywhere

```csharp
using FirebaseAuth.NET.Services;

public partial class LoginPage : ContentPage
{
    private readonly IFirebaseAuthService _auth;

    public LoginPage(IFirebaseAuthService auth)
    {
        InitializeComponent();
        _auth = auth;
    }

    private async void OnLoginClicked(object sender, EventArgs e)
    {
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
            // Handle typed errors when ThrowOnError = true
            switch (ex.Reason)
            {
                case AuthErrorReason.InvalidEmailAddress:
                    await DisplayAlert("Error", "Invalid email address.", "OK");
                    break;
                case AuthErrorReason.InvalidPassword:
                    await DisplayAlert("Error", "Invalid password.", "OK");
                    break;
                default:
                    await DisplayAlert("Error", ex.Message, "OK");
                    break;
            }
        }
    }

    private async void OnForgotPasswordClicked(object sender, EventArgs e)
    {
        var success = await _auth.SendPasswordResetEmailAsync("test@example.com");
        await DisplayAlert("Reset Password", success ? "Email sent." : "Failed to send.", "OK");
    }

    private async void OnChangePasswordClicked(object sender, EventArgs e)
    {
        var success = await _auth.ChangePasswordAsync("NewStrongPassword!234");
        await DisplayAlert("Change Password", success ? "Password updated." : "Failed to update password.", "OK");
    }

    private async void OnUnregisterClicked(object sender, EventArgs e)
    {
        var success = await _auth.UnregisterAsync();
        await DisplayAlert("Unregister", success ? "Account deleted." : "Failed to delete account.", "OK");
    }
}
```

Notes
- Changing password requires the user to be signed in. For sensitive operations, Firebase may require a recent login; if you receive an error, call `LoginAsync` again and retry `ChangePasswordAsync`.

---

### 4️⃣ Logout Example

```csharp
_auth.Logout();
```

---

## 🧩 Advanced
- Implement your own `ISecureStorage` (e.g., file, key vault, or mock for testing).
- Control registration availability using options (default allows registration):

```csharp
var options = new FirebaseAuthOptions { AllowRegistration = false };
var auth = new FirebaseAuthService(http, logger, storage, "YOUR_FIREBASE_API_KEY", options);
```

- Enable typed errors in UI-friendly way:

```csharp
var options = new FirebaseAuthOptions { ThrowOnError = true };
```

---

## 🧪 Example Usage (Console App)
```csharp
var http = new HttpClient();
var storage = new FileSecureStorage(); // your own ISecureStorage implementation
var logger = LoggerFactory.Create(b => b.AddConsole()).CreateLogger<FirebaseAuthService>();

var options = new FirebaseAuthOptions { ThrowOnError = true };
var auth = new FirebaseAuthService(http, logger, storage, "YOUR_FIREBASE_API_KEY", options);

try
{
    var user = await auth.RegisterAsync("user@example.com", "password123");
    Console.WriteLine($"Registered user: {user?.Email}");
}
catch (FirebaseAuthException ex)
{
    if (ex.Reason == AuthErrorReason.EmailExists)
        Console.WriteLine("Email already exists");
    else
        Console.WriteLine($"Registration failed: {ex.Message}");
}

var changed = await auth.ChangePasswordAsync("newP@ssw0rd!");
Console.WriteLine(changed ? "Password changed" : "Change failed");

var deleted = await auth.UnregisterAsync();
Console.WriteLine(deleted ? "Account deleted" : "Delete failed");
```

---

## 🌐 Cross-platform notes
- Uses `ILogger` for retry logging instead of `Console`, suitable for MAUI, Blazor, ASP.NET, WPF, and Console.
- Storage is abstracted behind `ISecureStorage`; provide a platform-appropriate implementation.
- Works with `HttpClient` everywhere. In Blazor WebAssembly, ensure CORS is allowed for Google Identity Toolkit endpoints (default is fine), and construct `HttpClient` from DI.

---

## 📘 API Docs
- Methods include XML summaries for IntelliSense and documentation tooling.
- Typed errors: `FirebaseAuthException` with `AuthErrorReason` for granular error handling when `ThrowOnError` is enabled.

---

## 🧑‍💻 Author
**Imre Szücs**  
Licensed under **MIT**

---

## 🌟 Contribute
Pull requests and improvements are welcome!  
If you find a bug, please open an issue: https://github.com/szucsim/FirebaseAuth.NET/issues
