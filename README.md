# 🔐 FirebaseAuth.NET

A simple, cross-platform **Firebase Authentication** library for .NET 9 apps (MAUI, Blazor, Console, etc.)  
Supports **Email + Password** login, registration, password reset, and token persistence with custom secure storage abstraction.

---

## 📦 Install from NuGet

```bash
dotnet add package FirebaseAuth.NET
```

NuGet: [https://www.nuget.org/packages/FirebaseAuth.NET](https://www.nuget.org/packages/FirebaseAuth.NET)

---

## 🧱 Features

✅ Email + Password Authentication  
✅ Password Reset  
✅ Auto Token Refresh  
✅ Reusable SecureStorage abstraction  
✅ Works in .NET 9 MAUI, Blazor, WPF, API, or Console  

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
            return new FirebaseAuthService(http, logger, storage, apiKey);
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
        var user = await _auth.LoginAsync("test@example.com", "password123");
        if (user != null)
            await DisplayAlert("Welcome", $"Logged in as {user.Email}", "OK");
        else
            await DisplayAlert("Error", "Login failed.", "OK");
    }

    private async void OnForgotPasswordClicked(object sender, EventArgs e)
    {
        var success = await _auth.SendPasswordResetEmailAsync("test@example.com");
        await DisplayAlert("Reset Password", success ? "Email sent." : "Failed to send.", "OK");
    }
}
```

---

### 4️⃣ Logout Example

```csharp
_auth.Logout();
```

---

## 🧩 Advanced
You can also implement your own `ISecureStorage` (e.g., file, key vault, or mock for testing).

---

## 🧪 Example Usage (Console App)
```csharp
var http = new HttpClient();
var storage = new FileSecureStorage(); // your own ISecureStorage implementation
var logger = LoggerFactory.Create(b => b.AddConsole()).CreateLogger<FirebaseAuthService>();

var auth = new FirebaseAuthService(http, logger, storage, "YOUR_FIREBASE_API_KEY");

var user = await auth.RegisterAsync("user@example.com", "password123");
Console.WriteLine($"Registered user: {user?.Email}");
```

---

## 🧑‍💻 Author
**Imre Szücs**  
Licensed under **MIT**  

---

## 🌟 Contribute
Pull requests and improvements are welcome!  
If you find a bug, please [open an issue](https://github.com/szucsim/FirebaseAuth.NET/issues).
