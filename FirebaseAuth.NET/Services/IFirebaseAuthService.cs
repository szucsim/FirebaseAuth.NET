namespace FirebaseAuth.NET.Services
{
    public interface IFirebaseAuthService
    {
        Task<FirebaseUser?> LoginAsync(string email, string password, CancellationToken ct = default);
        Task<FirebaseUser?> RegisterAsync(string email, string password, CancellationToken ct = default);
        Task<FirebaseUser?> GetCurrentUserAsync(CancellationToken ct = default);
        Task<bool> SendPasswordResetEmailAsync(string email, CancellationToken ct = default);
        void Logout();
    }
}
