namespace FirebaseAuth.NET.Services
{
    /// <summary>
    /// High-level Firebase Authentication service for login, registration, password reset,
    /// account deletion, password change, and token persistence.
    /// </summary>
    public interface IFirebaseAuthService
    {
        /// <summary>
        /// Signs in a user with email and password.
        /// </summary>
        /// <param name="email">The user's email address.</param>
        /// <param name="password">The user's password.</param>
        /// <param name="ct">Cancellation token.</param>
        /// <returns>The authenticated <see cref="FirebaseUser"/> or null on failure.</returns>
        /// <remarks>When options ThrowOnError is enabled, throws <see cref="FirebaseAuthException"/> on error.</remarks>
        Task<FirebaseUser?> LoginAsync(string email, string password, CancellationToken ct = default);

        /// <summary>
        /// Registers a new user with email and password.
        /// </summary>
        /// <param name="email">The email to register.</param>
        /// <param name="password">The password to set for the new user.</param>
        /// <param name="ct">Cancellation token.</param>
        /// <returns>The created <see cref="FirebaseUser"/> or null on failure.</returns>
        /// <remarks>
        /// Returns null immediately when registration is disabled via options.
        /// When ThrowOnError is enabled, throws <see cref="FirebaseAuthException"/> on error.
        /// </remarks>
        Task<FirebaseUser?> RegisterAsync(string email, string password, CancellationToken ct = default);

        /// <summary>
        /// Gets the currently authenticated user from secure storage.
        /// </summary>
        /// <param name="ct">Cancellation token.</param>
        /// <returns>The current <see cref="FirebaseUser"/> or null if not signed in.</returns>
        /// <remarks>
        /// Automatically refreshes the token if expired. When ThrowOnError is enabled, throws on failures.
        /// </remarks>
        Task<FirebaseUser?> GetCurrentUserAsync(CancellationToken ct = default);

        /// <summary>
        /// Sends a password reset email to the specified address.
        /// </summary>
        /// <param name="email">The user's email address.</param>
        /// <param name="ct">Cancellation token.</param>
        /// <returns>True on success; false otherwise.</returns>
        /// <remarks>When ThrowOnError is enabled, throws <see cref="FirebaseAuthException"/> on error.</remarks>
        Task<bool> SendPasswordResetEmailAsync(string email, CancellationToken ct = default);

        /// <summary>
        /// Deletes the currently authenticated account.
        /// </summary>
        /// <param name="ct">Cancellation token.</param>
        /// <returns>True on success; false otherwise.</returns>
        /// <remarks>
        /// Requires a valid current session. On success, clears local user state. Throws when ThrowOnError is enabled.
        /// </remarks>
        Task<bool> UnregisterAsync(CancellationToken ct = default);

        /// <summary>
        /// Changes the password of the currently authenticated user.
        /// </summary>
        /// <param name="newPassword">The new password to set.</param>
        /// <param name="ct">Cancellation token.</param>
        /// <returns>True on success; false otherwise.</returns>
        /// <remarks>
        /// Requires a valid and recent login depending on Firebase policy. Throws when ThrowOnError is enabled.
        /// </remarks>
        Task<bool> ChangePasswordAsync(string newPassword, CancellationToken ct = default);

        /// <summary>
        /// Clears persisted user state and tokens from secure storage.
        /// </summary>
        void Logout();
    }
}
