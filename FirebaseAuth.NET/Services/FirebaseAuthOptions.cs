namespace FirebaseAuth.NET.Services
{
    /// <summary>
    /// Configuration options for <see cref="FirebaseAuthService"/>.
    /// </summary>
    public sealed class FirebaseAuthOptions
    {
        /// <summary>
        /// When false, <see cref="IFirebaseAuthService.RegisterAsync(string, string, System.Threading.CancellationToken)"/> will be disabled and return null.
        /// Default is true.
        /// </summary>
        public bool AllowRegistration { get; init; } = true;

        /// <summary>
        /// When true, the service throws <see cref="FirebaseAuthException"/> with <see cref="AuthErrorReason"/>
        /// on failures instead of returning null/false. Default is false.
        /// </summary>
        public bool ThrowOnError { get; init; } = false;
    }
}
