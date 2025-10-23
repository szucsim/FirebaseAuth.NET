namespace FirebaseAuth.NET.Services
{
    public sealed class FirebaseAuthOptions
    {
        // When false, RegisterAsync will be disabled and return null.
        public bool AllowRegistration { get; init; } = true;
    }
}
