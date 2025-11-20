namespace FirebaseAuth.NET.Services
{
    public enum AuthErrorReason
    {
        Unknown = 0,
        EmailExists,
        InvalidEmailAddress,
        WeakPassword,
        EmailNotFound,
        InvalidPassword,
        InvalidLoginCredentials,
        UserDisabled,
        TooManyAttempts,
        InvalidIdToken,
        TokenExpired,
        MissingPassword,
        OperationNotAllowed,
        RequiresRecentLogin,
        NetworkError,
        MissingRefreshToken,
        InvalidRefreshToken
    }
}
