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
        UserDisabled,
        TooManyAttempts,
        InvalidIdToken,
        TokenExpired,
        MissingPassword,
        OperationNotAllowed,
        RequiresRecentLogin,
        NetworkError
    }
}
