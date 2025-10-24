using System;

namespace FirebaseAuth.NET.Services
{
    public sealed class FirebaseAuthException : Exception
    {
        public AuthErrorReason Reason { get; }
        public string? ErrorCode { get; }
        public int? StatusCode { get; }

        public FirebaseAuthException(AuthErrorReason reason, string message, string? errorCode = null, int? statusCode = null, Exception? inner = null)
            : base(message, inner)
        {
            Reason = reason;
            ErrorCode = errorCode;
            StatusCode = statusCode;
        }
    }
}
