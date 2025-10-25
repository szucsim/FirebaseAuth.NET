using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace FirebaseAuth.NET.Services
{
    /// <summary>
    /// Represents an authenticated Firebase user and current token state.
    /// </summary>
    public sealed class FirebaseUser
    {
        /// <summary>
        /// The OAuth2 access token returned by Firebase.
        /// </summary>
        public string IdToken { get; set; } = "";
        /// <summary>
        /// The refresh token for obtaining new access tokens.
        /// </summary>
        public string RefreshToken { get; set; } = "";
        /// <summary>
        /// The Firebase local user id (UID).
        /// </summary>
        public string LocalId { get; set; } = "";
        /// <summary>
        /// The user's email address, if provided by Firebase.
        /// </summary>
        public string? Email { get; set; }
        /// <summary>
        /// Expires-in (seconds) as returned by Firebase (string per API schema).
        /// </summary>
        public string? ExpiresIn { get; set; }
        /// <summary>
        /// UTC timestamp when IdToken expires, computed from ExpiresIn.
        /// </summary>
        public DateTime ExpiryUtc { get; set; } = DateTime.UtcNow.AddHours(1);
        /// <summary>
        /// Indicates whether the current IdToken is expired (UtcNow >= ExpiryUtc).
        /// </summary>
        public bool IsExpired => DateTime.UtcNow >= ExpiryUtc;
    }
}
