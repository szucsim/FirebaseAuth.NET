using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace FirebaseAuth.NET.Services
{
    public sealed class FirebaseUser
    {
        public string IdToken { get; set; } = "";
        public string RefreshToken { get; set; } = "";
        public string LocalId { get; set; } = "";
        public string? Email { get; set; }
        public string? ExpiresIn { get; set; }
        public DateTime ExpiryUtc { get; set; } = DateTime.UtcNow.AddHours(1);
        public bool IsExpired => DateTime.UtcNow >= ExpiryUtc;
    }
}
