using MongoDB.Bson.Serialization.Attributes;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Web;

namespace SimpleAuthService.Models
{
    /// <summary>
    /// entity to store refresh token in DB
    /// </summary>
    [BsonIgnoreExtraElements]
    public class RefreshToken 
    {
        public string RefreshTokenId { get; set; }
        public string Subject { get; set; }
        public string ClientId { get; set; }
        public DateTime IssuedUtc { get; set; }
        public DateTime ExpiresUtc { get; set; }
        public string ProtectedTicket { get; set; }
    }
}