using MongoDB.Bson;
using MongoDB.Bson.Serialization.Attributes;
using Microsoft.AspNet.Identity;
using System.Collections.Generic;

namespace AspNet.Identity.MongoDB
{
    public class IdentityRole : IRole<string>
    {
        public IdentityRole()
        {
            Id = ObjectId.GenerateNewId().ToString();
            PermissionList = new List<string>();
        }

        public IdentityRole(string roleName)
            : this()
        {
            Name = roleName;
        }

        [BsonRepresentation(BsonType.ObjectId)]
        public string Id { get; private set; }

        public string Name { get; set; }

        public List<string> PermissionList { get; set; }
    }
}
