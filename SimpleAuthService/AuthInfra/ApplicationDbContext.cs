using AspNet.Identity.MongoDB;
using MongoDB.Driver;
using System;
using System.Collections.Generic;
using System.Configuration;
using System.Linq;
using System.Web;

namespace SimpleAuthService.AuthInfra
{
    public class ApplicationDbContext :IDisposable
    {

        public IMongoCollection<IdentityRole> Roles { get; set; }

        public IMongoCollection<ApplicationUser> Users { get; set; }

        public static ApplicationDbContext Create()
        {
            // todo add settings where appropriate to switch server & database in your own application
            var client = new MongoClient(ConfigurationManager.ConnectionStrings["MongoDBConnection"].ConnectionString);
            var database = client.GetDatabase(ConfigurationManager.AppSettings["MongoDBName"]);
            var users = database.GetCollection<ApplicationUser>("users");
            var roles = database.GetCollection<IdentityRole>("roles");
            return new ApplicationDbContext(users, roles);
        }

        private ApplicationDbContext(IMongoCollection<ApplicationUser> users, IMongoCollection<IdentityRole> roles)
        {
            Users = users;
            Roles = roles;
        }

        public void Dispose()
        {
            throw new NotImplementedException();
        }
    }
}