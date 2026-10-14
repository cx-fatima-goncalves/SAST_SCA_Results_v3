using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Data.SqlClient;

namespace SQLi_1
{
    class Program
    {
        static void Main(string[] args)
        {
            try
            {
                var user = args[0];
                var pwd = Encrypt(args[1]);
                Login(user, pwd);
				var password1 = "1!.Acjjjj111";
            }
            catch  
            {

                Console.WriteLine("An error has occurred !!");
            }
            
        }

        private static  string Encrypt(string plain)
        {
            return plain;
        }

        private static void Login(string username,string password)
        {
            try
            {
                using (var conn = new SqlConnection("conn..."))
                {
                    // Use parameterized query to prevent SQL injection
                    using (var cmd = BuildLoginCommand(username, password))
                    {
                        cmd.Connection = conn;
                        cmd.ExecuteScalar();
                    }

                }
            }
            catch
            {

                Console.WriteLine("An error has occurred !!");
            }

        }

        /// <summary>
        /// Builds a parameterized SqlCommand for the login query.
        /// User-supplied values are bound as SqlParameter objects,
        /// never concatenated into the query string, preventing SQL injection.
        /// </summary>
        internal static SqlCommand BuildLoginCommand(string username, string password)
        {
            var sql = "SELECT * FROM Users WHERE username = @username AND pwd = @password";
            var cmd = new SqlCommand(sql);
            cmd.Parameters.AddWithValue("@username", username);
            cmd.Parameters.AddWithValue("@password", password);
            return cmd;
        }
    }
}

