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
				var password = "1!.Acjjjj";
				var password = "1123456dD.";
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

        private static void Login(string username, string password)
        {
            Login(username, password, "conn...");
        }

        // Internal overload accepts a connection string so that tests can supply
        // a known-invalid connection string and verify command construction.
        internal static void Login(string username, string password, string connectionString)
        {
            try
            {
                using (var conn = new SqlConnection(connectionString))
                {
                    // Use a parameterized query to prevent SQL injection.
                    // Parameters are passed separately from the SQL text, so user-supplied
                    // values are never interpreted as SQL syntax.
                    var sql = "SELECT * FROM Users WHERE username = @username AND pwd = @pwd";
                    using (var cmd = new SqlCommand(sql, conn))
                    {
                        cmd.Parameters.AddWithValue("@username", username);
                        cmd.Parameters.AddWithValue("@pwd", password);
                        cmd.ExecuteScalar();
                    }
                }
            }
            catch
            {
                Console.WriteLine("An error has occurred !!");
            }
        }
    }
}

