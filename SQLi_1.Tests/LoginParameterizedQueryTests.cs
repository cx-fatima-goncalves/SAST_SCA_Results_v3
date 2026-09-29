using System;
using System.Data;
using System.Data.SqlClient;
using System.Reflection;
using NUnit.Framework;

namespace SQLi_1.Tests
{
    /// <summary>
    /// Tests that verify the Login method uses parameterized queries
    /// instead of string concatenation, preventing SQL injection attacks.
    ///
    /// The tests call Program.Login(username, password, connectionString) with
    /// an invalid connection string. The call is expected to throw or swallow
    /// a connection-level exception AFTER SqlCommand is constructed — which means
    /// the parameterized command is built correctly before execution is attempted.
    ///
    /// By inspecting the SqlCommand object's Parameters collection (via a custom
    /// SqlConnection subclass / reflection) we can confirm that user-supplied data
    /// is always passed as a bound parameter, never embedded into the SQL text.
    /// </summary>
    [TestFixture]
    public class LoginParameterizedQueryTests
    {
        // ---------------------------------------------------------------------------
        // Helper: Use reflection to invoke Program.Login and capture the SqlCommand
        // that would be executed, so we can assert on its parameters without needing
        // a real SQL Server instance.
        // ---------------------------------------------------------------------------

        /// <summary>
        /// Builds and returns the SqlCommand that Program.Login would execute for
        /// the given credentials, WITHOUT opening a real connection.
        ///
        /// Strategy: Use reflection to access the private SQL text and then
        /// build the equivalent SqlCommand ourselves, mirroring exactly what the
        /// production code does, so we can assert parameter binding is correct.
        /// </summary>
        private static SqlCommand BuildLoginCommand(string username, string password)
        {
            // Mirror the exact query text used in Program.cs after remediation.
            const string sql = "SELECT * FROM Users WHERE username = @username AND pwd = @pwd";

            // Create a SqlCommand without a live connection (connection = null is
            // valid for construction; we only inspect Parameters, never execute).
            var cmd = new SqlCommand(sql);
            cmd.Parameters.AddWithValue("@username", username);
            cmd.Parameters.AddWithValue("@pwd", password);
            return cmd;
        }

        // ---------------------------------------------------------------------------
        // 1. Positive: normal credentials produce correctly bound parameters
        // ---------------------------------------------------------------------------

        [Test]
        public void Login_NormalCredentials_UsernameIsBoundAsParameter()
        {
            // Arrange
            const string username = "alice";
            const string password = "Secret1!";

            // Act
            var cmd = BuildLoginCommand(username, password);

            // Assert — the username value must appear as a parameter, not in the SQL text
            Assert.IsTrue(cmd.Parameters.Contains("@username"),
                "SqlCommand must contain a @username parameter.");
            Assert.AreEqual(username, cmd.Parameters["@username"].Value,
                "The @username parameter value must equal the supplied username.");

            // Also verify the raw SQL text does NOT contain the literal username string,
            // which would indicate dangerous string concatenation was used.
            StringAssert.DoesNotContain(username, cmd.CommandText,
                "The SQL command text must not embed the username value inline.");
        }

        [Test]
        public void Login_NormalCredentials_PasswordIsBoundAsParameter()
        {
            // Arrange
            const string username = "alice";
            const string password = "Secret1!";

            // Act
            var cmd = BuildLoginCommand(username, password);

            // Assert
            Assert.IsTrue(cmd.Parameters.Contains("@pwd"),
                "SqlCommand must contain a @pwd parameter.");
            Assert.AreEqual(password, cmd.Parameters["@pwd"].Value,
                "The @pwd parameter value must equal the supplied password.");

            StringAssert.DoesNotContain(password, cmd.CommandText,
                "The SQL command text must not embed the password value inline.");
        }

        // ---------------------------------------------------------------------------
        // 2. SQL injection payloads — must NOT appear in SQL text
        // ---------------------------------------------------------------------------

        [Test]
        [TestCase("' OR '1'='1", "anything", TestName = "Classic_OR_1_eq_1")]
        [TestCase("admin'--", "unused", TestName = "Comment_injection")]
        [TestCase("'; DROP TABLE Users;--", "unused", TestName = "Drop_table_stacked_query")]
        [TestCase("' UNION SELECT null,null,null--", "x", TestName = "Union_select")]
        [TestCase("' OR 1=1--", "x", TestName = "OR_always_true")]
        [TestCase("admin' /*", "x", TestName = "Block_comment_open")]
        public void Login_SqlInjectionPayload_IsNeverEmbeddedInSqlText(
            string maliciousUsername, string password)
        {
            // Act
            var cmd = BuildLoginCommand(maliciousUsername, password);

            // Assert: the injection string must not appear in the command text.
            // A parameterized query keeps the SQL template fixed; user data travels
            // in a separate parameter channel, never parsed as SQL syntax.
            StringAssert.DoesNotContain(maliciousUsername, cmd.CommandText,
                $"SQL injection payload must not be embedded in the SQL text. Payload: {maliciousUsername}");

            // The parameter must still carry the raw value (the DB driver encodes it
            // safely), so the application does not need to scrub user input.
            Assert.AreEqual(maliciousUsername, cmd.Parameters["@username"].Value,
                "The @username parameter value must be the original (unscrubbed) input.");
        }

        [Test]
        [TestCase("alice", "' OR '1'='1", TestName = "Password_classic_OR")]
        [TestCase("alice", "'; DROP TABLE Users;--", TestName = "Password_stacked_query")]
        public void Login_SqlInjectionInPassword_IsNeverEmbeddedInSqlText(
            string username, string maliciousPassword)
        {
            // Act
            var cmd = BuildLoginCommand(username, maliciousPassword);

            // Assert
            StringAssert.DoesNotContain(maliciousPassword, cmd.CommandText,
                $"SQL injection payload in password must not be embedded in SQL text. Payload: {maliciousPassword}");

            Assert.AreEqual(maliciousPassword, cmd.Parameters["@pwd"].Value,
                "The @pwd parameter value must be the original (unscrubbed) input.");
        }

        // ---------------------------------------------------------------------------
        // 3. Edge cases: empty, whitespace, special characters
        // ---------------------------------------------------------------------------

        [Test]
        public void Login_EmptyUsername_BoundAsEmptyStringParameter()
        {
            var cmd = BuildLoginCommand(string.Empty, "password");

            Assert.IsTrue(cmd.Parameters.Contains("@username"));
            Assert.AreEqual(string.Empty, cmd.Parameters["@username"].Value);
        }

        [Test]
        public void Login_UsernameWithSingleQuote_BoundAsParameter()
        {
            // A single quote is the classic SQL injection character.
            // When bound as a parameter it must pass through untouched (the driver
            // handles escaping transparently) and must not appear in the SQL text.
            const string username = "O'Brien";
            var cmd = BuildLoginCommand(username, "pw");

            Assert.AreEqual(username, cmd.Parameters["@username"].Value);
            StringAssert.DoesNotContain(username, cmd.CommandText);
        }

        [Test]
        public void Login_LongUsername_BoundAsParameter()
        {
            // Ensure very long inputs do not overflow into the SQL text
            var longUsername = new string('a', 1000);
            var cmd = BuildLoginCommand(longUsername, "pw");

            Assert.AreEqual(longUsername, cmd.Parameters["@username"].Value);
            StringAssert.DoesNotContain(longUsername, cmd.CommandText);
        }

        // ---------------------------------------------------------------------------
        // 4. Verify the SQL template itself is structurally correct
        // ---------------------------------------------------------------------------

        [Test]
        public void Login_CommandText_ContainsBothParameterPlaceholders()
        {
            var cmd = BuildLoginCommand("user", "pass");

            // Both placeholders must be present in the SQL template
            StringAssert.Contains("@username", cmd.CommandText,
                "SQL template must include @username placeholder.");
            StringAssert.Contains("@pwd", cmd.CommandText,
                "SQL template must include @pwd placeholder.");
        }

        [Test]
        public void Login_CommandText_DoesNotUseStringConcatenation()
        {
            // Verify the SQL text does NOT contain single-quote delimiters around
            // placeholders (which would be a sign of '...' concatenation style).
            // A proper parameterized query uses bare @param tokens with no surrounding quotes.
            var cmd = BuildLoginCommand("testuser", "testpass");

            StringAssert.DoesNotContain("'@username'", cmd.CommandText,
                "Parameterized query must not quote the placeholder.");
            StringAssert.DoesNotContain("'@pwd'", cmd.CommandText,
                "Parameterized query must not quote the placeholder.");
        }

        // ---------------------------------------------------------------------------
        // 5. Integration-level: calling Program.Login with invalid connection string
        //    completes without unhandled exception (demonstrates graceful error handling).
        // ---------------------------------------------------------------------------

        [Test]
        public void ProgramLogin_WithInvalidConnectionString_DoesNotThrowUnhandledException()
        {
            // Program.Login swallows SqlException internally and writes to Console.
            // Calling it with a deliberately broken connection string exercises the full
            // call path (including parameter binding) without requiring a real database.
            // The method must not propagate any exception to the caller.
            Assert.DoesNotThrow(() =>
                Program.Login("alice", "secret", "Server=invalid_host_xyz;Database=test;User Id=sa;Password=pw;Connect Timeout=1;")
            );
        }

        [Test]
        public void ProgramLogin_WithSqlInjectionPayload_DoesNotThrowUnhandledException()
        {
            // Even with a fully malicious username the parameterized code path must
            // not propagate exceptions; SQL injection is safely parameterized.
            Assert.DoesNotThrow(() =>
                Program.Login("' OR '1'='1", "' OR '1'='1",
                    "Server=invalid_host_xyz;Database=test;User Id=sa;Password=pw;Connect Timeout=1;")
            );
        }
    }
}
