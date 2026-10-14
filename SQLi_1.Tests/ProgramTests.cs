using System;
using System.Data;
using System.Data.SqlClient;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using SQLi_1;

namespace SQLi_1.Tests
{
    /// <summary>
    /// Tests verifying that the Login SQL command is built with parameterized
    /// queries (not string concatenation), preventing SQL injection (CWE-89).
    /// </summary>
    [TestClass]
    public class ProgramTests
    {
        // -----------------------------------------------------------------------
        // Helpers
        // -----------------------------------------------------------------------

        /// <summary>
        /// Returns the value of the named parameter from a SqlCommand,
        /// or throws if the parameter does not exist.
        /// </summary>
        private static object GetParamValue(SqlCommand cmd, string paramName)
        {
            if (!cmd.Parameters.Contains(paramName))
                throw new ArgumentException($"Parameter '{paramName}' not found in command.");
            return cmd.Parameters[paramName].Value;
        }

        // -----------------------------------------------------------------------
        // 1. Structural / parameterized-query tests
        // -----------------------------------------------------------------------

        [TestMethod]
        [TestCategory("SQLInjection")]
        public void BuildLoginCommand_UsesParameterizedQuery()
        {
            // The command text must contain named placeholders, NOT literal values.
            using (var cmd = Program.BuildLoginCommand("alice", "secret"))
            {
                StringAssert.Contains(cmd.CommandText, "@username",
                    "Query must reference @username placeholder.");
                StringAssert.Contains(cmd.CommandText, "@password",
                    "Query must reference @password placeholder.");
            }
        }

        [TestMethod]
        [TestCategory("SQLInjection")]
        public void BuildLoginCommand_DoesNotConcatenateUsernameIntoQueryText()
        {
            const string user = "alice";
            using (var cmd = Program.BuildLoginCommand(user, "secret"))
            {
                // The literal username value must NOT appear in the SQL text.
                Assert.IsFalse(
                    cmd.CommandText.Contains(user),
                    "Username value must not be embedded in the SQL command text.");
            }
        }

        [TestMethod]
        [TestCategory("SQLInjection")]
        public void BuildLoginCommand_DoesNotConcatenatePasswordIntoQueryText()
        {
            const string pwd = "P@ssw0rd!";
            using (var cmd = Program.BuildLoginCommand("alice", pwd))
            {
                // The literal password value must NOT appear in the SQL text.
                Assert.IsFalse(
                    cmd.CommandText.Contains(pwd),
                    "Password value must not be embedded in the SQL command text.");
            }
        }

        [TestMethod]
        [TestCategory("SQLInjection")]
        public void BuildLoginCommand_HasTwoParameters()
        {
            using (var cmd = Program.BuildLoginCommand("alice", "secret"))
            {
                Assert.AreEqual(2, cmd.Parameters.Count,
                    "Command must have exactly two SqlParameters (@username and @password).");
            }
        }

        [TestMethod]
        [TestCategory("SQLInjection")]
        public void BuildLoginCommand_UsernameParameterCarriesCorrectValue()
        {
            const string user = "bob";
            using (var cmd = Program.BuildLoginCommand(user, "pwd"))
            {
                Assert.AreEqual(user, GetParamValue(cmd, "@username"),
                    "@username parameter must carry the supplied username value.");
            }
        }

        [TestMethod]
        [TestCategory("SQLInjection")]
        public void BuildLoginCommand_PasswordParameterCarriesCorrectValue()
        {
            const string pwd = "MySecret123";
            using (var cmd = Program.BuildLoginCommand("alice", pwd))
            {
                Assert.AreEqual(pwd, GetParamValue(cmd, "@password"),
                    "@password parameter must carry the supplied password value.");
            }
        }

        // -----------------------------------------------------------------------
        // 2. SQL injection payload tests — payloads must not alter query text
        // -----------------------------------------------------------------------

        [TestMethod]
        [TestCategory("SQLInjection")]
        public void BuildLoginCommand_SqlInjectionPayloadInUsername_NotEmbeddedInQuery()
        {
            // Classic OR-based authentication bypass payload
            const string payload = "' OR '1'='1";
            using (var cmd = Program.BuildLoginCommand(payload, "irrelevant"))
            {
                Assert.IsFalse(
                    cmd.CommandText.Contains(payload),
                    "SQL injection payload in username must not appear in command text.");

                // The payload is safely bound as a parameter value
                Assert.AreEqual(payload, GetParamValue(cmd, "@username"),
                    "Payload must be stored verbatim in @username parameter (treated as data).");
            }
        }

        [TestMethod]
        [TestCategory("SQLInjection")]
        public void BuildLoginCommand_SqlInjectionPayloadInPassword_NotEmbeddedInQuery()
        {
            // UNION-based injection attempt
            const string payload = "' UNION SELECT * FROM Users--";
            using (var cmd = Program.BuildLoginCommand("alice", payload))
            {
                Assert.IsFalse(
                    cmd.CommandText.Contains("UNION"),
                    "UNION keyword from injection payload must not appear in command text.");

                Assert.AreEqual(payload, GetParamValue(cmd, "@password"),
                    "Payload must be stored verbatim in @password parameter (treated as data).");
            }
        }

        [TestMethod]
        [TestCategory("SQLInjection")]
        public void BuildLoginCommand_DropTablePayload_NotEmbeddedInQuery()
        {
            // Destructive DDL injection payload
            const string payload = "'; DROP TABLE Users;--";
            using (var cmd = Program.BuildLoginCommand(payload, "pass"))
            {
                Assert.IsFalse(
                    cmd.CommandText.Contains("DROP"),
                    "DROP keyword from injection payload must not appear in command text.");

                Assert.IsFalse(
                    cmd.CommandText.Contains("DROP TABLE"),
                    "DDL statement from injection payload must not appear in command text.");
            }
        }

        [TestMethod]
        [TestCategory("SQLInjection")]
        public void BuildLoginCommand_AlwaysTruePayload_QueryTextUnchanged()
        {
            // Ensure the canonical authentication-bypass payload does not widen the WHERE clause
            const string payload = "admin'--";
            using (var cmd = Program.BuildLoginCommand(payload, "anything"))
            {
                // Only the two placeholders should appear — no comment markers, no tautologies
                Assert.IsFalse(
                    cmd.CommandText.Contains("--"),
                    "SQL comment marker from payload must not appear in command text.");
            }
        }

        // -----------------------------------------------------------------------
        // 3. Edge-case / boundary tests
        // -----------------------------------------------------------------------

        [TestMethod]
        [TestCategory("SQLInjection")]
        public void BuildLoginCommand_EmptyUsername_DoesNotThrow()
        {
            // Empty string is valid data and must be handled gracefully
            using (var cmd = Program.BuildLoginCommand(string.Empty, "secret"))
            {
                Assert.AreEqual(string.Empty, GetParamValue(cmd, "@username"),
                    "@username must hold an empty string without error.");
            }
        }

        [TestMethod]
        [TestCategory("SQLInjection")]
        public void BuildLoginCommand_VeryLongUsername_DoesNotThrow()
        {
            // Oversized input must be accepted as a parameter value without truncation or exception
            var longUsername = new string('a', 1000);
            using (var cmd = Program.BuildLoginCommand(longUsername, "secret"))
            {
                Assert.AreEqual(longUsername, GetParamValue(cmd, "@username"),
                    "@username must store oversized input verbatim.");
            }
        }

        [TestMethod]
        [TestCategory("SQLInjection")]
        public void BuildLoginCommand_UnicodeUsername_DoesNotThrow()
        {
            // Non-ASCII input should be handled without modification
            const string unicodeUser = "中文用户";   // Chinese characters
            using (var cmd = Program.BuildLoginCommand(unicodeUser, "secret"))
            {
                Assert.AreEqual(unicodeUser, GetParamValue(cmd, "@username"),
                    "@username must store Unicode characters verbatim.");
            }
        }

        [TestMethod]
        [TestCategory("SQLInjection")]
        public void BuildLoginCommand_SingleQuoteInUsername_TreatedAsData()
        {
            // Single quotes are the most basic injection character; they must not break the query
            const string user = "O'Brien";
            using (var cmd = Program.BuildLoginCommand(user, "secret"))
            {
                // Value preserved in parameter, not in query text
                Assert.AreEqual(user, GetParamValue(cmd, "@username"),
                    "Single-quoted username must be stored verbatim as a parameter.");

                Assert.IsFalse(
                    cmd.CommandText.Contains("O'Brien"),
                    "Literal username with single quote must not appear in SQL command text.");
            }
        }

        // -----------------------------------------------------------------------
        // 4. Query structure / format invariants
        // -----------------------------------------------------------------------

        [TestMethod]
        [TestCategory("SQLInjection")]
        public void BuildLoginCommand_QueryTextIsConstant_RegardlessOfInput()
        {
            // The command text must be identical for any two inputs —
            // it is a static template, not a dynamically built string.
            using (var cmd1 = Program.BuildLoginCommand("alice", "pass1"))
            using (var cmd2 = Program.BuildLoginCommand("' OR 1=1--", "'; DROP TABLE Users;--"))
            {
                Assert.AreEqual(cmd1.CommandText, cmd2.CommandText,
                    "SQL command text must not change based on user-supplied input.");
            }
        }
    }
}
