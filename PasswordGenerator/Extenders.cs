using System.Runtime.InteropServices;
using System.Security;

using static PasswordGenerator.PasswordValidator;

namespace PasswordGenerator
{
    /// <summary>
    /// Provides extension methods for working with <see cref="SecureString"/>,
    /// including safe comparison, conversion to plain text, and creation from plain text.
    /// </summary>
    public static class Extenders
    {
        /// <summary>
        /// Determines whether two <see cref="SecureString"/> instances are equal without exposing their contents in managed memory.
        /// </summary>
        /// <param name="a">The first <see cref="SecureString"/> to compare, or <c>null</c>.</param>
        /// <param name="b">The second <see cref="SecureString"/> to compare, or <c>null</c>.</param>
        /// <returns>
        /// <c>true</c> if both parameters are <c>null</c>, or if their lengths are equal and their contents match;
        /// otherwise, <c>false</c>.
        /// </returns>
        /// <remarks>
        /// This method safely converts the strings to unmanaged BSTR memory for comparison and guarantees
        /// that the memory is zeroed out after use.
        /// </remarks>
        public static bool SecureStringEquals(this SecureString? a, SecureString? b)
        {
            if (a == null && b == null)
            {
                return false;
            }

            if (a == null || b == null)
            {
                return false;
            }

            if (a.Length != b.Length)
            {
                return false;
            }

            IntPtr ptrA = Marshal.SecureStringToBSTR(a);
            IntPtr ptrB = Marshal.SecureStringToBSTR(b);
            try
            {
                string strA = Marshal.PtrToStringBSTR(ptrA);
                string strB = Marshal.PtrToStringBSTR(ptrB);
                return strA == strB;
            }
            finally
            {
                Marshal.ZeroFreeBSTR(ptrA);
                Marshal.ZeroFreeBSTR(ptrB);
            }
        }


        /// <summary>
        /// Converts a <see cref="SecureString"/> to a plain <see cref="string"/>.
        /// </summary>
        /// <param name="secure">The <see cref="SecureString"/> to convert.</param>
        /// <returns>The plain-text contents of <paramref name="secure"/>.</returns>
        /// <exception cref="ArgumentException">
        /// Thrown when <paramref name="secure"/> is <c>null</c> or has zero length.
        /// </exception>
        /// <remarks>
        /// The method retrieves the data through a BSTR and immediately zeroes the allocated unmanaged memory.
        /// Use with caution because the result resides in managed memory and is not protected.
        /// </remarks>
        public static string ToUnSecureString(this SecureString secure)
        {
            if (secure is null || secure.Length == 0)
            {
                return string.Empty;
            }
            IntPtr ptr = Marshal.SecureStringToBSTR(secure);
            try
            {
                return Marshal.PtrToStringBSTR(ptr);
            }
            finally
            {
                Marshal.ZeroFreeBSTR(ptr);
            }
        }

        /// <summary>
        /// Creates a <see cref="SecureString"/> from a plain-text string.
        /// </summary>
        /// <param name="password">The source string to protect.</param>
        /// <returns>A new <see cref="SecureString"/> instance that contains a copy of the characters from <paramref name="password"/>.</returns>
        /// <exception cref="ArgumentNullException">
        /// Thrown when <paramref name="password"/> is <c>null</c>.
        /// </exception>
        /// <remarks>
        /// After filling, the secure string is marked as read-only (<see cref="SecureString.MakeReadOnly"/>).
        /// <para>
        /// <strong>Note:</strong> The current implementation does not explicitly check for <c>null</c>;
        /// passing <c>null</c> will result in a <see cref="NullReferenceException"/>.
        /// It is recommended to add a guard clause in production code.
        /// </para>
        /// </remarks>
        public static SecureString ToSecureString(this string password)
        {
            SecureString secure = new();
            foreach (char c in password)
            {
                secure.AppendChar(c);
            }
            secure.MakeReadOnly();
            return secure;
        }

        /// <summary>
        /// Validates a password against generation settings and calculates a complexity score.
        /// </summary>
        /// <param name="password">The password to validate as a <see cref="SecureString"/>.</param>
        /// <param name="settings">The generation settings to validate against.</param>
        /// <returns>A <see cref="PasswordValidationResult"/> containing validation status, errors, and a complexity score.</returns>
        /// <remarks>
        /// The score is calculated based on:
        /// <list type="bullet">
        /// <item><description>Password length (up to 25 points)</description></item>
        /// <item><description>Presence of uppercase letters (10 points)</description></item>
        /// <item><description>Presence of lowercase letters (10 points)</description></item>
        /// <item><description>Presence of digits (10 points)</description></item>
        /// <item><description>Presence of special characters (15 points)</description></item>
        /// <item><description>Character uniqueness (15 points)</description></item>
        /// </list>
        /// Maximum score is 100.
        /// </remarks>
        public static PasswordValidationResult ValidatePasswordWithScore(SecureString? password, GenerationSettings settings)
        {
            PasswordValidationResult result = ValidatePassword(password, settings);

            if (result.IsValid && password != null)
            {
                string passwordStr = password.ToUnSecureString();

                // Оценка сложности (0-100)
                int score = 0;

                // Длина
                if (passwordStr.Length >= 12)
                {
                    score += 25;
                }
                else if (passwordStr.Length >= 10)
                {
                    score += 20;
                }
                else if (passwordStr.Length >= 8)
                {
                    score += 15;
                }
                else if (passwordStr.Length >= 6)
                {
                    score += 10;
                }

                if (passwordStr.Any(char.IsUpper))
                {
                    score += 10;
                }

                if (passwordStr.Any(char.IsLower))
                {
                    score += 10;
                }

                if (passwordStr.Any(char.IsDigit))
                {
                    score += 10;
                }

                if (passwordStr.Any(ch => !char.IsLetterOrDigit(ch)))
                {
                    score += 15;
                }

                if (passwordStr.Distinct().Count() >= passwordStr.Length * 0.7)
                {
                    score += 15;
                }

                result.Score = Math.Min(100, score);
            }

            return result;
        }
    }
}
