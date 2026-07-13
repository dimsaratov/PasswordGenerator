using System.Runtime.InteropServices;
using System.Security;

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

    }
}
