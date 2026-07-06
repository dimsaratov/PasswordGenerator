using System.Security;
using System.Security.Cryptography;
using System.Text;

namespace PasswordGenerator
{
    /// <summary>
    /// Provides password generation functionality using cryptographically secure random number generation.
    /// </summary>
    /// <remarks>
    /// This static class contains the core generation logic. It works in conjunction with <see cref="GenerationSettings"/>
    /// to produce passwords that meet the specified complexity requirements.
    /// <para>
    /// The generation process guarantees that each enabled character set (lowercase, uppercase, digits, symbols)
    /// is represented at least once in the final password. Additional characters are added randomly, and the entire
    /// string is shuffled using the Fisher-Yates algorithm to eliminate any predictable order.
    /// </para>
    /// <para>
    /// All random operations are performed using <see cref="System.Security.Cryptography.RandomNumberGenerator"/>,
    /// which provides a cryptographically strong source of entropy and ensures uniform distribution of characters.
    /// </para>
    /// </remarks>
    /// <example>
    /// <code>
    /// var settings = new GenerationSettings
    /// {
    ///     UseLowercase = true,
    ///     UseUppercase = true,
    ///     UseDigits = true,
    ///     UseSymbols = true,
    ///     MinLength = 12,
    ///     MaxLength = 20
    /// };
    /// string password = Generator.Generate(settings);
    /// </code>
    /// </example>
    public static class Generator
    {
        private static readonly string[] setNames = Enum.GetNames<CharacterSet>();

        /// <summary>
        /// A static method for generating a password as a string Generate(GenerationSettings).
        /// </summary>
        /// <param name="settings"></param>
        /// <returns></returns>
        /// <exception cref="InvalidOperationException"></exception>
        public static string Generate(GenerationSettings settings)
        {
            if (!settings.IsCorrect)
            {
                throw new InvalidOperationException("No character sets selected.");
            }

            StringBuilder result = new();
            BaseFill(result, settings);
            string charSet = settings.GetCharacterSet();

            int length = settings.GetLength();
            for (int i = result.Length; i < length; i++)
            {
                result.Append(GetRandomChar(charSet));
            }
            return ShuffleString(result.ToString());
        }

        /// <summary>
        /// A static method for generating a password as a Secure String Generate(GenerationSettings).
        /// </summary>
        /// <param name="settings"></param>
        /// <returns></returns>
        /// <exception cref="InvalidOperationException"></exception>
        public static SecureString GenerateAsSecure(GenerationSettings settings)
        {
            return Generate(settings).ToSecureString();
        }

        private static void BaseFill(StringBuilder result, GenerationSettings settings)
        {
            foreach (string name in setNames)
            {
                if (settings.UseCharacterSet(name))
                {
                    int k = RandomNumberGenerator.GetInt32(0, settings.ExtraCharsPerSet);
                    result.Append(GetRandomChar(settings[name]));
                    for (int i = 0; i < k; i++)
                    {
                        result.Append(GetRandomChar(settings[name]));
                    }
                }
            }
        }

        private static char GetRandomChar(string source)
        {
            int index = RandomNumberGenerator.GetInt32(0, source.Length);
            return source[index];
        }

        private static string ShuffleString(string input)
        {
            char[] chars = input.ToCharArray();
            for (int i = chars.Length - 1; i > 0; i--)
            {
                int j = RandomNumberGenerator.GetInt32(0, i + 1);
                (chars[i], chars[j]) = (chars[j], chars[i]);
            }
            return new string(chars);
        }
    }
}

