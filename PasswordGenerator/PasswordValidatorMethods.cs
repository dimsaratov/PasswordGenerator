using System.Security;

namespace PasswordGenerator
{
    /// <summary>
    /// Provides password validation functionality against generation settings.
    /// </summary>
    public static partial class PasswordValidator
    {
        /// <summary>
        /// Calculates the complexity score for a password.
        /// </summary>
        /// <param name="passwordStr">The password as a plain string.</param>
        /// <returns>A complexity score between 0 and 100.</returns>
        private static int CalculateComplexityScore(string passwordStr)
        {
            int score = 0;

            score += CalculateLengthScore(passwordStr.Length);
            score += CalculateCharacterTypeScore(passwordStr);
            score += CalculateUniquenessScore(passwordStr);

            return score;
        }

        /// <summary>
        /// Calculates the length-based portion of the complexity score.
        /// </summary>
        /// <param name="length">The password length.</param>
        /// <returns>Score contribution from length (0-35 points).</returns>
        private static int CalculateLengthScore(int length)
        {
            if (length >= 16)
            {
                return 35;
            }
            else if (length >= 14)
            {
                return 25;
            }
            else if (length >= 12)
            {
                return 20;
            }
            else if (length >= 10)
            {
                return 15;
            }
            else if (length >= 8)
            {
                return 10;
            }

            return 0;
        }

        /// <summary>
        /// Calculates the character type-based portion of the complexity score.
        /// </summary>
        /// <param name="passwordStr">The password as a plain string.</param>
        /// <returns>Score contribution from character types (0-45 points).</returns>
        private static int CalculateCharacterTypeScore(string passwordStr)
        {
            int score = 0;

            // Use uppercase characters
            if (passwordStr.Any(char.IsUpper))
            {
                score += 10;
            }

            // Use lowercase characters
            if (passwordStr.Any(char.IsLower))
            {
                score += 10;
            }

            // Use digit characters
            if (passwordStr.Any(char.IsDigit))
            {
                score += 10;
            }

            // Use special characters
            if (passwordStr.Any(ch => !char.IsLetterOrDigit(ch)))
            {
                score += 15;
            }

            return score;
        }

        /// <summary>
        /// Calculates the uniqueness-based portion of the complexity score.
        /// </summary>
        /// <param name="passwordStr">The password as a plain string.</param>
        /// <returns>Score contribution from character uniqueness (0-20 points).</returns>
        private static int CalculateUniquenessScore(string passwordStr)
        {
            // Check if at least 50% of characters are unique
            return passwordStr.Distinct().Count() >= (int)(passwordStr.Length * 0.5) ? 20 : 0;
        }

        /// <summary>
        /// Checks if the password is null or empty.
        /// </summary>
        /// <param name="password">The password to check.</param>
        /// <returns><c>true</c> if the password is null or has zero length; otherwise, <c>false</c>.</returns>
        public static bool IsPasswordNullOrEmpty(this SecureString? password)
        { return password == null || password.Length == 0; }

        /// <summary>
        /// Validates the minimum length requirement.
        /// </summary>
        /// <param name="passwordStr">The password as a plain string.</param>
        /// <param name="settings">The generation settings.</param>
        /// <param name="result">The validation result to update.</param>
        private static void ValidateMinLength(
            string passwordStr,
            GenerationSettings settings,
            PasswordValidationResult result)
        {
            if (passwordStr.Length < settings.MinLength)
            {
                result.IsValid = false;
                result.Errors
                    .Add($"Minimum password length is {settings.MinLength} characters (current: {passwordStr.Length})");
            }
        }

        /// <summary>
        /// Validates the maximum length requirement.
        /// </summary>
        /// <param name="passwordStr">The password as a plain string.</param>
        /// <param name="settings">The generation settings.</param>
        /// <param name="result">The validation result to update.</param>
        private static void ValidateMaxLength(
            string passwordStr,
            GenerationSettings settings,
            PasswordValidationResult result)
        {
            if (passwordStr.Length > settings.MaxLength)
            {
                result.IsValid = false;
                result.Errors
                    .Add($"Maximum password length is {settings.MaxLength} characters (current: {passwordStr.Length})");
            }
        }

        /// <summary>
        /// Validates the uppercase letters requirement.
        /// </summary>
        /// <param name="passwordStr">The password as a plain string.</param>
        /// <param name="settings">The generation settings.</param>
        /// <param name="result">The validation result to update.</param>
        private static void ValidateUppercase(
            string passwordStr,
            GenerationSettings settings,
            PasswordValidationResult result)
        {
            if (settings.UseUppercase && !passwordStr.Any(char.IsUpper))
            {
                result.IsValid = false;
                result.Errors.Add("Password must contain at least one uppercase letter");
            }
        }

        /// <summary>
        /// Validates the lowercase letters requirement.
        /// </summary>
        /// <param name="passwordStr">The password as a plain string.</param>
        /// <param name="settings">The generation settings.</param>
        /// <param name="result">The validation result to update.</param>
        private static void ValidateLowercase(
            string passwordStr,
            GenerationSettings settings,
            PasswordValidationResult result)
        {
            if (settings.UseLowercase && !passwordStr.Any(char.IsLower))
            {
                result.IsValid = false;
                result.Errors.Add("Password must contain at least one lowercase letter");
            }
        }

        /// <summary>
        /// Validates the digits requirement.
        /// </summary>
        /// <param name="passwordStr">The password as a plain string.</param>
        /// <param name="settings">The generation settings.</param>
        /// <param name="result">The validation result to update.</param>
        private static void ValidateDigits(
            string passwordStr,
            GenerationSettings settings,
            PasswordValidationResult result)
        {
            if (settings.UseDigits && !passwordStr.Any(char.IsDigit))
            {
                result.IsValid = false;
                result.Errors.Add("Password must contain at least one digit");
            }
        }

        /// <summary>
        /// Validates the special characters requirement.
        /// </summary>
        /// <param name="passwordStr">The password as a plain string.</param>
        /// <param name="settings">The generation settings.</param>
        /// <param name="result">The validation result to update.</param>
        private static void ValidateSpecialCharacters(
            string passwordStr,
            GenerationSettings settings,
            PasswordValidationResult result)
        {
            if (!(!settings.UseSymbols || passwordStr.Any(ch => !char.IsLetterOrDigit(ch))))
            {
                result.IsValid = false;
                result.Errors.Add("Password must contain at least one special character");
            }
        }

        /// <summary>
        /// Validates that the password contains only allowed characters.
        /// </summary>
        /// <param name="passwordStr">The password as a plain string.</param>
        /// <param name="settings">The generation settings.</param>
        /// <param name="result">The validation result to update.</param>
        /// <remarks>
        /// Allowed characters are: <list type="bullet"><item><description>Letters (uppercase and lowercase) - always
        /// allowed</description></item><item><description>Digits - always
        /// allowed</description></item><item><description>Special characters - only those specified in <see
        /// cref="GenerationSettings.SpecialChars"/></description></item></list>
        /// </remarks>
        private static void ValidateAllowedCharacters(
            string passwordStr,
            GenerationSettings settings,
            PasswordValidationResult result)
        {
            if (settings.SpecialChars?.Length == 0)
            {
                return;
            }

            // Find characters that are not letters, not digits, and not in SpecialChars
            List<char> notAllowedFound = [ ..passwordStr
                .Where(ch => !char.IsLetterOrDigit(ch) && !settings.SpecialChars.Contains(ch))
                .Distinct() ];

            if (notAllowedFound.Count != 0)
            {
                result.IsValid = false;
                result.Errors
                    .Add(
                        $"Password contains not allowed special characters:\n" +
                        $"{string.Join(", ", notAllowedFound.Select(c => $"'{c}'"))}");
            }
        }

        /// <summary>
        /// Validates that the number of characters common to both old and new passwords  does not exceed the allowed
        /// limit.
        /// </summary>
        /// <param name="newPassword">The new password as a plain string.</param>
        /// <param name="oldPassword">The old password as a plain string.</param>
        /// <param name="settings">The generation settings.</param>
        /// <param name="result">The validation result to update.</param>
        private static void ValidateRepeatedCharacters(
            string newPassword,
            SecureString? oldPassword,
            GenerationSettings settings,
            PasswordValidationResult result)
        {
            if (oldPassword.IsPasswordNullOrEmpty())
            {
                return;
            }

#pragma warning disable CS8604 // ¬озможно, аргумент-ссылка, допускающий значение NULL.
            string oldPass = oldPassword.ToUnSecureString();
#pragma warning restore CS8604 // ¬озможно, аргумент-ссылка, допускающий значение NULL.

            if (settings.ForbiddenRepeatedChars <= 0 || string.IsNullOrEmpty(oldPass))
            {
                return;
            }

            // Find characters that exist in both passwords
            IEnumerable<char> commonChars = newPassword.Intersect(oldPass);
            int commonCount = commonChars.Count();

            if (commonCount > settings.ForbiddenRepeatedChars)
            {
                result.IsValid = false;
                result.Errors
                    .Add($"Password shares {commonCount} characters with the old password.\n" +
                         $"Maximum allowed is {settings.ForbiddenRepeatedChars}.\n" +
                         $"Common characters: {string.Join(", ", commonChars)}");
            }
        }
    }
}