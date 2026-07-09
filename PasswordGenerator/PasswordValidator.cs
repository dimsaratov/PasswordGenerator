using System.Security;

namespace PasswordGenerator
{
    /// <summary>
    /// Provides password validation functionality against generation settings.
    /// </summary>
    public static class PasswordValidator
    {
        /// <summary>
        /// Checks whether the password matches the specified generation settings.
        /// </summary>
        /// <param name="password">The password to validate as a <see cref="SecureString"/>.</param>
        /// <param name="settings">The generation settings to validate against.</param>
        /// <param name="oldPassword">
        /// The old password to validate as a <see cref="SecureString"/> to check the number of duplicate characters.
        /// </param>
        /// <returns>A <see cref="PasswordValidationResult"/> containing validation status and any errors.</returns>
        /// <remarks>
        /// The validation checks the following criteria based on the settings: <list
        /// type="bullet">///<item><description>Password is not null or empty</description></item> ///
        /// <item><description>Minimum and maximum length requirements</description></item> ///
        /// <item><description>Presence of uppercase letters (if<see cref="GenerationSettings.UseUppercase"/> is
        /// enabled)</description></item> ///<item><description>Presence of lowercase letters (if <see
        /// cref="GenerationSettings.UseLowercase"/> is enabled)</description></item> /// <item><description>Presence of
        /// digits (if <see cref="GenerationSettings.UseDigits"/> is enabled)</description></item> ///
        /// <item><description>Presence of special characters (if <see cref="GenerationSettings.UseSymbols"/> is
        /// enabled)</description></item> ///<item><description>Presence of allowed characters (if <see
        /// cref="GenerationSettings.SpecialChars"/> is specified)</description></item> /// <item><description>Presence
        /// number of repeated characters (if <see cref="GenerationSettings.ForbiddenRepeatedChars"/> is
        /// specified)</description></item> ///</list>
        /// </remarks>
        public static PasswordValidationResult ValidatePassword(
            SecureString? password,
            GenerationSettings settings,
            SecureString? oldPassword = null)
        {
            PasswordValidationResult result = new();

            // Check if password is null or empty
            if (IsPasswordNullOrEmpty(password))
            {
                result.IsValid = false;
                result.Errors.Add("Password cannot be empty");
                return result;
            }

            // Convert to plain string for validation
#pragma warning disable CS8604 // ¬озможно, аргумент-ссылка, допускающий значение NULL.
            string passwordStr = password.ToUnSecureString();
#pragma warning restore CS8604 // ¬озможно, аргумент-ссылка, допускающий значение NULL.

            // Validate minimum length
            ValidateMinLength(passwordStr, settings, result);

            // Validate maximum length
            ValidateMaxLength(passwordStr, settings, result);

            // Validate uppercase letters requirement
            ValidateUppercase(passwordStr, settings, result);

            // Validate lowercase letters requirement
            ValidateLowercase(passwordStr, settings, result);

            // Validate digits requirement
            ValidateDigits(passwordStr, settings, result);

            // Validate special characters requirement
            ValidateSpecialCharacters(passwordStr, settings, result);

            // Validate allowed characters
            ValidateAllowedCharacters(passwordStr, settings, result);

            // Validate repeated characters
            ValidateRepeatedCharacters(passwordStr, oldPassword, settings, result);

            return result;
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
                    .Add($"Password contains not allowed special characters: {string.Join(", ", notAllowedFound.Select(c => $"'{c}'"))}");
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
                    .Add(
                        $"Password shares {commonCount} characters with the old password. " +
                            $"Maximum allowed is {settings.ForbiddenRepeatedChars}. " +
                            $"Common characters: {string.Join(", ", commonChars)}");
            }
        }



    }
}