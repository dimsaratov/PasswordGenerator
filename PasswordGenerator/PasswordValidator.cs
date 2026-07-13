using System.Security;

namespace PasswordGenerator
{
    /// <summary>
    /// Provides password validation functionality against generation settings.
    /// </summary>
    public static partial class PasswordValidator
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
        /// Validates a password against generation settings and calculates a complexity score.
        /// </summary>
        /// <param name="password">The new password to validate as a <see cref="SecureString"/>.</param>
        /// <param name="settings">The generation settings to validate against.</param>
        /// <param name="oldPassword">The old password to check for duplicate characters in the new password as a <see cref="SecureString"/>.</param>
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
        public static PasswordValidationResult ValidatePasswordWithScore(SecureString? password,
                                                                 GenerationSettings settings,
                                                                 SecureString? oldPassword = null)
        {
            PasswordValidationResult result = ValidatePassword(password, settings, oldPassword);

            if (password != null)
            {
                string passwordStr = password.ToUnSecureString();

                int score = CalculateComplexityScore(passwordStr);
                result.Score = Math.Min(100, score);
            }
            return result;
        }


        /// <summary>
        /// Calculates the complexity score for a password.
        /// </summary>
        /// <param name="password">The password as a plain secure string.</param>
        /// <returns>A complexity score between 0 and 100.</returns>
        public static int CalculateComplexityScore(SecureString password)
        {
            return CalculateCharacterTypeScore(password.ToUnSecureString());
        }
    }
}