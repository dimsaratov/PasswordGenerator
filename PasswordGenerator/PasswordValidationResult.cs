namespace PasswordGenerator
{
    /// <summary>
    /// Represents the result of a password validation operation.
    /// </summary>
    public class PasswordValidationResult
    {
        /// <summary>
        /// Gets or sets a value indicating whether the password meets all the requirements.
        /// </summary>
        public bool IsValid { get; set; } = true;

        /// <summary>
        /// Gets or sets the list of errors describing why the password does not meet the requirements.
        /// </summary>
        public List<string> Errors { get; set; } = [];

        /// <summary>
        /// Gets or sets the complexity score of the password (0-100).
        /// </summary>
        /// <remarks>
        /// A higher score indicates a stronger password. This value is only meaningful
        /// when <see cref="IsValid"/> is <c>true</c>.
        /// </remarks>
        public int Score { get; set; }

        /// <summary>
        /// Returns a string representation of the validation result.
        /// </summary>
        /// <returns>
        /// A message indicating success if <see cref="IsValid"/> is <c>true</c>;
        /// otherwise, a newline-separated list of all validation errors.
        /// </returns>
        public override string ToString()
        {
            return IsValid ? "The password meets all the requirements" : string.Join(Environment.NewLine, Errors);
        }
    }
}