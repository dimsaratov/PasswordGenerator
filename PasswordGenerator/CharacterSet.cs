namespace PasswordGenerator
{
    /// <summary>
    /// Specifies the character sets that can be used for password generation.
    /// </summary>
    /// <remarks>
    /// This enumeration is marked with the <see cref="FlagsAttribute"/> attribute, allowing multiple character sets to
    /// be combined using bitwise operations (e.g., <c>CharacterSet.Uppercase | CharacterSet.Digits</c>). <para>The flag
    /// values are designed as powers of two to ensure proper bitwise combination:<list
    /// type="table"><listheader><term>Member</term><description>Value</description></listheader><item><term><see
    /// cref="Uppercase"/></term><description>1 (0x01)</description></item><item><term><see
    /// cref="Lowercase"/></term><description>2 (0x02)</description></item><item><term><see
    /// cref="Digits"/></term><description>4 (0x04)</description></item><item><term><see
    /// cref="Symbols"/></term><description>8 (0x08)</description></item></list></para> <para>This enum is used by <see
    /// cref="GenerationSettings"/> to determine which character sets are enabled during password generation. At least
    /// one character set must be selected for the settings to be considered valid (<see
    /// cref="GenerationSettings.IsCorrect"/>).</para>
    /// </remarks>
    /// <example>
    /// <code>// Combine multiple character sets var selectedSets = CharacterSet.Uppercase | CharacterSet.Lowercase |
    /// CharacterSet.Digits;  // Check if a specific set is enabled bool useSymbols = (selectedSets &amp;
    /// CharacterSet.Symbols) == CharacterSet.Symbols;  // Using with GenerationSettings (if extended to support flags)
    /// var settings = new GenerationSettings(); settings.EnabledSets = CharacterSet.Uppercase | CharacterSet.Lowercase
    /// | CharacterSet.Symbols;</code>
    /// </example>
    [Flags]
#pragma warning disable RCS1135 // Declare enum member with zero value (when enum has FlagsAttribute)
    public enum CharacterSet
#pragma warning restore RCS1135 // Declare enum member with zero value (when enum has FlagsAttribute)
    {
        /// <summary>
        /// Use uppercase letters.
        /// </summary>
        Uppercase = 1,
        /// <summary>
        /// Use lowercase letters.
        /// </summary>
        Lowercase = 2,
        /// <summary>
        /// Use digits
        /// </summary>
        Digits = 4,
        /// <summary>
        /// Use special chars
        /// </summary>
        Symbols = 8
    }
}
