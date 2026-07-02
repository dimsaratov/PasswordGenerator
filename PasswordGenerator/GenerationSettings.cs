using System.ComponentModel;
using System.Security.Cryptography;
using System.Text;

namespace PasswordGenerator
{
    internal enum CharacterSet
    {
        Lowercase,
        Uppercase,
        Digits,
        Symbols
    }

    /// <summary>
    /// Represents configurable settings for password generation.
    /// </summary>
    /// <remarks>
    /// This class holds all parameters required by the <see cref="Generator"/> to produce passwords.
    /// It implements <see cref="INotifyPropertyChanged"/> to facilitate two-way data binding in UI applications
    /// (e.g., WPF, MAUI, WinForms).
    /// <para>
    /// The settings include:
    /// <list type="bullet">
    /// <item><description>Character sets (lowercase, uppercase, digits, symbols) with individual enable/disable flags.</description></item>
    /// <item><description>Minimum and maximum password length, with automatic synchronization to keep MinLength ≤ MaxLength.</description></item>
    /// <item><description>Customizable set of special characters (default: ~`!@#$%^&amp;*()-_=+[]{};:'"",./&lt;&gt;?|\).</description></item>
    /// <item><description><see cref="ExtraCharsPerSet"/> – controls how many additional characters (beyond the guaranteed one) are added from each enabled set.</description></item>
    /// </list>
    /// </para>
    /// <para>
    /// The <see cref="IsCorrect"/> property validates that at least one character set is enabled.
    /// The <see cref="GetCharacterSet"/> method returns the combined string of all enabled character sets.
    /// The <see cref="GetLength"/> method provides a cryptographically secure random length within the Min/Max bounds.
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
    ///     MaxLength = 20,
    ///     ExtraCharsPerSet = 2,
    ///     SpecialChars = new[] { '!', '@', '#', '$', '%' }
    /// };
    /// // Verify settings are valid
    /// if (settings.IsCorrect)
    /// {
    ///     string password = Generator.Generate(settings);
    /// }
    /// </code>
    /// </example>
    public class GenerationSettings : INotifyPropertyChanged
    {
        private const string baseChars = @"~`!@#$%^&*()-_=+[]{};:'"",./<>?|\";
        private readonly HashSet<char> allowedSet;
        private PropertyChangedEventHandler? onPropertyChanged;
        private int min = 8;
        private int max = 16;

        #region Property

        /// <summary>
        /// String of lowercase
        /// </summary>
        public string Lowercase { get; } = "abcdefghijklmnopqrstuvwxyz";

        /// <summary>
        /// String of uppercase
        /// </summary>
        public string Uppercase { get; } = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";

        /// <summary>
        /// String of digits
        /// </summary>
        public string Digits { get; } = "0123456789";

        /// <summary>
        /// String of special characters
        /// </summary>
        public string Symbols { get; private set; }


        /// <summary>
        /// Minimum password length. The default value is 8. Values less than 8 are not allowed
        /// </summary>
        public int MinLength
        {
            get => min;
            set
            {
                if (min != value && value >= 8)
                {
                    min = value;
                    OnPropertyChanged(new PropertyChangedEventArgs(nameof(MinLength)));
                    if (min > MaxLength)
                    {
                        max = min;
                        OnPropertyChanged(new PropertyChangedEventArgs(nameof(MaxLength)));
                    }
                }
            }
        }

        /// <summary>
        /// Maximum password length. The default value is 16
        /// </summary>
        public int MaxLength
        {
            get => max;
            set
            {
                if (max != value && value >= 8)
                {
                    max = value;
                    OnPropertyChanged(new PropertyChangedEventArgs(nameof(MaxLength)));
                    if (max < MinLength)
                    {
                        min = max;
                        OnPropertyChanged(new PropertyChangedEventArgs(nameof(MinLength)));
                    }
                }
            }
        }

        /// <summary>
        ///It is guaranteed that at least one character
        ///from each active set will be added,
        ///and an additional number will be randomly
        ///selected (from 0 to ExtraCharsPerSet - 1).
        ///The total number in the set will be at
        ///least = 1 + random(0 ... ExtraCharsPerSet-1).
        ///Default value = 3
        /// </summary>
        public int ExtraCharsPerSet
        {
            get;
            set
            {
                if (field != value)
                {
                    field = value;
                    OnPropertyChanged(new(nameof(ExtraCharsPerSet)));
                }
            }
        } = 3;

        /// <summary>
        ///Сollection of special characters for password generation.
        ///Default value ~`!@#$%^&amp;*()-_=+[]{};:'"",./&lt;&gt;?|\
        ///The number of special characters must be at least 3
        /// </summary>
        public char[] SpecialChars
        {
            get;
            set
            {
                ArgumentNullException.ThrowIfNull(value);
                char[] valueChars = GetSpecialChars(value);
                if (valueChars.Length < 3)
                {
                    throw new ArgumentException("The argument does not contain any supported special characters or less than the minimum number (3).");
                }
                field = valueChars;
                Symbols = new(valueChars);
                OnPropertyChanged(new PropertyChangedEventArgs(nameof(SpecialChars)));
            }
        }

        /// <summary>
        ///  Use uppercase letters. Default value True
        /// </summary>
        public bool UseUppercase { get; set; } = true;

        /// <summary>
        /// Use lowercase letters. Default value True
        /// </summary>
        public bool UseLowercase { get; set; } = true;

        /// <summary>
        /// Use digital characters. Default value True
        /// </summary>
        public bool UseDigits { get; set; } = true;

        /// <summary>
        /// Use special characters. Default value True
        /// </summary>
        public bool UseSymbols { get; set; } = true;

        /// <summary>
        /// Returns true if at least one character set is used and false if none of the character sets are used.
        /// </summary>
        public bool IsCorrect
        {
            get
            {
                int i = 0;

                if (UseUppercase)
                {
                    i++;
                }

                if (UseLowercase)
                {
                    i++;
                }

                if (UseDigits)
                {
                    i++;
                }

                if (UseSymbols && SpecialChars.Length > 0)
                {
                    i++;
                }

                return i > 0;
            }
        }
        #endregion

        #region Events

        /// <summary>Occurs when a property value changes.</summary>
        protected virtual void OnPropertyChanged(PropertyChangedEventArgs e) { onPropertyChanged?.Invoke(this, e); }

        /// <summary>Occurs when a property value changes.</summary>
        public event PropertyChangedEventHandler? PropertyChanged
        {
            add => onPropertyChanged += value;
            remove => onPropertyChanged -= value;
        }
        #endregion

        /// <summary>
        /// GenerationSettings – stores settings, implements INotifyPropertyChanged.
        /// </summary>
        public GenerationSettings()
        {
            allowedSet = [.. baseChars];
            Symbols = new(baseChars);
            SpecialChars = [.. allowedSet];
        }

        #region Methods

        /// <summary>
        /// Determines whether the specified character set is currently enabled.
        /// </summary>
        /// <param name="setName">
        /// The name of the character set to check. Must match one of the following:
        /// <c>nameof(Lowercase)</c>, <c>nameof(Uppercase)</c>, <c>nameof(Digits)</c>, or <c>nameof(Symbols)</c>.
        /// </param>
        /// <returns>
        /// <c>true</c> if the character set is enabled; otherwise, <c>false</c>.
        /// If the provided name does not match any known set, <c>false</c> is returned.
        /// </returns>
        /// <exception cref="ArgumentNullException">
        /// Thrown when <paramref name="setName"/> is <c>null</c> or an empty string.
        /// </exception>
        /// <remarks>
        /// This method is primarily used by the generator to iterate over all available character sets
        /// and determine which ones should be included in the password.
        /// </remarks>
        /// <example>
        /// <code>
        /// var settings = new GenerationSettings();
        /// bool useLower = settings.UseCharacterSet(nameof(GenerationSettings.Lowercase));
        /// Console.WriteLine($"Lowercase enabled: {useLower}");
        /// </code>
        /// </example>
        public bool UseCharacterSet(string setName)
        {
            ArgumentNullException.ThrowIfNullOrEmpty(nameof(setName));
            return setName switch
            {
                nameof(Lowercase) => UseLowercase,
                nameof(Uppercase) => UseUppercase,
                nameof(Digits) => UseDigits,
                nameof(Symbols) => UseSymbols,
                _ => false
            };
        }

        /// <summary>
        /// Gets the character string for the specified character set.
        /// </summary>
        /// <param name="setName">
        /// The name of the character set to retrieve. Must match one of the following:
        /// <c>nameof(Lowercase)</c>, <c>nameof(Uppercase)</c>, <c>nameof(Digits)</c>, or <c>nameof(Symbols)</c>.
        /// </param>
        /// <returns>
        /// A <see cref="string"/> containing all characters of the requested set.
        /// If <paramref name="setName"/> does not match any known set, an empty string is returned.
        /// </returns>
        /// <exception cref="ArgumentNullException">
        /// Thrown when <paramref name="setName"/> is <c>null</c> or an empty string.
        /// </exception>
        /// <remarks>
        /// This indexer provides a convenient way to obtain character set strings by name,
        /// primarily used by the <see cref="Generator"/> during password construction.
        /// The available names correspond to the public properties <see cref="Lowercase"/>,
        /// <see cref="Uppercase"/>, <see cref="Digits"/>, and <see cref="Symbols"/>.
        /// </remarks>
        /// <example>
        /// <code>
        /// var settings = new GenerationSettings();
        /// string lowercase = settings[nameof(GenerationSettings.Lowercase)];
        /// Console.WriteLine($"Lowercase: {lowercase}");
        /// </code>
        /// </example>
        public string this[string setName]
        {
            get
            {
                ArgumentNullException.ThrowIfNullOrEmpty(nameof(setName));
                return setName switch
                {
                    nameof(Lowercase) => Lowercase,
                    nameof(Uppercase) => Uppercase,
                    nameof(Digits) => Digits,
                    nameof(Symbols) => Symbols,
                    _ => string.Empty
                };
            }
        }

        /// <summary>
        /// Sets the default set of special characters
        /// </summary>
        public void DefaultSpecialChars()
        {
            SpecialChars = [.. allowedSet];
        }

        /// <summary>
        ///If MaxLength is not equal to MinLength,
        ///returns an arbitrary length for the password
        ///in the range from MaxLength to minLength,
        ///otherwise returns MinLength.
        /// </summary>
        /// <returns></returns>
        public int GetLength()
        {
            return MinLength == MaxLength ? MinLength : RandomNumberGenerator.GetInt32(MinLength, MaxLength + 1);
        }


        /// <summary>
        /// Returns a set of characters for password generation
        /// </summary>
        /// <returns></returns>
        public string GetCharacterSet()
        {
            StringBuilder sb = new();
            if (UseUppercase)
            {
                sb.Append(Uppercase);
            }
            if (UseLowercase)
            {
                sb.Append(Lowercase);
            }

            if (UseDigits)
            {
                sb.Append(Digits);
            }

            if (UseSymbols)
            {
                sb.Append(SpecialChars);
            }
            return sb.ToString();
        }

        private char[] GetSpecialChars(char[] input)
        {
            return [.. input.Where(allowedSet.Contains)];
        }

        #endregion
    }
}
