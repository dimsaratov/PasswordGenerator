using System.ComponentModel;
using System.Runtime.CompilerServices;
using System.Security.Cryptography;
using System.Text;

namespace PasswordGenerator
{
    /// <summary>
    /// Represents configurable settings for password generation.
    /// </summary>
    /// <remarks>
    /// This class holds all parameters required by the <see cref="Generator"/> to produce passwords. It implements <see
    /// cref="INotifyPropertyChanged"/> to facilitate two-way data binding in UI applications (e.g., WPF, MAUI,
    /// WinForms). <para>The settings include:<list type="bullet"><item><description>Character sets (lowercase,
    /// uppercase, digits, symbols) with individual enable/disable flags.</description></item><item><description>Minimum
    /// and maximum password length, with automatic synchronization to keep MinLength ≤
    /// MaxLength.</description></item><item><description>Customizable set of special characters (default:
    /// ~`!@#$%^&amp;*()-_=+[]{};:'"",./&lt;&gt;?|\).</description></item><item><description><see
    /// cref="ExtraCharsPerSet"/> – controls how many additional characters (beyond the guaranteed one) are added from
    /// each enabled set.</description></item></list></para> <para>The <see cref="IsCorrect"/> property validates that
    /// at least one character set is enabled. The <see cref="GetCharacterSet"/> method returns the combined string of
    /// all enabled character sets. The <see cref="GetLength"/> method provides a cryptographically secure random length
    /// within the Min/Max bounds.</para>
    /// </remarks>
    /// <example>
    /// <code>var settings = new GenerationSettings { UseLowercase = true, UseUppercase = true, UseDigits = true,
    /// UseSymbols = true, MinLength = 12, MaxLength = 20, ExtraCharsPerSet = 2, SpecialChars = new[] { '!', '@', '#',
    /// '$', '%' } }; // Verify settings are valid if (settings.IsCorrect) { string password =
    /// Generator.Generate(settings); }</code>
    /// </example>
    public class GenerationSettings : INotifyPropertyChanged
    {
        /// <summary>
        /// The minimum allowed password length value
        /// </summary>
        public const int Minimum = 8;

        /// <summary>
        /// A basic set of special characters for password generation
        /// </summary>
        public const string BaseChars = @"~`!@#$%^&*()-_=+[]{};:'"",./<>?|\";

        #region Variable
        private readonly HashSet<char> allowSpecialChars;
        private readonly HashSet<char> currentSpecialChars = [];
        private PropertyChangedEventHandler? onPropertyChanged;
        private int min = Minimum;
        private int max = 16;
        private bool useUppercase = true;
        private bool useLowercase = true;
        private string symbols = BaseChars;
        #endregion

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
        public string Symbols
        {
            get => symbols;
            set
            {
                ArgumentNullException.ThrowIfNullOrEmpty(value);
                if (symbols != value)
                {
                    SetSpecialCharsInternal([.. value]);
                }
            }
        }

        /// <summary>
        /// Сollection of special characters for password generation. Default value ~`!@#$%^&amp;*()-
        /// _=+[]{};:'"",./&lt;&gt;?|\ The number of special characters must be at least 3
        /// </summary>
        public char[] SpecialChars
        {
            get => [.. currentSpecialChars];
            set
            {
                ArgumentNullException.ThrowIfNull(value);
                SetSpecialCharsInternal(value);
            }
        }

        /// <summary>
        /// Minimum password length. The default value is 8. Values less than 8 are not allowed
        /// </summary>
        public int MinLength
        {
            get => min;
            set
            {
                ValidateLength(value);
                if (min != value)
                {
                    min = value;
                    if (min > MaxLength)
                    {
                        max = min;
                        OnPropertyChanged(nameof(MaxLength));
                    }
                    OnPropertyChanged(nameof(MinLength));
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
                ValidateLength(value);
                if (max != value)
                {
                    max = value;
                    if (max < MinLength)
                    {
                        min = max;
                        OnPropertyChanged(nameof(MinLength));
                    }
                    OnPropertyChanged(nameof(MaxLength));
                }
            }
        }

        /// <summary>
        /// It is guaranteed that at least one character from each active set will be added, and an additional number
        /// will be randomly selected (from 0 to ExtraCharsPerSet - 1). The total number in the set will be at least = 1
        /// + random(0 ... ExtraCharsPerSet-1). Default value = 3
        /// </summary>
        public int ExtraCharsPerSet
        {
            get;
            set
            {
                if (value < 1)
                {
                    throw new ArgumentOutOfRangeException(nameof(value), "ExtraCharsPerSet must be at least 1.");
                }
                if (field != value)
                {
                    field = value;
                    OnPropertyChanged(nameof(ExtraCharsPerSet));
                }
            }
        } = 3;

        /// <summary>
        /// Use uppercase letters. Default value True
        /// </summary>
        public bool UseUppercase
        {
            get => useUppercase;
            set
            {
                if (useUppercase == value)
                {
                    return;
                }

                useUppercase = value;
                if (!value && !UseLowercase)
                {
                    useLowercase = true;
                    OnPropertyChanged(nameof(UseLowercase));
                }
                OnPropertyChanged(nameof(UseUppercase));
            }
        }

        /// <summary>
        /// Use lowercase letters. Default value True
        /// </summary>
        public bool UseLowercase
        {
            get => useLowercase;
            set
            {
                if (useLowercase == value)
                {
                    return;
                }

                useLowercase = value;

                if (!value && !UseUppercase)
                {
                    useUppercase = true;
                    OnPropertyChanged(nameof(UseUppercase));
                }

                OnPropertyChanged(nameof(UseLowercase));
            }
        }

        /// <summary>
        /// Use digital characters. Default value True
        /// </summary>
        public bool UseDigits
        {
            get;
            set
            {
                if (field != value)
                {
                    field = value;
                    OnPropertyChanged(nameof(UseDigits));
                }
            }
        } = true;

        /// <summary>
        /// Use special characters. Default value True
        /// </summary>
        public bool UseSymbols
        {
            get;
            set
            {
                if (field != value)
                {
                    field = value;
                    OnPropertyChanged(nameof(UseSymbols));
                }
            }
        } = true;

        /// <summary>
        /// Returns true if at least one character set is used and false if none of the character sets are used.
        /// </summary>
        public bool IsCorrect => UseUppercase ||
            UseLowercase ||
            UseDigits ||
            (UseSymbols && currentSpecialChars.Count > 0);
        #endregion

        #region Events

        /// <summary>
        /// Occurs when a property value changes.
        /// </summary>
        protected virtual void OnPropertyChanged(PropertyChangedEventArgs e) { onPropertyChanged?.Invoke(this, e); }

        /// <summary>
        /// Occurs when a property value changes.
        /// </summary>
        protected virtual void OnPropertyChanged([CallerMemberName] string? propertyName = null)
        { onPropertyChanged?.Invoke(this, new PropertyChangedEventArgs(propertyName)); }

        /// <summary>
        /// Occurs when a property value changes.
        /// </summary>
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
            allowSpecialChars = [.. BaseChars];
            currentSpecialChars = [.. BaseChars];
            symbols = BaseChars;
        }

        #region Methods

        /// <summary>
        /// Determines whether the specified character set is currently enabled.
        /// </summary>
        /// <param name="characterSet">
        /// The character set to retrieve. Must be one of: <see cref="CharacterSet.Uppercase"/>, <see
        /// cref="CharacterSet.Lowercase"/>, <see cref="CharacterSet.Digits"/>, or <see cref="CharacterSet.Symbols"/>.
        /// </param>
        /// <returns>
        /// <c>true</c> if the character set is enabled; otherwise, <c>false</c>. If the provided name does not match
        /// any known set, <c>false</c> is returned.
        /// </returns>
        /// <exception cref="ArgumentNullException">
        /// Thrown when <paramref name="characterSet"/> is <c>null</c> or an empty string.
        /// </exception>
        /// <remarks>
        /// This method is primarily used by the generator to iterate over all available character sets and determine
        /// which ones should be included in the password.
        /// </remarks>
        /// <example>
        /// <code>var settings = new GenerationSettings(); bool useLower =
        /// settings.UseCharacterSet(nameof(GenerationSettings.Lowercase)); Console.WriteLine($"Lowercase enabled:
        /// {useLower}");</code>
        /// </example>

        public bool UseCharacterSet(CharacterSet characterSet)
        {
            return !Enum.IsDefined(characterSet)
                ? throw new ArgumentException($"Invalid character set: {characterSet}", nameof(characterSet))
                : characterSet switch
                {
                    CharacterSet.Lowercase => UseLowercase,
                    CharacterSet.Uppercase => UseUppercase,
                    CharacterSet.Digits => UseDigits,
                    CharacterSet.Symbols => UseSymbols,
                    _ => false
                };
        }

        /// <summary>
        /// Gets the character string for the specified character set.
        /// </summary>
        /// <param name="characterSet">
        /// The character set to retrieve. Must be one of: <see cref="CharacterSet.Uppercase"/>, <see
        /// cref="CharacterSet.Lowercase"/>, <see cref="CharacterSet.Digits"/>, or <see cref="CharacterSet.Symbols"/>.
        /// </param>
        /// <returns>
        /// A <see cref="CharacterSet"/> containing all characters of the requested set. If <paramref
        /// name="characterSet"/> does not match any known set, an empty string is returned.
        /// </returns>
        /// <exception cref="ArgumentNullException">
        /// Thrown when <paramref name="characterSet"/> is <c>null</c> or an empty string.
        /// </exception>
        /// <remarks>
        /// This indexer provides a convenient way to obtain character set strings by name, primarily used by the <see
        /// cref="Generator"/> during password construction. The available names correspond to the public properties
        /// <see cref="Lowercase"/>, <see cref="Uppercase"/>, <see cref="Digits"/>, and <see cref="Symbols"/>.
        /// </remarks>
        /// <example>
        /// <code>var settings = new GenerationSettings(); string lowercase = settings[CharacterSet.Lowercase];
        /// Console.WriteLine($"Lowercase: {lowercase}");</code>
        /// </example>
        public string this[CharacterSet characterSet] => !Enum.IsDefined(characterSet)
            ? throw new ArgumentException($"Invalid character set: {characterSet}", nameof(characterSet))
            : characterSet switch
            {
                CharacterSet.Uppercase => Uppercase,
                CharacterSet.Lowercase => Lowercase,
                CharacterSet.Digits => Digits,
                CharacterSet.Symbols => Symbols,
                _ => string.Empty
            };

        /// <summary>
        /// Resets the special characters set to the default <see cref="BaseChars"/> value.
        /// </summary>
        /// <remarks>
        /// This method replaces the current <see cref="SpecialChars"/> with the default set
        /// defined by <see cref="BaseChars"/>. If the current set already equals the default set,
        /// no changes are made.
        /// </remarks>
        public void DefaultSpecialChars()
        {
            if (!currentSpecialChars.SetEquals(allowSpecialChars))
            {
                currentSpecialChars.Clear();
                foreach (char c in allowSpecialChars)
                {
                    currentSpecialChars.Add(c);
                }
                symbols = new string([.. currentSpecialChars]);

                OnPropertyChanged(nameof(SpecialChars));
                OnPropertyChanged(nameof(Symbols));
                OnPropertyChanged();
            }
        }

        /// <summary>
        /// If MaxLength is not equal to MinLength, returns an arbitrary length for the password in the range from
        /// MaxLength to minLength, otherwise returns MinLength.
        /// </summary>
        /// <returns></returns>
        public int GetLength()
        { return MinLength == MaxLength ? MinLength : RandomNumberGenerator.GetInt32(MinLength, MaxLength + 1); }

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
                sb.Append(symbols);
            }
            return sb.ToString();
        }

        #region Private Methods
        private static void ValidateLength(
            int value,
            [CallerArgumentExpression(nameof(value))] string? paramName = null)
        {
            if (value < Minimum)
            {
                throw new ArgumentOutOfRangeException(
                    paramName ?? nameof(value),
                    $"{paramName} must be at least {Minimum}.");
            }
        }

        /// <summary>
        /// Sets the special characters from the given array, filtering out unsupported characters.
        /// </summary>
        /// <param name="chars">Array of characters to set.</param>
        /// <exception cref="ArgumentException">Thrown when less than 3 supported characters are provided.</exception>
        private void SetSpecialCharsInternal(char[] chars)
        {
            HashSet<char> validChars = [.. chars.Where(allowSpecialChars.Contains)];
            if (validChars.Count < 3)
            {
                throw new ArgumentException("At least 3 supported special characters must be provided.");
            }

            bool setChanged = !currentSpecialChars.SetEquals(validChars);

            if (setChanged)
            {
                currentSpecialChars.Clear();
                foreach (char c in validChars)
                {
                    currentSpecialChars.Add(c);
                }
            }

            string newSymbols = new([.. currentSpecialChars]);

            if (setChanged || newSymbols != symbols)
            {
                symbols = newSymbols;

                OnPropertyChanged(nameof(SpecialChars));
                OnPropertyChanged(nameof(Symbols));
                OnPropertyChanged();
            }
        }
        #endregion

        #endregion
    }
}
