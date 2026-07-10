using System.Collections;
using System.ComponentModel;
using System.Runtime.CompilerServices;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json.Serialization;

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
    public class GenerationSettings : INotifyPropertyChanged, ICloneable, INotifyDataErrorInfo
    {
        /// <summary>
        /// The minimum allowed password length value
        /// </summary>
        public const int Minimum = 8;

        /// <summary>
        /// A basic set of special characters for password generation
        /// </summary>
        public const string BaseChars = @"~!@#$%^&*()-_=+[]{};:'"",./<>?|\";
        private const string lowercaseChars = "abcdefghijklmnopqrstuvwxyz";
        private const string uppercaseChars = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
        private const string digitalChars = "0123456789";

        #region Variable
        private readonly Dictionary<string, List<string>> _errors = [];
        private readonly HashSet<char> allowSpecialChars;
        private readonly HashSet<char> currentSpecialChars = [];
        private PropertyChangedEventHandler? onPropertyChanged;
        private int min = Minimum;
        private int max = 16;
        private bool useUppercase = true;
        private bool useLowercase = true;
        private string symbols = BaseChars;
        private bool useDigits = true;
        private bool useSymbols = true;
        private int extraCharsPerSet = 3;

        /// <summary>
        /// Cached hash code of the <see cref="currentSpecialChars"/> set. Updated whenever the set changes to avoid
        /// recomputing in <see cref="GetHashCode"/>.
        /// </summary>
        private int _symbolsHashCode;
        #endregion

        #region Property

        /// <summary>
        /// String of lowercase
        /// </summary>
        public static string Lowercase => lowercaseChars;

        /// <summary>
        /// String of uppercase
        /// </summary>
        public static string Uppercase => uppercaseChars;

        /// <summary>
        /// String of digits
        /// </summary>
        public static string Digits => digitalChars;

        /// <summary>
        /// String of special characters
        /// </summary>
        public string Symbols
        {
            get => symbols;
            set
            {
                if (symbols != value)
                {
                    SetSpecialCharsInternal(value is null ? null : [.. value]);
                }
            }
        }

        /// <summary>
        /// Collection of special characters for password generation.
        /// </summary>
        /// <remarks>
        /// <para> When setting this property, only characters present in <see cref="BaseChars"/> are retained.</para>
        /// <para><b>Validation:</b> At least 3 supported characters must be provided. If validation fails, an error is
        /// added via <see cref="INotifyDataErrorInfo"/> and the current set remains unchanged.</para>
        /// </remarks>
        [JsonIgnore]
        public char[] SpecialChars { get => [.. currentSpecialChars]; set => SetSpecialCharsInternal(value); }

        /// <summary>
        /// Gets or sets the maximum number of allowed repeated characters in the password.
        /// </summary>
        /// <value>
        /// The maximum number of consecutive duplicate characters allowed.  A value of <c>0</c> disables the check.
        /// </value>
        /// <remarks>
        /// <para> When validating a password, this setting controls how many consecutive  identical characters are
        /// permitted. If a password contains more than  the specified number of repeated characters in a row, the
        /// validation will fail.</para> <para> For example, with <c>RepeatedChars = 2</c>:<list
        /// type="bullet"><item><description>"aa" - allowed (2 repetitions)</description></item><item><description>"aaa"
        /// - not allowed (3 repetitions, exceeds limit)</description></item><item><description>"aaab" - not allowed (3
        /// repetitions)</description></item></list></para> <para> If the value is set to <c>0</c>, the repeated
        /// character check is disabled  and any number of consecutive identical characters will be accepted.</para>
        /// <para> The validation process compares both the old password and the new password  against this setting to
        /// ensure that no password violates the repetition limit.</para> <para> Negative values are not permitted and
        /// will throw an <see cref="ArgumentOutOfRangeException"/>.</para>
        /// </remarks>
        /// <exception cref="ArgumentOutOfRangeException">
        /// Thrown when attempting to set a negative value.
        /// </exception>
        public int ForbiddenRepeatedChars
        {
            get;
            set
            {
                ArgumentOutOfRangeException.ThrowIfNegative(value);
                if (field != value)
                {
                    field = value;
                    OnPropertyChanged(nameof(ForbiddenRepeatedChars));
                }
            }
        } = 6;


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
            get => extraCharsPerSet;
            set
            {
                if (extraCharsPerSet != value)
                {
                    if (value < 1)
                    {
                        AddError(nameof(ExtraCharsPerSet), "ExtraCharsPerSet must be at least 1.");
                    }
                    else
                    {
                        ClearErrors(nameof(ExtraCharsPerSet));
                    }

                    if (value >= 1)
                    {
                        extraCharsPerSet = value;
                    }
                    OnPropertyChanged(nameof(ExtraCharsPerSet));
                }
            }
        }


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
            get => useDigits;
            set
            {
                if (useDigits != value)
                {
                    useDigits = value;
                    OnPropertyChanged(nameof(UseDigits));
                }
            }
        }

        /// <summary>
        /// Use special characters. Default value <c>true</c>.
        /// </summary>
        /// <remarks>
        /// <para> This property determines whether special characters are included in generated passwords. It is not
        /// automatically modified when setting <see cref="SpecialChars"/> or <see cref="Symbols"/>.</para> <para>
        /// However, note that <see cref="SpecialChars"/> validation requires at least 3 supported characters. If you
        /// set an invalid set, an error will be added via <see cref="INotifyDataErrorInfo"/>, and the current set
        /// remains unchanged.</para>
        /// </remarks>
        public bool UseSymbols
        {
            get => useSymbols;
            set
            {
                if (useSymbols != value)
                {
                    useSymbols = value;
                    OnPropertyChanged(nameof(UseSymbols));
                }
            }
        }

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
            _symbolsHashCode = ComputeSymbolsHashCode();
        }

        /// <summary>
        /// Initializes a new instance of the <see cref="GenerationSettings"/> class by copying the values from another
        /// <see cref="GenerationSettings"/> object.
        /// </summary>
        /// <param name="other">
        /// The <see cref="GenerationSettings"/> instance to copy from. This parameter cannot be <c>null</c>.
        /// </param>
        /// <exception cref="ArgumentNullException">
        /// Thrown when <paramref name="other"/> is <c>null</c>.
        /// </exception>
        /// <remarks>
        /// <para> This constructor performs a <b>deep copy</b> of all mutable state:<list
        /// type="bullet"><item><description> The <see cref="currentSpecialChars"/> collection is cloned into a new <see
        /// cref="HashSet{T}"/>, ensuring that changes to the copy do not affect the original and vice
        /// versa.</description></item><item><description> The <see cref="allowSpecialChars"/> collection is <b>not</b>
        /// cloned because it is<c>readonly</c> and never modified after construction. Both instances share the same
        /// reference, which is safe and efficient.</description></item><item><description> All value-type fields (<see
        /// cref="MinLength"/>, <see cref="MaxLength"/>, booleans, etc.) are copied by value, as
        /// expected.</description></item></list></para> <para> This constructor is used internally by the <see
        /// cref="Clone"/> method to provide a deep copy of the settings, and can also be used directly by consumers who
        /// need an independent copy.</para>
        /// </remarks>
        /// <example>
        /// <code> var original = new GenerationSettings { MinLength = 12, UseDigits = false }; var copy = new
        /// GenerationSettings(original); copy.MinLength = 20; // Does not affect 'original'</code>
        /// </example>
        public GenerationSettings(GenerationSettings other)
        {
            ArgumentNullException.ThrowIfNull(other);

            allowSpecialChars = other.allowSpecialChars;
            currentSpecialChars = [.. other.currentSpecialChars];
            symbols = other.symbols;
            min = other.min;
            max = other.max;
            useUppercase = other.useUppercase;
            useLowercase = other.useLowercase;
            useDigits = other.useDigits;
            useSymbols = other.useSymbols;
            extraCharsPerSet = other.extraCharsPerSet;
            _symbolsHashCode = other._symbolsHashCode;
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
        /// This method replaces the current <see cref="SpecialChars"/> with the default set defined by <see
        /// cref="BaseChars"/>. Since <see cref="BaseChars"/> always contains at least 3 characters, the <see
        /// cref="UseSymbols"/> property  will remain or become <c>true</c> if it was previously <c>false</c> (because
        /// the set will be non‑empty).
        /// </remarks>
        public void DefaultSpecialChars() { SetSpecialCharsInternal([.. BaseChars]); }

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
            StringBuilder sb = new(256);
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
        #endregion

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
        /// <remarks>
        /// <para> This method filters <paramref name="chars"/> using the allowed set (<see cref="allowSpecialChars"/>).
        /// Only characters that exist in the allowed set are retained.</para> <para><b>Validation rules:</b><list
        /// type="bullet"><item><description> If <paramref name="chars"/> is <c>null</c>, an error is added for the
        /// properties<see cref="Symbols"/> and <see cref="SpecialChars"/>, and the current set remains
        /// unchanged.</description></item><item><description> If after filtering fewer than 3 valid characters remain,
        /// an error is added for the properties<see cref="Symbols"/> and <see cref="SpecialChars"/>, and the current
        /// set remains unchanged.</description></item><item><description> If at least 3 valid characters are present,
        /// any existing errors for <see cref="Symbols"/> and <see cref="SpecialChars"/> are cleared, and the internal
        /// storage is updated.</description></item></list></para> <para><b>Note:</b> Unlike previous versions, this
        /// method no longer automatically disables<see cref="UseSymbols"/> when the set becomes empty, because an empty
        /// set is now considered invalid and will not be accepted.</para>
        /// </remarks>
        private void SetSpecialCharsInternal(char[]? chars)
        {
            ClearErrors(nameof(Symbols));
            ClearErrors(nameof(SpecialChars));

            if (chars is null)
            {
                AddError(nameof(Symbols), "Special characters array cannot be null.");
                AddError(nameof(SpecialChars), "Special characters array cannot be null.");
                return;
            }

            HashSet<char> validChars = [.. chars.Where(allowSpecialChars.Contains)];

            if (validChars.Count < 3)
            {
                AddError(
                    nameof(Symbols),
                    $"At least 3 supported special characters are required. Provided: {validChars.Count}.");
                AddError(
                    nameof(SpecialChars),
                    $"At least 3 supported special characters are required. Provided: {validChars.Count}.");
                return;
            }

            bool setChanged = !currentSpecialChars.SetEquals(validChars);
            if (setChanged)
            {
                currentSpecialChars.Clear();
                foreach (char c in validChars)
                {
                    currentSpecialChars.Add(c);
                }

                _symbolsHashCode = ComputeSymbolsHashCode();
            }

            string newSymbols = new([.. currentSpecialChars]);
            if (setChanged)
            {
                symbols = newSymbols;
                OnPropertyChanged(nameof(SpecialChars));
                OnPropertyChanged(nameof(Symbols));
                OnPropertyChanged();
            }
        }

        private int ComputeSymbolsHashCode()
        {
            int hash = 0;
            foreach (char c in currentSpecialChars)
            {
                hash ^= c.GetHashCode();
            }
            return hash;
        }
        #endregion

        #region INotifyDataErrorInfo

        /// <inheritdoc/>
        public event EventHandler<DataErrorsChangedEventArgs>? ErrorsChanged;

        /// <inheritdoc/>
        public bool HasErrors => _errors.Count != 0;

        /// <inheritdoc/>
        public IEnumerable GetErrors(string? propertyName)
        {
            return string.IsNullOrEmpty(propertyName)
                ? _errors.SelectMany(x => x.Value)
                : _errors.TryGetValue(propertyName, out List<string>? list) ? list : Enumerable.Empty<string>();
        }

        private void AddError(string propertyName, string error)
        {
            if (!_errors.TryGetValue(propertyName, out List<string>? list))
            {
                list = [];
                _errors[propertyName] = list;
            }
            list.Add(error);
            ErrorsChanged?.Invoke(this, new DataErrorsChangedEventArgs(propertyName));
        }

        private void ClearErrors(string propertyName)
        {
            if (_errors.Remove(propertyName))
            {
                ErrorsChanged?.Invoke(this, new DataErrorsChangedEventArgs(propertyName));
            }
        }
        #endregion

        #region ICloneable

        /// <summary>
        /// Creates a deep copy of the current <see cref="GenerationSettings"/> object.
        /// </summary>
        /// <returns>
        /// A new <see cref="GenerationSettings"/> instance that is a deep copy of the original.
        /// </returns>
        /// <remarks>
        /// <para> This method creates a new instance using the copy constructor, which clones all mutable state,
        /// including the <see cref="currentSpecialChars"/> collection. The resulting object is fully independent of the
        /// original.</para> <para> The <see cref="allowSpecialChars"/> collection is shared between instances because
        /// it is immutable and never modified after construction.</para>
        /// </remarks>
        public GenerationSettings Clone() { return new(this); }

        /// <summary>
        /// Determines whether the current <see cref="GenerationSettings"/> object has the same content as another.
        /// </summary>
        /// <param name="other">The other object to compare with.</param>
        /// <returns>
        /// <c>true</c> if all relevant properties are equal; otherwise, <c>false</c>.
        /// </returns>
        public bool Equals(GenerationSettings? other)
        {
            return other is not null &&
                (ReferenceEquals(this, other) ||
                    (MinLength == other.MinLength &&
                        MaxLength == other.MaxLength &&
                        UseUppercase == other.UseUppercase &&
                        UseLowercase == other.UseLowercase &&
                        UseDigits == other.UseDigits &&
                        UseSymbols == other.UseSymbols &&
                        ExtraCharsPerSet == other.ExtraCharsPerSet &&
                        currentSpecialChars.SetEquals(other.currentSpecialChars)));
        }

        /// <inheritdoc/>
        public override bool Equals(object? obj) { return Equals(obj as GenerationSettings); }

        /// <inheritdoc/>
        public override int GetHashCode()
        {
            int hash = HashCode.Combine(
                MinLength,
                MaxLength,
                UseUppercase,
                UseLowercase,
                UseDigits,
                UseSymbols,
                ExtraCharsPerSet);
            return HashCode.Combine(hash, _symbolsHashCode);
        }

        /// <summary>
        /// Determines whether two <see cref="GenerationSettings"/> objects are equal by content.
        /// </summary>
        /// <param name="left">The first object.</param>
        /// <param name="right">The second object.</param>
        /// <returns><c>true</c> if equal; otherwise, <c>false</c>.</returns>
        public static bool operator ==(GenerationSettings? left, GenerationSettings? right)
        {
            return Equals(left, right);
        }

        /// <summary>
        /// Determines whether two <see cref="GenerationSettings"/> objects are not equal by content.
        /// </summary>
        public static bool operator !=(GenerationSettings? left, GenerationSettings? right)
        {
            return !Equals(left, right);
        }

        object ICloneable.Clone() { return Clone(); }
        #endregion
    }
}
