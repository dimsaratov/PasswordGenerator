MIT License

Copyright (c) [2026] [Kozupitsa DmA]
Password generator is a cryptographic solution for .NET

Description
The PasswordGenerator library provides a simple and reliable way to generate passwords with a high level of entropy.
It is designed taking into account modern requirements for security and ease of integration into GUI applications (WPF, MAUI, WinForms).

Key features
Cryptographic strength all random numbers are generated through a RandomNumberGenerator (CSPRNG),
which guarantees the unpredictability of passwords. Flexible configuration enable/disable individual character
sets (lowercase, uppercase, numbers, special characters), set the password length range and configure
the set of special characters used. Guaranteed inclusion of all selected types each active character set
will be represented by at least one character in the final password, which ensures compliance 
with complexity policies. Automatic minLength/MaxLength synchronization the values are adjusted to maintain
the correct range. INotifyPropertyChanged support properties notify about changes, which simplifies linking
to the UI.
Efficient mixing the final row is shuffled according to the Fisher/Yates algorithm, eliminating the predictability of the order.

Usage example:

csharp

using PasswordGenerator;

var settings = new GenerationSettings
{
    UseLowercase = true,
    UseUppercase = true,
    UseDigits = true,
    UseSymbols = true,
    MinLength = 12,
    MaxLength = 20,
    ExtraCharsPerSet = 3,
    SpecialChars = new[] { '!', '@', '#', '$', '%' }
};

string password = Generator.Generate(settings);
Console.WriteLine(password);

Technical details
The platform is .NET Standard 2.0+ / .NET 6+.

The namespace is PasswordGenerator.

Classes:

GenerationSettings stores settings, implements INotifyPropertyChanged.
Generator is a static class with the Generate(GenerationSettings) method.

Safety
The generator uses only a cryptographically strong source of entropy.
All character indexes are obtained via RandomNumberGenerator.GetInt32, which ensures uniform distribution.
The password is not stored in memory for longer than the time it was created.
The possibility of creating an empty or invalid password is excluded the checks are built into the logic.

License
The project is distributed under the MIT license.

This solution is ready for use in a production environment and can be easily integrated into any.NET applications that require secure password generation.

