using PasswordGenerator;

namespace PassGenerator
{
    internal class Tests
    {

        private GenerationSettings settings = new();



        public void DeclareSet()
        {

            Console.Clear();
            Console.WriteLine();
            Console.WriteLine(new string('*', 75));

            Console.WriteLine($"Минимальная длина пароля: {settings.MinLength}");
            string? line = Console.ReadLine();
            if (!string.IsNullOrWhiteSpace(line))
            {
                settings.MinLength = int.Parse(line);
            }

            Console.WriteLine($"Максимальная длина пароля: {settings.MaxLength}");
            line = Console.ReadLine();
            if (!string.IsNullOrWhiteSpace(line))
            {
                settings.MaxLength = int.Parse(line);
            }

            Console.WriteLine("Space: изменить настройки");
            Console.WriteLine("Enter: генерировать новый пароль");
            Console.WriteLine("Esc: выход");

            Console.WriteLine($"Min={settings.MinLength} Max={settings.MaxLength}");
        }


        public void GenerateOne()
        {
            DeclareSet();
        again:
            string password = PasswordGenerator.Generator.Generate(settings);
            Console.WriteLine($"Длина пароля: {password.Length} Pass:  {password}");
        readKey:
            ConsoleKey ki = Console.ReadKey(true).Key;
            switch (ki)
            {
                case ConsoleKey.Spacebar:
                    GenerateOne();
                    return;
                case ConsoleKey.Enter:
                case ConsoleKey.Execute:
                    goto again;
                case ConsoleKey.Escape:
                    Console.Clear();
                    break;
                default:
                    Console.Write("\b \b");
                    goto readKey;
            }
        }
    }
}

