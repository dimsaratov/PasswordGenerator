using System.Text;

namespace PassGenerator
{
    internal static class Program
    {
        private static Tests tests = new();
        private static async Task Main()
        {
            Encoding.RegisterProvider(CodePagesEncodingProvider.Instance);

        again:
            Console.Clear();
            Console.WriteLine();
            Console.WriteLine(new string('*', 75));
            Console.WriteLine($"0 Сформировать пароль");
            Console.WriteLine($"1 Сформировать массив");
        readKey:
            ConsoleKey ki = Console.ReadKey(true).Key;
            switch (ki)
            {
                case ConsoleKey.NumPad0:
                case ConsoleKey.D0:
                    tests.GenerateOne();
                    goto again;
                case ConsoleKey.NumPad1:
                case ConsoleKey.D2:
                    goto again;
                default:
                    Console.Write("\b \b");
                    goto readKey;
            }
        }
    }
}