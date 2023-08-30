namespace InfoSec
{
    public static class ConsoleMessages
    {
        public static void PrintMenu()
        {
            Console.WriteLine("Choose an action:");
            Console.WriteLine("1) Cipher");
            Console.WriteLine("2) Decipher");
            Console.WriteLine("Q) Quit");
        }

        public static void InvalidInput()
        {
            Console.WriteLine("Your input is invalid, try again.");
        }

        public static void SelectCipher(Type[] ciphers)
        {
            Console.WriteLine("Select cipher:");

            for (int i = 0; i < ciphers.Count(); i++)
            {
                Console.WriteLine($"{i}) {ciphers[i].Name};");
            }
        }

        public static void SelectFile()
        {
            Console.WriteLine("Enter filename to cipher / decipher:");
        }

        public static void Farewell()
        {
            Console.WriteLine("See you soon.");
        }
    }
}
