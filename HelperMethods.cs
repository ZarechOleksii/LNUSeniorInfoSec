using InfoSec.Ciphers;

namespace InfoSec
{
    public static class HelperMethods
    {
        public static ICipher SelectCipher(Type[] ciphers)
        {
            int cipherNum;

            while (true)
            {
                ConsoleMessages.SelectCipher(ciphers);
                var cipherChar = Console.ReadLine();

                if (int.TryParse(cipherChar, out cipherNum)
                    && cipherNum >= 0
                    && cipherNum < ciphers.Length)
                    break;

                ConsoleMessages.InvalidInput();
            }
            Console.WriteLine($"You have chosen {ciphers[cipherNum].Name}.");

            return (ICipher)Activator.CreateInstance(ciphers[cipherNum]);
        }

        public static string SelectFile()
        {
            string? path;

            while (true)
            {
                ConsoleMessages.SelectFile();
                path = Console.ReadLine();

                if (File.Exists(path))
                    break;
                else
                    ConsoleMessages.InvalidInput();
            }

            return path;
        }

        public static void CreateFileResult(string resultText, string path, bool isCipher)
        {
            var folder = Path.GetDirectoryName(path);
            var extension = Path.GetExtension(path);
            var fileName = Path.GetFileNameWithoutExtension(path);
            var date = DateTime.Now.ToString("dd.MM.yyyy HH-mm");

            var fullPath = Path.Combine(folder, fileName + (isCipher ? " Enciphered " : " Deciphered ") + date + extension);
            File.WriteAllText(fullPath, resultText);

            Console.WriteLine($"Success. Result is saved: {fullPath}");
        }
    }
}
