using InfoSec;
using InfoSec.Ciphers;

char menuChoice = ' ';
ICipher currentCipher;

var interafaceType = typeof(ICipher);
var ciphers = AppDomain.CurrentDomain.GetAssemblies()
    .SelectMany(assembly => assembly.GetTypes())
    .Where(oneType => interafaceType.IsAssignableFrom(oneType) && !oneType.IsInterface)
    .ToArray();

while (!menuChoice.IsQuitting())
{
    ConsoleMessages.PrintMenu();
    menuChoice = Console.ReadKey().KeyChar;
    Console.WriteLine();

    if (!menuChoice.IsValid())
    {
        ConsoleMessages.InvalidInput();
    }
    else
    {
        if (!menuChoice.IsQuitting())
        {
            //select cipher
            currentCipher = HelperMethods.SelectCipher(ciphers);

            //select file
            var selectedFilePath = HelperMethods.SelectFile();
            var textFromFile = File.ReadAllText(selectedFilePath);

            //provide parameters
            currentCipher.ProvideParameters();

            //logic
            string resultText;

            if (menuChoice.IsCiphering())
                resultText = currentCipher.Cipher(textFromFile);
            else
                resultText = currentCipher.Decipher(textFromFile);

            //write to file
            HelperMethods.CreateFileResult(resultText, selectedFilePath, menuChoice.IsCiphering());
            //
        }
    }

}
ConsoleMessages.Farewell();
