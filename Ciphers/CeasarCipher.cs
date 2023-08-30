namespace InfoSec.Ciphers
{
    public class CeasarCipher : ICipher
    {
        private int _toMove;

        private static char CipherChar(char toCipher, int toMove)
        {
            if (toCipher.IsEnglish())
            {
                int moving = toMove % Alphabets.englishLen;

                int newPos = toCipher + moving;

                if (toCipher.IsCapitalEnglish())
                {
                    newPos = newPos > 90 ? newPos - Alphabets.englishLen : newPos < 65 ? newPos + Alphabets.englishLen : newPos;
                }
                else
                {
                    newPos = newPos > 122 ? newPos - Alphabets.englishLen : newPos < 97 ? newPos + Alphabets.englishLen : newPos;
                }

                return (char)newPos;
            }

            if (toCipher.IsUkrainian())
            {
                int moving = toMove % Alphabets.ukrainianLen;

                int pos = Alphabets.ukrainian.Contains(toCipher) ? Alphabets.ukrainian.IndexOf(toCipher) : Alphabets.ukrainianCapital.IndexOf(toCipher);

                int newPos = pos + moving;

                newPos = newPos >= Alphabets.ukrainianLen ? newPos % Alphabets.ukrainianLen : newPos < 0 ? newPos + Alphabets.ukrainianLen : newPos;

                return Alphabets.ukrainian.Contains(toCipher) ? Alphabets.ukrainian[newPos] : Alphabets.ukrainianCapital[newPos];
            }

            return toCipher;
        }

        public string Cipher(string toCipher)
        {
            return new string(toCipher.Select(q => CipherChar(q, _toMove)).ToArray());
        }

        public string Decipher(string toDecipher)
        {
            return new string(toDecipher.Select(q => CipherChar(q, -_toMove)).ToArray());
        }

        public void ProvideParameters()
        {
            while (true)
            {
                Console.WriteLine("Enter the key for Ceasar cipher:");
                var keyString = Console.ReadLine();
                if (int.TryParse(keyString, out _toMove))
                    break;
                ConsoleMessages.InvalidInput();
            }
        }
    }
}
