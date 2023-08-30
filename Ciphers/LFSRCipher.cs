using System.Text;

namespace InfoSec.Ciphers
{
    public class LFSRGenerator
    {
        private Queue<bool> _register;
        private readonly uint _key;

        public LFSRGenerator()
        {
            _register = new(9);
            Random random = new();
            _key = (uint)random.Next(1, 512);

            FillRegister();
        }

        public LFSRGenerator(uint key)
        {
            _register = new(9);
            _key = key;

            FillRegister();
        }

        public void PrintKey()
        {
            Console.WriteLine($"Cipher key is: {_key}");
        }

        public byte GetNextByte()
        {
            byte toReturn = 0;

            for(int i = 0; i < 8; i++)
            {
                toReturn |= GetNextBit(7 - i);
            }

            return toReturn;
        }

        //x9 + x3 + 1
        private byte GetNextBit(int iteration)
        {
            var indexer = _register.ToList();

            bool newEl = indexer[8] ^ indexer[2] ^ true;

            bool toReturn = _register.Dequeue();
            _register.Enqueue(newEl);

            return (byte)(Convert.ToByte(toReturn) << iteration);
        }

        private void FillRegister()
        {
            for (int i = 0; i < 9; i++)
            {
                _register.Enqueue(Convert.ToBoolean(_key & (1 << i)));
            }
        }
    }

    public class LFSRCipher : ICipher
    {
        private LFSRGenerator _generator;
        private readonly Encoding _encoder;

        public LFSRCipher()
        {
            _encoder = Encoding.UTF8;
        }

        public string Cipher(string toCipher)
        {
            byte[] bytes = _encoder.GetBytes(toCipher);
            var ciphered = bytes.Select(one => (byte)(one ^ _generator.GetNextByte())).ToArray();

            return Convert.ToBase64String(ciphered);
        }

        public string Decipher(string toDecipher)
        {
            byte[] bytes = Convert.FromBase64String(toDecipher);
            var deciphered = bytes.Select(one => (byte)(one ^ _generator.GetNextByte())).ToArray();

            return _encoder.GetString(deciphered);
        }

        public void ProvideParameters()
        {
            Console.WriteLine("Press K if you would like to enter parameters (needed to decipher)");
            Console.WriteLine("Press any key to to generate random parameters (do not do this if you want to decipher)");
            var choice = Console.ReadKey().KeyChar;
            Console.WriteLine();

            if (choice == 'K' || choice == 'k')
            {
                uint key;

                while (true)
                {
                    Console.WriteLine("Enter key between 1 and 511");
                    var line = Console.ReadLine();
                    var number = Convert.ToUInt32(line);

                    if (number > 0 && number < 512)
                    {
                        key = number;
                        break;
                    }
                    else
                    {
                        ConsoleMessages.InvalidInput();
                    }
                }

                _generator = new(key);
            }
            else
            {
                _generator = new();
            }

            _generator.PrintKey();
        }
    }
}
