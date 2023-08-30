using System.Text;

namespace InfoSec.Ciphers
{
    public class BBSGenerator
    {
        #region private variables
        private const int rangeFrom = 100000;
        private const int rangeTo = 999999;
        private readonly uint _p;
        private readonly uint _q;
        private readonly uint _m;
        private readonly uint _s;
        private uint _last;
        #endregion

        #region constructors
        public BBSGenerator()
        {
            GenerateVariables(out uint p, out uint q, out uint s);
            _p = p;
            _q = q;
            _m = p * q;
            _s = s;
            _last = s;
        }

        public BBSGenerator(uint p, uint q, uint s)
        {
            _p = p;
            _q = q;
            _m = p * q;
            _s = s;
            _last = s;
        }
        #endregion

        #region private methods
        private static void GenerateVariables(out uint p, out uint q, out uint s)
        {
            Random random = new Random();
            p = (uint)random.Next(rangeFrom, rangeTo);
            q = (uint)random.Next(rangeFrom, rangeTo);

            while (p % 4 != 3)
                p++;
            while (q % 4 != 3)
                q++;

            while (!IsPrime(p) || !IsPrime(2 * p + 1))
                p += 4;
            while (!IsPrime(q) || !IsPrime(2 * q + 1) || q == p)
                q += 4;

            s = (uint)random.Next(rangeFrom * 10, rangeTo * 10);

            while (s % p == 0 || s % q == 0)
                s++;
        }
        #endregion

        #region public methods
        public byte GetNextByte()
        {
            byte toReturn = 0;

            for (int i = 0; i < 8; i++)
            {
                _last = (uint)(_last * _last % _m);
                byte lsbit = (byte)(_last << 7);
                toReturn |= (byte)(lsbit >> i);
            }

            return toReturn;
        }

        public void PrintVariables()
        {
            Console.WriteLine("BBS variables:");
            Console.WriteLine($"p = {_p}");
            Console.WriteLine($"q = {_q}");
            Console.WriteLine($"s = {_s}");
        }

        public static bool ValidateParameters(uint p, uint q, uint s, out string message)
        {
            message = "Validation errors:\n";
            var beginning = message.Length;

            if (p <= 0)
                message += "p is not positive\n";
            if (q <= 0)
                message += "q is not positive\n";
            if (p % 4 != 3)
                message += "p mod4 has to be equal to 3\n";
            if (q % 4 != 3)
                message += "q mod4 has to be equal to 3\n";
            if (!IsPrime(p))
                message += "p is not prime\n";
            if (!IsPrime(q))
                message += "q is not prime\n";
            if (s < 2)
                message += "s has to be larger than 1\n";
            if (s % p == 0)
                message += "p should not be factor of s\n";
            if (s % q == 0)
                message += "q should not be factor of s\n";

            var ending = message.Length;
            return beginning == ending;
        }

        public static bool IsPrime(uint number)
        {
            if (number <= 1) return false;
            if (number == 2) return true;
            if (number % 2 == 0) return false;

            var boundary = (int)Math.Floor(Math.Sqrt(number));

            for (int i = 3; i <= boundary; i += 2)
                if (number % i == 0)
                    return false;

            return true;
        }
        #endregion
    }

    public class RandomGeneratorSequenceCipher : ICipher
    {
        #region private variables
        private readonly Encoding _encoder;
        private BBSGenerator _bbsGenerator;
        #endregion

        #region constructors
        public RandomGeneratorSequenceCipher()
        {
            _encoder = Encoding.UTF8;
        }
        #endregion

        #region ICipher Methods
        public string Cipher(string toCipher)
        {
            byte[] bytes = _encoder.GetBytes(toCipher);
            var ciphered = bytes.Select(one => (byte)(one ^ _bbsGenerator.GetNextByte())).ToArray();

            return Convert.ToBase64String(ciphered);
        }

        public string Decipher(string toDecipher)
        {
            byte[] bytes = Convert.FromBase64String(toDecipher);
            var deciphered = bytes.Select(one => (byte)(one ^ _bbsGenerator.GetNextByte())).ToArray();

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
                uint p;
                uint q;
                uint s;

                while (true)
                {
                    Console.WriteLine("Enter space separated p, q, s values");
                    var line = Console.ReadLine();
                    var nums = line.Split(' ').Select(num => Convert.ToUInt32(num)).ToArray();

                    if (!BBSGenerator.ValidateParameters(nums[0], nums[1], nums[2], out string message))
                    {
                        ConsoleMessages.InvalidInput();
                        Console.WriteLine(message);
                    }
                    else
                    {
                        p = nums[0];
                        q = nums[1];
                        s = nums[2];
                        break;
                    }
                }

                _bbsGenerator = new(p, q, s);
            }
            else
            {
                _bbsGenerator = new();
            }

            _bbsGenerator.PrintVariables();
        }
        #endregion
    }
}
