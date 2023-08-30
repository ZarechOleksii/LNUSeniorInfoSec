using System.Linq;
using System.Numerics;
using System.Text;

namespace InfoSec.Ciphers
{
    public class ElGamalCipherLogic
    {
        private const int rangeFrom = 1000;
        private const int rangeTo = 9999;
        private readonly int p;
        private readonly int g;
        private readonly int x;
        private readonly int y;

        public ElGamalCipherLogic()
        {
            Random random = new Random();
            p = random.Next(rangeFrom, rangeTo);
            g = -1;
            
            while(g == -1)
            {
                p += 1;
                while (!IsPrime(p))
                    p += 1;
                g = GetPrimitiveRoot();
            }

            x = random.Next(2, p - 1);
            y = (int)BigInteger.ModPow(new BigInteger(g), x, p);
        }

        public ElGamalCipherLogic(int P, int X)
        {
            p = P;
            x = X;
        }

        public int GetPrimitiveRoot()
        {
            HashSet<int> factors = GetPrimeFactors();

            for (int i = 2; i < p - 1; i++)
            {
                var notFound = false;

                foreach(var factor in factors)
                {
                    if(BigInteger.ModPow(i, (p - 1) / factor, p) == 1)
                    {
                        notFound = true;
                        break;
                    }
                }

                if (!notFound)
                {
                    return i;
                }
            }

            return -1;
        }

        public HashSet<int> GetPrimeFactors()
        {
            HashSet<int> factors = new();

            var starting = p - 1;
            while(starting != 1)
            {
                for(int i = 2; i <= starting; i++)
                {
                    if(starting % i == 0)
                    {
                        starting /= i;
                        factors.Add(i);
                        break;
                    }
                }
            }

            return factors;
        }

        public (int, int) EncryptChar(char given)
        {
            Random random = new Random();
            var k = random.Next(2, p - 1);
            var a = (int)BigInteger.ModPow(new BigInteger(g), k, p);
            var b = (int)(BigInteger.Pow(new BigInteger(y), k) * given % p);

            return (a, b);
        }

        public char DecryptChar((int, int) given)
        {
            return (char)(given.Item2 * BigInteger.Pow(given.Item1, p - 1 - x) % p);
        }

        public void PrintKeys()
        {
            Console.WriteLine("Your keys:");
            Console.WriteLine($"p = {p}");
            Console.WriteLine($"g = {g}");
            Console.WriteLine($"y = {y}");
            Console.WriteLine($"x = {x}");
        }

        public static bool IsPrime(int number)
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
    }

    public class ElGamalCipher : ICipher
    {
        private ElGamalCipherLogic _cipher;
        private Encoding _encoding = Encoding.UTF8;

        public string Cipher(string toCipher)
        {
            return string.Join(';', toCipher.Select(ch =>
            {
                var nums = _cipher.EncryptChar(ch);
                return string.Format("{0},{1}", nums.Item1, nums.Item2);
            }));
        }

        public string Decipher(string toDecipher)
        {
            return new string(toDecipher.Split(';').Select(nums =>
            {
                var split = nums.Split(',');
                return _cipher.DecryptChar((Convert.ToInt32(split[0]), Convert.ToInt32(split[1])));
            }).ToArray());
        }

        public void ProvideParameters()
        {
            Console.WriteLine("Press K if you would like to enter parameters (needed to decipher)");
            Console.WriteLine("Press any key to to generate random parameters (do not do this if you want to decipher)");
            var choice = Console.ReadKey().KeyChar;
            Console.WriteLine();

            if (choice == 'K' || choice == 'k')
            {
                Console.WriteLine("Enter space separated p and x values");
                var line = Console.ReadLine();
                var nums = line.Split(' ').Select(num => Convert.ToInt32(num)).ToArray();

                int p = nums[0];
                int x = nums[1];

                _cipher = new(p, x);
            }
            else
            {
                _cipher = new();
            }

            _cipher.PrintKeys();
        }
    }
}
