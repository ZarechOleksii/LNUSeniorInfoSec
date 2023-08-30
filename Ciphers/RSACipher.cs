using System.Numerics;
using System.Security.Cryptography;
using System.Text;

namespace InfoSec.Ciphers
{
    public class RSACipherLogic
    {
        private const int rangeFrom = 1000;
        private const int rangeTo = 9999;
        private int p;
        private int q;
        private int n = 9173503;
        private int ei;
        private int e;
        private int d = 6111579;


        public RSACipherLogic()
        {
            p = 3557;
            q = 2579;
            n = p * q;
            ei = (p - 1) * (q - 1);
            e = 3;
          /*Random random = new Random();
            p = random.Next(rangeFrom, rangeTo);
            q = random.Next(rangeFrom * 10, rangeTo * 2);

            while (!IsPrime(p))
                p += 1;

            while (!IsPrime(q) || !IsPrime(2 * q + 1))
                q += 1;

            ei = (p - 1) * (q - 1);

            var eiFactors = GetPrimeFactors(ei);

            e = 2;

            while (eiFactors.Intersect(GetPrimeFactors(e)).Count() != 0)
            {
                e++;
            }

            d = (int)BigInteger.ModPow(e, -1, ei);*/
        }

        public RSACipherLogic(int E, int N)
        {
            e = E;
            n = N;
        }

/*        public BigInteger GetHashCode(BigInteger hash)
        {
            return BigInteger.ModPow(hash, e, n);
        }

        public BigInteger FromHashCode(BigInteger hashCode)
        {
            return BigInteger.ModPow(hashCode, d, n);
        }
*/
        public BigInteger Sign(BigInteger hashCode)
        {
            return BigInteger.ModPow(hashCode, d, n);
        }

        public bool CheckSignature(BigInteger hash, BigInteger signature)
        {
            return hash == BigInteger.ModPow(signature, e, n);
        }

        public void PrintPublicKey()
        {
            Console.WriteLine($"{e} {n}");
        }

        public HashSet<int> GetPrimeFactors(int num)
        {
            HashSet<int> factors = new();

            var starting = num;
            while (starting != 1)
            {
                for (int i = 2; i <= starting; i++)
                {
                    if (starting % i == 0)
                    {
                        starting /= i;
                        factors.Add(i);
                        break;
                    }
                }
            }

            return factors;
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

    public class RSACipher : ICipher
    {
        private RSACipherLogic _cipher;
        private Encoding _encoding = Encoding.UTF8;

        public string Cipher(string toCipher)
        {
            _cipher = new();

            var toInt = new BigInteger(_encoding.GetBytes(toCipher), true, true);
            var signature = _cipher.Sign(toInt);

            _cipher.PrintPublicKey();
            return $"{toInt};{signature}";
        }

        public string Decipher(string toDecipher)
        {
            Console.WriteLine("Enter space separated e and n values:");
            var line = Console.ReadLine();
            var nums = line.Split(' ').Select(num => Convert.ToInt32(num)).ToArray();

            int e = nums[0];
            int n = nums[1];

            _cipher = new(e, n);

            var hashCode = BigInteger.Parse(toDecipher.Split(';')[0]);
            var signature = BigInteger.Parse(toDecipher.Split(';')[1]);
            var deciphered = _encoding.GetString(hashCode.ToByteArray());

            if(_cipher.CheckSignature(hashCode, signature))
            {
                Console.WriteLine("Signature OK.");
            }
            else
            {
                Console.WriteLine("File was changed");
            }

            return deciphered;
        }

        public void ProvideParameters()
        {

        }
    }
}
