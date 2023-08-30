using System.Numerics;
using System.Text;

namespace InfoSec.Ciphers
{
    public class DFCCipher : ICipher
    {
        private readonly Encoding _encoder;

        private readonly ulong[] KS = new ulong[] 
        {
            8612972639056069780,
            226400614624548920,
            5035468734399885746,
            553156715519044213
        };

        private readonly Dictionary<byte, uint> RT = new()
        {
            { 0, 2097004772 },
            { 1, 1954285085 },
            { 2, 3365714148 },
            { 3, 3468975126 },
            { 4, 2633388411 },
            { 5, 1911068964 },
            { 6, 2320349597 },
            { 7, 2249410864 },
            { 8, 2065977074 },
            { 9, 1849770395 },
            { 10, 387070618 },
            { 11, 2918460961 },
            { 12, 1227714091 },
            { 13, 1055100589 },
            { 14, 1764728770 },
            { 15, 2978588257 },
            { 16, 549712766 },
            { 17, 3740314487 },
            { 18, 2144995964 },
            { 19, 2727824165 },
            { 20, 1717732873 },
            { 21, 686066682 },
            { 22, 1673192148 },
            { 23, 3509665854 },
            { 24, 1967512829 },
            { 25, 399248786 },
            { 26, 2840886307 },
            { 27, 417363613 },
            { 28, 2639746930 },
            { 29, 2619256257 },
            { 30, 1864181430 },
            { 31, 959711219 },
            { 32, 3579201126 },
            { 33, 1184528401 },
            { 34, 1384899482 },
            { 35, 3010817392 },
            { 36, 3030312725 },
            { 37, 1281709889 },
            { 38, 1140809226 },
            { 39, 1697237180 },
            { 40, 1581872912 },
            { 41, 3497395980 },
            { 42, 2013352980 },
            { 43, 2764484128 },
            { 44, 3740624868 },
            { 45, 1039099802 },
            { 46, 607101939 },
            { 47, 819564492 },
            { 48, 4039053126 },
            { 49, 1544881217 },
            { 50, 734191907 },
            { 51, 784382990 },
            { 52, 2657154479 },
            { 53, 3769928227 },
            { 54, 3320560754 },
            { 55, 593650101 },
            { 56, 3055179425 },
            { 57, 1215365210 },
            { 58, 3657057306 },
            { 59, 1140870797 },
            { 60, 2624915895 },
            { 61, 2579714736 },
            { 62, 3760968213 },
            { 63, 3105750281 },
        };

        private const ulong KD = 1016016805044927346;
        private const uint KC = 950786156;

        private readonly ulong[] KA = new ulong[] { 8365803483922232900, 2894538933423297295, 6225686844207436271 };
        private readonly ulong[] KB = new ulong[] { 6882991164150283484, 2119183971916836371, 55796257728209984 };

        private ulong[,] RoundKeys;

        private ulong ConfusionPermutation(ulong halfBlock, ulong roundKeyFirstHalf, ulong roundKeySecondHalf)
        {
            BigInteger power = new(Math.Pow(2, 64));
            var ciphered = (ulong)((roundKeyFirstHalf * halfBlock + roundKeySecondHalf) % (power + 13) % power);

            uint ZL = (uint)(ciphered>>32);
            uint ZR = (uint)ciphered;
            ZR ^= RT.GetValueOrDefault((byte)(ZL >> 26));
            ZL ^= KC;

            return (ulong)(((((ulong)ZR << 32) | ZL) + KD) % power);
        }

        private ulong[,] CreateRoundKeys(ulong[] mainKey)
        {
            var toConcat = 4 - mainKey.Length;

            var PK256 = mainKey.Concat(KS.Take(toConcat)).ToArray();
            uint[] PK = new uint[8];

            for (int i = 0; i < 8; i++)
            {
                PK[i] = i % 2 == 0 ? (uint)(PK256[i / 2] >> 32) : (uint)PK256[(i - 1) / 2];
            }

            ulong[] OA, OB, EA, EB;
            OA = new ulong[4];
            OB = new ulong[4];
            EA = new ulong[4];
            EB = new ulong[4];
            OA[0] = ((ulong)PK[0] << 32) | PK[7];
            OB[0] = ((ulong)PK[4] << 32) | PK[3];
            EA[0] = ((ulong)PK[1] << 32) | PK[6];
            EB[0] = ((ulong)PK[5] << 32) | PK[2];

            for (int i = 1; i < 4; i++)
            {
                OA[i] = OA[0] ^ KA[i - 1];
                OB[i] = OB[0] ^ KB[i - 1];
                EA[i] = EA[0] ^ KA[i - 1];
                EB[i] = EB[0] ^ KB[i - 1];
            }

            ulong[,] KI = new ulong[8, 2];
            KI[0, 0] = 0;
            KI[0, 1] = 0;

            for (int i = 1; i < 8; i++)
            {
                ulong X = KI[i - 1, 0];
                ulong Y = KI[i - 1, 1];

                for (int j = 0; j < 4; j++)
                {
                    Y ^= j % 2 == 0 ? ConfusionPermutation(X, OA[j], OB[j]) : ConfusionPermutation(X, EA[j], EB[j]);
                    (X, Y) = (Y, X);
                }

                KI[i, 0] = Y;
                KI[i, 1] = X;
            }

            return KI;
        }

        private ulong[] EncryptBlock(ulong[] block)
        {
            ulong X = block[0];
            ulong Y = block[1];

            for (int i = 0; i < 8; i++)
            {
                Y ^= ConfusionPermutation(X, RoundKeys[i, 0], RoundKeys[i, 1]);
                (X, Y) = (Y, X);
            }

            return new ulong[] { Y, X };
        }

        private ulong[] DecryptBlock(ulong[] block)
        {
            ulong X = block[0];
            ulong Y = block[1];

            for (int i = 7; i >= 0; i--)
            {
                Y ^= ConfusionPermutation(X, RoundKeys[i, 0], RoundKeys[i, 1]);
                (X, Y) = (Y, X);
            }

            return new ulong[] { Y, X };
        }

        public DFCCipher()
        {
            _encoder = Encoding.UTF8;
        }

        public string Cipher(string toCipher)
        {
            byte[] bytes = _encoder.GetBytes(toCipher);

            List<byte> toEncodeList = bytes.ToList();

            while (toEncodeList.Count % 16 != 0)
            {
                toEncodeList.Add(0);
            }

            byte[] toEncode = toEncodeList.ToArray();

            List<byte> data = new();

            for(int i = 0; i < toEncode.Length; i += 16)
            {
                ulong[] block = new ulong[2]
                {
                    BitConverter.ToUInt64(toEncode, i),
                    BitConverter.ToUInt64(toEncode, i + 8)
                };

                var encrypted = EncryptBlock(block);

                data.AddRange(BitConverter.GetBytes(encrypted[0]));
                data.AddRange(BitConverter.GetBytes(encrypted[1]));
            }

            return Convert.ToBase64String(data.ToArray());
        }

        public string Decipher(string toDecipher)
        {
            byte[] bytes = Convert.FromBase64String(toDecipher);

            List<byte> data = new();

            for (int i = 0; i < bytes.Length; i += 16)
            {
                ulong[] block = new ulong[2]
                {
                    BitConverter.ToUInt64(bytes, i),
                    BitConverter.ToUInt64(bytes, i + 8)
                };

                var decrypted = DecryptBlock(block);

                data.AddRange(BitConverter.GetBytes(decrypted[0]));
                data.AddRange(BitConverter.GetBytes(decrypted[1]));
            }

            return _encoder.GetString(data.ToArray());
        }

        public void ProvideParameters()
        {
            Console.WriteLine("Enter space separated 64bit unsigned integers to be used as key (max 4)");
            var input = Console.ReadLine();
            var nums = input.Split(' ').Select(num => Convert.ToUInt64(num)).ToArray();
            RoundKeys = CreateRoundKeys(nums);
        }
    }
}
