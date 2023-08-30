using System.Text;

namespace InfoSec.Ciphers
{
    public class PlayfairCipher : ICipher
    {
        private readonly char[,] _table = new char[5, 5];
        private const char replacer = 'X';

        private string CipherPair(char first, char second)
        {
            int firstRow = -1;
            int firstColumn = -1;
            int secondRow = -1;
            int secondColumn = -1;

            for (int i = 0; i < 5; i++)
            {
                for (int j = 0; j < 5; j++)
                {
                    if (_table[i,j] == first)
                    {
                        firstRow = i;
                        firstColumn = j;
                    }

                    if (_table[i,j] == second)
                    {
                        secondRow = i;
                        secondColumn = j;
                    }
                }
            }

            char firstCiphered;
            char secondCiphered;

            if (firstRow == secondRow)
            {
                if (firstColumn != 4)
                    firstCiphered = _table[firstRow, firstColumn + 1];
                else
                    firstCiphered = _table[firstRow, 0];

                if (secondColumn != 4)
                    secondCiphered = _table[secondRow, secondColumn + 1];
                else
                    secondCiphered = _table[secondRow, 0];

            }
            else if (firstColumn == secondColumn)
            {
                if (firstRow != 4)
                    firstCiphered = _table[firstRow + 1, firstColumn];
                else
                    firstCiphered = _table[0, firstColumn];

                if (secondRow != 4)
                    secondCiphered = _table[secondRow + 1, secondColumn];
                else
                    secondCiphered = _table[0, secondColumn];
            }
            else
            {
                firstCiphered = _table[firstRow, secondColumn];
                secondCiphered = _table[secondRow, firstColumn];
            }

            return "" + firstCiphered + secondCiphered;
        }

        private string DecipherPair(char first, char second)
        {
            int firstRow = -1;
            int firstColumn = -1;
            int secondRow = -1;
            int secondColumn = -1;

            for (int i = 0; i < 5; i++)
            {
                for (int j = 0; j < 5; j++)
                {
                    if (_table[i, j] == first)
                    {
                        firstRow = i;
                        firstColumn = j;
                    }

                    if (_table[i, j] == second)
                    {
                        secondRow = i;
                        secondColumn = j;
                    }
                }
            }

            char firstCiphered;
            char secondCiphered;

            if (firstRow == secondRow)
            {
                if (firstColumn != 0)
                    firstCiphered = _table[firstRow, firstColumn - 1];
                else
                    firstCiphered = _table[firstRow, 4];

                if (secondColumn != 0)
                    secondCiphered = _table[secondRow, secondColumn - 1];
                else
                    secondCiphered = _table[secondRow, 4];

            }
            else if (firstColumn == secondColumn)
            {
                if (firstRow != 0)
                    firstCiphered = _table[firstRow - 1, firstColumn];
                else
                    firstCiphered = _table[4, firstColumn];

                if (secondRow != 0)
                    secondCiphered = _table[secondRow - 1, secondColumn];
                else
                    secondCiphered = _table[4, secondColumn];
            }
            else
            {
                firstCiphered = _table[firstRow, secondColumn];
                secondCiphered = _table[secondRow, firstColumn];
            }

            return "" + firstCiphered + secondCiphered;
        }

        public string Cipher(string toCipher)
        {
            var upperChars = toCipher.ToUpper();
            var result = "";

            int q = 0;
            for (int i = 0; i < upperChars.Length; i++)
            {
                char first;
                char? second = null;

                if (upperChars[i].IsCapitalEnglish())
                {
                    int firstCheckpoint = q;
                    first = upperChars[i];

                    while(i < upperChars.Length - 1)
                    {
                        i++;
                        q++;
                        if (upperChars[i].IsCapitalEnglish())
                        {
                            second = upperChars[i];
                            break;
                        }
                        else
                            result += upperChars[i];
                    }

                    if (second is null)
                    {
                        string pair = CipherPair(first, replacer);
                        result = result.Insert(firstCheckpoint, $"{pair[0]}");
                        result += pair[1];
                    }
                    else if (first == second)
                    {
                        string pair = CipherPair(first, replacer);
                        result = result.Insert(firstCheckpoint, pair);
                        i--;
                    }
                    else
                    {
                        string pair = CipherPair(first, (char)second);
                        result = result.Insert(firstCheckpoint, $"{pair[0]}");
                        result += pair[1];
                    }
                }
                else
                {
                    result += upperChars[i];
                }
                q++;
            }

            return result;
        }

        public string Decipher(string toDecipher)
        {
            var upperChars = toDecipher.ToUpper();
            var result = "";

            for (int i = 0; i < upperChars.Length; i++)
            {
                char first;
                char? second = null;

                if (upperChars[i].IsCapitalEnglish())
                {
                    int firstCheckpoint = i;
                    first = upperChars[i];

                    while (i < upperChars.Length - 1)
                    {
                        i++;
                        if (upperChars[i].IsCapitalEnglish())
                        {
                            second = upperChars[i];
                            break;
                        }
                        else
                            result += upperChars[i];
                    }

                    string pair = DecipherPair(first, (char)second);
                    result = result.Insert(firstCheckpoint, $"{pair[0]}");
                    result += pair[1];
                }
                else
                {
                    result += upperChars[i];
                }
            }

            return result;
        }

        public void ProvideParameters()
        {
            Console.WriteLine("Enter the key for Playfair cipher:");
            HashSet<char> set = new();
            string key = Console.ReadLine().ToUpper();

            foreach(var x in key)
            {
                if (x.IsCapitalEnglish() && !set.Contains(x) && x != 'Q')
                {
                    set.Add(x);
                }
            }

            for (int i = 65; i < 91; i++)
            {
                var current = (char)i;

                if (current != 'Q')
                    set.Add(current);
            }

            int q = 0;
            var letters = set.ToArray();

            for(int i = 0; i < 5; i++)
            {
                for(int j = 0; j < 5; j++)
                {
                    _table[i, j] = letters[q];
                    q++;
                }
            }
        }
    }
}
