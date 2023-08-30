namespace InfoSec
{
    public static class Alphabets
    {
        public static readonly List<char> ukrainian =
            "абвгґдеєжзиійїклмнопрстуфхцчшщьюя".ToList();

        public static readonly List<char> ukrainianCapital =
            "АБВГҐДЕЄЖЗИІЙЇКЛМНОПРСТУФХЦЧШЩЬЮЯ".ToList();

        public const int ukrainianLen = 33;

        public const int englishLen = 26;

        public static bool IsUkrainian(this char letter)
        {
            return ukrainian.Contains(letter) || ukrainianCapital.Contains(letter);
        }

        public static bool IsEnglish(this char letter)
        {
            return IsCapitalEnglish(letter) || IsSmallEnglish(letter);
        }

        public static bool IsCapitalEnglish(this char letter)
        {
            return (letter > 64 && letter < 91);
        }

        public static bool IsSmallEnglish(this char letter)
        {
            return (letter > 96 && letter < 123);
        }
    }
}
