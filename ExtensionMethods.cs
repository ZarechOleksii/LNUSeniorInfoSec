namespace InfoSec
{
    public static class ExtensionMethods
    {
        public static bool IsQuitting(this char given)
        {
            return given is 'q' or 'Q';
        }

        public static bool IsCiphering(this char given)
        {
            return given is '1';
        }

        public static bool IsDeciphering(this char given)
        {
            return given is '2';
        }

        public static bool IsValid(this char given)
        {
            return given.IsQuitting() || given.IsDeciphering() || given.IsCiphering();
        }
    }
}
