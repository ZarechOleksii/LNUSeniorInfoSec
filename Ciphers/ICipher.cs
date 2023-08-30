namespace InfoSec.Ciphers
{
    public interface ICipher
    {
        public void ProvideParameters();
        public string Cipher(string toCipher);
        public string Decipher(string toDecipher);
    }
}
