using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Encryption_Schemes.Ciphers
{
    public abstract class Cipher
    {
        public class InvalidKey : Exception
        {
            public InvalidKey(string message = "", Exception inner = null)
            : base(message, inner)
            { }
        }
        protected int Mod(int num, int deno)
        {
            return num - deno * (int)Math.Floor(Convert.ToDecimal(num / deno));
        }
        /// <summary>
        /// Encrypts a string
        /// </summary>
        /// <param name="msg">string to be encrtypted</param>
        /// <returns>an encrypted string</returns>
        public abstract string Encrypt(string msg);
        /// <summary>
        /// Encrypts a file
        /// </summary>
        /// <param name="decFile">file to be encrypted</param>
        /// <param name="encFile">encrypted file</param>
        public abstract void Encrypt(string decFile, string encFile);
        /// <summary>
        /// Decrypts a string
        /// </summary>
        /// <param name="encMsg">string to be decrypted</param>
        /// <returns>a decrypted string</returns>
        public abstract string Decrypt(string encMsg);
        /// <summary>
        /// decrypts a file
        /// </summary>
        /// <param name="encFile">file to be decyrpted</param>
        /// <param name="decFile"> decrypted file</param>
        public abstract void Decrypt(string encFile, string decFile);
        /// <summary>
        /// generates a key to be used for encryption
        /// </summary>
        public abstract void GenKey();
    }
}
