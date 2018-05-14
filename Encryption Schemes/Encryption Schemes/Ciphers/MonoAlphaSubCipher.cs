using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Encryption_Schemes.Ciphers
{
    public class MonoAlphaSubCipher : Cipher
    {
        private byte[] key;
        private const int TOTAL_BYTES = 256;
        /// <summary>
        /// Encrypts a string
        /// </summary>
        /// <param name="msg">string to be encrtypted</param>
        /// <returns>an encrypted string</returns>
        public override string Encrypt(string msg)
        {
            throw new NotImplementedException();
        }
        /// <summary>
        /// Encrypts a file
        /// </summary>
        /// <param name="decFile">file to be encrypted</param>
        /// <param name="encFile">encrypted file</param>
        public override void Encrypt(string decFile, string encFile)
        {
            throw new NotImplementedException();
        }
        /// <summary>
        /// Decrypts a string
        /// </summary>
        /// <param name="encMsg">string to be decrypted</param>
        /// <returns>a decrypted string</returns>
        public override string Decrypt(string encMsg)
        {
            throw new NotImplementedException();
        }
        /// <summary>
        /// decrypts a file
        /// </summary>
        /// <param name="encFile">file to be decyrpted</param>
        /// <param name="decFile"> decrypted file</param>
        public override void Decrypt(string encFile, string decFile)
        {
            throw new NotImplementedException();
        }
        /// <summary>
        /// generates a key to be used for encryption
        /// </summary>
        public override void GenKey()
        {
            throw new NotImplementedException();
        }
        /// <summary>
        /// Retrieves the stored encryption key
        /// </summary>
        /// <returns></returns>
        public byte[] GetKey()
        {
            return key;
        }
        /// <summary>
        /// Sets the Key to be used with the encryption
        /// </summary>
        /// <param name="newKey"></param>
        public void SetKey(byte[] newKey)
        {
            throw new NotImplementedException();
            key = newKey;
        }
    }
}
