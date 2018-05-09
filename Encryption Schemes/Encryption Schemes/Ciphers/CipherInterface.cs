using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Encryption_Schemes.Ciphers
{
    abstract class CipherInterface
    {
        private byte[] key;
        private byte[] seed;

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
        /// <summary>
        /// generates a seed to run the encryption on
        /// </summary>
        public abstract void GenSeed();
        /// <summary>
        /// Retrieves the stored encryption key
        /// </summary>
        /// <returns></returns>
        public abstract byte[] GetKey();
        /// <summary>
        /// Retrieves the stored Seed
        /// </summary>
        /// <returns></returns>
        public abstract byte[] GetSeed();
        /// <summary>
        /// Sets the Key to be used with the encryption
        /// </summary>
        /// <param name="newKey"></param>
        public abstract void SetKey(byte[] newKey);
        /// <summary>
        /// Sets the seed to be used with the encryption
        /// </summary>
        /// <param name="newSeed"></param>
        public abstract void SetSeed(byte[] newSeed);
    }
}
