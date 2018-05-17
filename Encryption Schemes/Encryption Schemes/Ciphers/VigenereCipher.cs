using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.IO;

namespace Encryption_Schemes.Ciphers
{
    public class VigenereCipher : Cipher
    {
        private byte[] key;
        private const int TOTAL_BYTES = 256;
        private const int DEFAULT_KEY_LEN = 32;

        private byte[] Encrypt(byte[] data)
        {
            if (key == null)
            {
                throw new InvalidKey();
            }
            int keyIndex = 0;
            for (int index = 0; index < data.Length; index++)
            {
                data[index] = (byte)Mod(data[index] + key[keyIndex++ % key.Length], TOTAL_BYTES);
            }
            return data;
        }
        private byte[] Decrypt(byte[] data)
        {
            if (key == null)
            {
                throw new InvalidKey();
            }
            int keyIndex = 0;
            for (int index = 0; index < data.Length; index++)
            {
                data[index] = (byte)Mod(data[index] - key[keyIndex++ % key.Length], TOTAL_BYTES);
            }
            return data;
        }
        /// <summary>
        /// Encrypts a string
        /// </summary>
        /// <param name="msg">string to be encrtypted</param>
        /// <returns>an encrypted string</returns>
        public override string Encrypt(string msg)
        {
            return Convert.ToBase64String(Encrypt(Encoding.ASCII.GetBytes(msg)));
        }
        /// <summary>
        /// Encrypts a file
        /// </summary>
        /// <param name="decFile">file to be encrypted</param>
        /// <param name="encFile">encrypted file</param>
        public override void Encrypt(string decFile, string encFile)
        {
            File.WriteAllBytes(encFile, Encrypt(File.ReadAllBytes(decFile)));
        }
        /// <summary>
        /// Decrypts a string
        /// </summary>
        /// <param name="encMsg">string to be decrypted</param>
        /// <returns>a decrypted string</returns>
        public override string Decrypt(string encMsg)
        {
            return Encoding.UTF8.GetString(Decrypt(Convert.FromBase64String(encMsg)));
        }
        /// <summary>
        /// decrypts a file
        /// </summary>
        /// <param name="encFile">file to be decyrpted</param>
        /// <param name="decFile"> decrypted file</param>
        public override void Decrypt(string encFile, string decFile)
        {
            File.WriteAllBytes(decFile, Decrypt(File.ReadAllBytes(encFile)));
        }
        /// <summary>
        /// generates a key to be used for encryption
        /// </summary>
        public override void GenKey()
        {
            GenKey(DEFAULT_KEY_LEN);
        }
        public void GenKey(int kLen)
        {
            if (kLen < 0)
            {
                throw new InvalidKey("Invalid Key Len Choosen");
            }
            Random ranGen = new Random();
            key = new byte[kLen];
            for (int index = 0; index < key.Length; index++)
            {
                key[index] = (byte)(ranGen.Next() % TOTAL_BYTES);
            }
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
            key = newKey;
        }
    }
}
