using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.IO;

namespace Encryption_Schemes.Ciphers
{
    public class ShiftCipher : Cipher
    {
        private int key;
        private MODE shiftType;
        private const int CEASER_SHIFT = 3;
        private const int ROT_13_SHIFT = 13;
        private const int DEFAULT_KEY = 0;
        private const int MIN_SHIFT = 1;
        private const int MAX_SHIFT = 100000; // 100,000
        private const int TOTAL_BYTES = 256;
        public enum MODE { SHIFT = 0,CEASER, ROT13 };
        public ShiftCipher(MODE type = MODE.SHIFT)
        {
            key = DEFAULT_KEY;
            shiftType = type;
        }
        private byte[] Encrypt(byte[] data)
        {
            if (key == DEFAULT_KEY)
            {
                throw new InvalidKey();
            }
            for (int index = 0; index < data.Length; index++)
            {
                data[index] = (byte)Mod(data[index] + key, TOTAL_BYTES);
            }
            return data;
        }
        private byte[] Decrypt(byte[] data)
        {
            if (key == DEFAULT_KEY)
            {
                throw new InvalidKey();
            }
            for (int index = 0; index < data.Length; index++)
            {
                data[index] = (byte)Mod(data[index] - key, TOTAL_BYTES);
            }
            return data;
        }
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
            if (key == 0)
            {
                switch (shiftType)
                {
                    case MODE.CEASER:
                        key = CEASER_SHIFT;
                        break;
                    case MODE.ROT13:
                        key = ROT_13_SHIFT;
                        break;
                    default:
                        Random generator = new Random();
                        key = generator.Next(MIN_SHIFT, MAX_SHIFT);
                        break;
                }
            }
        }
        /// <summary>
        /// Retrieves the stored encryption key
        /// </summary>
        /// <returns></returns>
        public int GetKey()
        {
            return key;
        }
        /// <summary>
        /// Sets the Key to be used with the encryption
        /// </summary>
        /// <param name="newKey"></param>
        public void SetKey(int newKey)
        {
            key = newKey;
        }
        public MODE GetMode()
        {
            return shiftType;
        }
    }
}
