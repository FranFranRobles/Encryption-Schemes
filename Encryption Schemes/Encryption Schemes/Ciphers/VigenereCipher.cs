using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Encryption_Schemes.Ciphers
{
    public class VigenereCipher : Cipher
    {
        // Private Members
        private byte[] key;

        // Private Constants
        private const int DEFAULT_KEY_LEN = 32;

        // Private Methods
        private byte[] Encrypt(byte[] data)
        {
            if (key == null)
            {
                throw new InvalidKey();
            }
            int keyIndex = 0;
            for (int curByte = 0; curByte < data.Length; curByte++)
            {
                data[curByte] = (byte)Mod(data[curByte] + key[keyIndex++ % key.Length], TOTAL_BYTES);
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
            for (int currByte = 0; currByte < data.Length; currByte++)
            {
                data[currByte] = (byte)Mod(data[currByte] - key[keyIndex++ % key.Length], TOTAL_BYTES);
            }
            return data;
        }

        //Public Methods

        /// <summary>
        /// generates an encryption key
        /// </summary>
        public override void GenKey()
        {
            GenKey(DEFAULT_KEY_LEN);
        }
        /// <summary>
        /// generates an encryption key to a specified key length
        /// </summary>
        /// <param name="kLen"> len of desired key</param>
        public void GenKey(int kLen)
        {
            if (kLen <= 0)
            {
                throw new InvalidKey("Invalid Key Len Choosen");
            }
            key = new byte[kLen];
            RanGen(ref key);
        }
        /// <summary>
        /// Encrypts a string
        /// </summary>
        /// <param name="msg">string to be encrtypted</param>
        /// <returns>an encrypted string</returns>
        public override string Encrypt(string msg)
        {
            return FromByteArrToB_64Str(Encrypt(FromStrToByteArr(msg)));
        }
        /// <summary>
        /// Encrypts a file
        /// </summary>
        /// <param name="decFile">file to be encrypted</param>
        /// <param name="encFile">encrypted file</param>
        public override void Encrypt(string decFile, string encFile)
        {
            WriteToFile(encFile, Encrypt(ReadFile(decFile)));
        }
        /// <summary>
        /// Decrypts a string
        /// </summary>
        /// <param name="encMsg">string to be decrypted</param>
        /// <returns>a decrypted string</returns>
        public override string Decrypt(string encMsg)
        {
            return ConvertToString(Decrypt(FromB_64StrToByteArr(encMsg)));
        }
        /// <summary>
        /// decrypts a file
        /// </summary>
        /// <param name="encFile">file to be decyrpted</param>
        /// <param name="decFile"> decrypted file</param>
        public override void Decrypt(string encFile, string decFile)
        {
            WriteToFile(decFile, Decrypt(ReadFile(encFile)));
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
