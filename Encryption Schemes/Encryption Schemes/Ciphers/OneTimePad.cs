using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Encryption_Schemes.Ciphers
{
    public class OneTimePad : Cipher
    {
        // Private Members
        private byte[] key;
        private int DefaultKeyLen;

        // Private Methods
        private byte[] Encrypt(byte[] data)
        {
            if (key == null || key.Length < data.Length)
            {
                throw new InvalidKey();
            }
            int curByte = 0;
            while (curByte  < data.Length)
            {
                data[curByte] = (byte)(key[curByte] ^ data[curByte]);
                curByte++;
            }
            return data;
        }
        private byte[] Decrypt(byte[] data)
        {
            if (key == null || key.Length < data.Length)
            {
                throw new InvalidKey();
            }
            int curByte = 0;
            while (curByte < data.Length)
            {
                data[curByte] = (byte)(key[curByte] ^ data[curByte]);
                curByte++;
            }
            return data;
        }
        /// <summary>
        /// generates an encryption key to a specified key length
        /// </summary>
        /// <param name="kLen"> len of desired key</param>
        private void GenKey(int kLen)
        {
            if (kLen <= 0)
            {
                throw new InvalidKey("Invalid Key Len Choosen");
            }
            key = new byte[kLen];
            RanGen(ref key);
        }
        // Public CTOR
        public OneTimePad(int keyLen = 0)
        {
            key = null;
            DefaultKeyLen = keyLen;
        }
        //Public Methods

        /// <summary>
        /// generates an encryption key
        /// </summary>
        public override void GenKey()
        {
            GenKey(DefaultKeyLen);
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
            byte[] plainTxt = ReadFile(decFile);
            GenKey(plainTxt.Length);
            WriteToFile(encFile, Encrypt(plainTxt));
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

