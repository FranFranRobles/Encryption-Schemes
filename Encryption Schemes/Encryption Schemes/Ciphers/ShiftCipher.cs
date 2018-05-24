using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Encryption_Schemes.Ciphers
{
    public class ShiftCipher : Cipher
    {
        // Private Members
        private int key;
        private MODE shiftType;
        // private constants
        private const int CEASER_SHIFT = 3;
        private const int ROT_13_SHIFT = 13;
        private const int DEFAULT_KEY = 0;
        // public enum
        public enum MODE { SHIFT = 0,CEASER, ROT13 };

        //CTOR

        public ShiftCipher(MODE type = MODE.SHIFT)
        {
            key = DEFAULT_KEY;
            shiftType = type;
        }

        // Private Methods
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
        
        //Public Methods

        /// <summary>
        /// generates an encryption key based on shift mode
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
                        byte[] keyBytes = new byte[INT_BYTES];
                        RanGen(ref keyBytes);
                        key = BitConverter.ToInt32(keyBytes, 0);
                        key = Math.Abs(key);
                        break;
                }
            }
        }
        /// <summary>
        /// Returns the the shift type of the shift cipher
        /// </summary>
        /// <returns></returns>
        public MODE GetMode()
        {
            return shiftType;
        }
        /// <summary>
        /// Encrypts a String
        /// </summary>
        /// <param name="msg">message to be encrypted</param>
        /// <returns>an encrypted string</returns>
        public override string Encrypt(string msg)
        {
            return FromByteArrToB_64Str(Encrypt(FromStrToByteArr(msg))); ;
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
    }
}
