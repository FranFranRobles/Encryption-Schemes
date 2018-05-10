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
        public enum MODE { SHIFT = 0,CEASER, ROT13 };
        public ShiftCipher(MODE type = MODE.SHIFT)
        {
            key = 0; // no shift
            shiftType = type;
        }
        private byte[] Encrypt(byte[] data)
        {
            throw new NotImplementedException();
        }
        private byte[] Decrypt(byte[] data)
        {
            throw new NotImplementedException();
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
            return "";
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
        public int GetKey()
        {
            throw new NotImplementedException();
        }
        /// <summary>
        /// Sets the Key to be used with the encryption
        /// </summary>
        /// <param name="newKey"></param>
        public void SetKey(int newKey)
        {
            throw new NotImplementedException();
        }
        public MODE GetMode()
        {
            return shiftType;
        }
    }
}
