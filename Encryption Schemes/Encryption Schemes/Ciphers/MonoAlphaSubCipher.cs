using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.IO;

namespace Encryption_Schemes.Ciphers
{
    public class MonoAlphaSubCipher : Cipher
    {
        private byte[] key;
        private const int TOTAL_BYTES = 256;

        private byte[] Encrypt(byte[] data)
        {
            if (key == null || !ValidKey(key))
            {
                throw new InvalidKey();
            }
            int index = 0;
            while (index < data.Length)
            {
                data[index] = key[data[index]];
                index++;
            }
            return data;
        }
        private byte[] Decrypt(byte[] data)
        {
            if (key == null || !ValidKey(key))
            {
                throw new InvalidKey();
            }
            byte[] decKey = MakeDecKey();
            int index = 0;
            while (index < data.Length)
            {
                data[index] = decKey[data[index]];
                index++;
            }
            return data;
        }
        private byte[] MakeDecKey()
        {
            byte[] decKey = new byte[TOTAL_BYTES];
            for (int index = 0; index < key.Length; index++)
            {
                decKey[key[index]] = (byte)index;
            }
            return decKey;
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
            key = RandList();
        }
        private List<T> Randomize<T>(List<T> list)
        {
            List<T> randomize = new List<T>();
            Random ranGen = new Random();
            while (list.Count > 0)
            {
                T temp = list[ranGen.Next() % list.Count];
                list.Remove(temp);
                randomize.Add(temp);
            }
            return randomize;
        }
        /// <summary>
        /// generates a  random list of bytes that only occur once
        /// </summary>
        /// <returns>byte[] of random bytes that only occur once</returns>
        private byte[] RandList()
        {
            List<int> genList = new List<int>(Enumerable.Range(0, TOTAL_BYTES));
            List<byte> tempNumHolder = new List<byte>();
            Random ranGen = new Random();
            List<byte> key = new List<byte>();
            foreach (int num in genList)
            {
                tempNumHolder.Add((byte)num);
            }
            while (tempNumHolder.Count > 0)
            {
                tempNumHolder = Randomize(tempNumHolder);
                byte temp = tempNumHolder[ranGen.Next() % tempNumHolder.Count];
                tempNumHolder.Remove(temp);
                key.Add(temp);
            }
            return key.ToArray();
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
            if (!ValidKey(newKey))
            {
                throw new InvalidKey("key is not of correct type or length");
            }
            key = newKey;
        }
        /// <summary>
        /// verifies the key is of correct length or type
        /// </summary>
        /// <param name="key">key to be checked</param>
        /// <returns>true if key is correct</returns>
        private bool ValidKey(byte[] key)
        {
            bool validKey = key.Length == TOTAL_BYTES;
            int keyIndex = 0;
            bool[] contaimentList = new bool[TOTAL_BYTES];
            while (validKey == true && keyIndex < TOTAL_BYTES)
            {
                validKey = contaimentList[key[keyIndex]] != true;
                contaimentList[key[keyIndex++]] = true;
            }
            return validKey;
        }
    }
}
