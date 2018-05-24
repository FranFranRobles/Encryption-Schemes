using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Encryption_Schemes.Ciphers
{
    public class MonoAlphaSubCipher : Cipher
    {
        //Private Data Members
        private byte[] key;

        //Private Methods

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
        /// <summary>
        /// Creates the key to be used for decryption
        /// </summary>
        /// <returns>A Decryption Key</returns>
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
        /// <summary>
        /// generates a  random list of bytes that only occur once
        /// </summary>
        /// <returns>byte[] of random bytes that only occur once</returns>
        private byte[] GenerateKey()
        {
            List<byte> key = new List<byte>();
            List<byte> tempNumHolder = new List<byte>();
            List<int> genList = new List<int>(Enumerable.Range(0, TOTAL_BYTES));// int list 0 - 255
            foreach (int num in genList)
            {
                tempNumHolder.Add((byte)num);
            }
            while (tempNumHolder.Count > 0)
            {
                tempNumHolder = RandomizeList(tempNumHolder);
                byte temp = tempNumHolder[RandomInt() % tempNumHolder.Count];
                tempNumHolder.Remove(temp);
                key.Add(temp);
            }
            return key.ToArray();
        }
        /// <summary>
        /// Randomly Shuffles the inputed list
        /// </summary>
        /// <typeparam name="T">Type</typeparam>
        /// <param name="list">list to be shuffled</param>
        /// <returns>a randomly shuffled list</returns>
        private List<T> RandomizeList<T>(List<T> list)
        {
            List<T> randomizedList = new List<T>();
            while (list.Count > 0)
            {
                T temp = list[RandomInt() % list.Count];
                list.Remove(temp);
                randomizedList.Add(temp);
            }
            return randomizedList;
        }
        /// <summary>
        /// Generates A Random Int
        /// </summary>
        /// <returns>A random int</returns>
        private int RandomInt()
        {
            byte[] intBytes = new byte[INT_BYTES];
            RanGen(ref intBytes);
            int randInt = BitConverter.ToInt32(intBytes, 0); // 0 = starting index
            return Math.Abs(randInt);
        }
        //Public Methods

        /// <summary>
        /// generates an encryption key
        /// </summary>
        public override void GenKey()
        {
            key = GenerateKey();
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
            if (!ValidKey(newKey))
            {
                throw new InvalidKey("key is not of correct type or length");
            }
            key = newKey;
        }
    }
}
