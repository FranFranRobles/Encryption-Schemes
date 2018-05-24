using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.IO;
using System.Security.Cryptography;

namespace Encryption_Schemes.Ciphers
{
    public abstract class Cipher
    {
        #region Protected Constants
        protected const int INT_BYTES = 4;
        protected const int TOTAL_BYTES = 256;
        #endregion

        #region Cipher Exceptions
        public class InvalidKey : Exception
        {
            public InvalidKey(string message = "", Exception inner = null)
            : base(message, inner)
            { }
        }
        #endregion

        #region Protected Methods
        /// <summary>
        /// Finds the remainder of numerator / denominator by using the quotent remainder theorem
        /// </summary>
        /// <param name="numerator"></param>
        /// <param name="denominator"></param>
        /// <returns>returns the remainder of numerator / denominator</returns>
        protected int Mod(int numerator, int denominator)
        {
            return numerator - denominator * (int)Math.Floor(Convert.ToDecimal(numerator / denominator));
        }
        /// <summary>
        /// fills inputed array with a random sequence of bytes;
        /// </summary>
        /// <param name="randomSeq">array to be filled</param>
        protected void RanGen(ref byte[] randomSeq)
        {
            if (randomSeq == null)
            {
                throw new NullReferenceException();
            }
            RandomNumberGenerator ranGen = RandomNumberGenerator.Create();
            ranGen.GetBytes(randomSeq);
        }
        #endregion

        #region Protected Data Converters
        /// <summary>
        /// Gets all bytes from a base 64 string
        /// </summary>
        /// <param name="str">string to grab all bytes from</param>
        /// <returns>byte array representing the string</returns>
        protected byte[] FromB_64StrToByteArr(string str)
        {
            return Convert.FromBase64String(str);
        }
        /// <summary>
        /// Converts a byte[] to a string
        /// </summary>
        /// <param name="str">byte array to convert to a string</param>
        /// <returns>a string represnting the byte array</returns>
        protected string ConvertToString(byte[] str)
        {
            return Encoding.UTF8.GetString(str);
        }
        /// <summary>
        /// reads a file to a byte array
        /// </summary>
        /// <param name="file">file to be read</param>
        /// <returns>byte array containing the all the data of the file</returns>
        protected byte[] ReadFile(string file)
        {
            return File.ReadAllBytes(file);
        }
        /// <summary>
        /// writes the given data to the specified file location
        /// </summary>
        /// <param name="path">file to save data to</param>
        /// <param name="data">data to save onto the file</param>
        protected void WriteToFile(string path, byte[] data)
        {
            File.WriteAllBytes(path, data);
        }
        /// <summary>
        /// converts string to a byte aray
        /// </summary>
        /// <param name="str">string to convert to a byte array</param>
        /// <returns>a byte array containing all ascii encoded bytes of the inputed string</returns>
        protected byte[] FromStrToByteArr(string str)
        {
            return Encoding.ASCII.GetBytes(str);
        }
        /// <summary>
        /// Converts a byte array to a base 64 string
        /// </summary>
        /// <param name="str">string as bytes</param>
        /// <returns>a converted base 64 string</returns>
        protected string FromByteArrToB_64Str(byte[] str)
        {
            return Convert.ToBase64String(str);
        }
        #endregion

        #region Public Method Signatures
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
        /// generates an encryption key
        /// </summary>
        public abstract void GenKey();
    }
    #endregion

}
