using Microsoft.VisualStudio.TestTools.UnitTesting;
using Encryption_Schemes.Ciphers;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Encryption_Schemes.Ciphers.Tests
{
    [TestClass()]
    public class VigenereTests
    {
        string BASE_FILE = @"..\..\TestFiles\SampleTxt.txt";
        string ENC_FILE = @"..\..\TestFiles\EncFile.txt";
        string DEC_FILE = @"..\..\TestFiles\DecFile.txt";
        const string MASC_CIPHER_TESTS = "Vigenere Cipher Tests";
        const string TEST_STR = "This is my Secret message.";

        [TestMethod()]
        [TestCategory(MASC_CIPHER_TESTS)]
        public void CTOR_Test()
        {
            TestCtor(new VigenereCipher());
        }
        [TestMethod()]
        [TestCategory(MASC_CIPHER_TESTS)]
        public void EncryptStrTest()
        {
            VigenereCipher myCipher = new VigenereCipher();
            TestCtor(myCipher);
            myCipher.GenKey();
            TestStrEnc(myCipher, myCipher.Encrypt(TEST_STR));
        }
        [TestMethod()]
        [TestCategory(MASC_CIPHER_TESTS)]
        [ExpectedException(typeof(Cipher.InvalidKey))]
        public void EncryptNoKeyTest()
        {
            VigenereCipher myCipher = new VigenereCipher();
            TestCtor(myCipher);
            myCipher.Encrypt(TEST_STR);
        }
        [TestMethod()]
        [TestCategory(MASC_CIPHER_TESTS)]
        public void EncryptFileTest()
        {
            VigenereCipher cipher = new VigenereCipher();
            cipher.GenKey();
            cipher.Encrypt(BASE_FILE, ENC_FILE);
            TestFileEnc();
        }

        [TestMethod()]
        [TestCategory(MASC_CIPHER_TESTS)]
        public void DecryptStrTest()
        {
            VigenereCipher myCipher = new VigenereCipher();
            TestCtor(myCipher);
            myCipher.GenKey();
            string encStr = myCipher.Encrypt(TEST_STR);
            TestStrEnc(myCipher, encStr);
            TestStrDec(encStr, myCipher.Decrypt(encStr));
        }
        [TestMethod()]
        [TestCategory(MASC_CIPHER_TESTS)]
        [ExpectedException(typeof(Cipher.InvalidKey))]
        public void DecryptNoKeyTest()
        {
            VigenereCipher myCipher = new VigenereCipher();
            TestCtor(myCipher);
            myCipher.Decrypt(Convert.ToBase64String(Encoding.ASCII.GetBytes(TEST_STR)));
        }
        [TestMethod()]
        [TestCategory(MASC_CIPHER_TESTS)]
        public void DecryptFileTest()
        {
            VigenereCipher cipher = new VigenereCipher();
            System.IO.File.Exists(ENC_FILE);
            System.IO.File.Exists(DEC_FILE);
            cipher.GenKey();
            cipher.Encrypt(BASE_FILE, ENC_FILE);
            TestFileEnc();
            cipher.Decrypt(ENC_FILE, DEC_FILE);
            TestFileDec();
        }

        [TestMethod()]
        [TestCategory(MASC_CIPHER_TESTS)]
        public void GenKeyTest()
        {
            VigenereCipher masc = new VigenereCipher();
            TestCtor(masc);
            masc.GenKey();
            Assert.IsNotNull(masc.GetKey(), "key was not intialized");
        }

        [TestMethod()]
        [TestCategory(MASC_CIPHER_TESTS)]
        public void GetKeyTest()
        {
            VigenereCipher encryptorOne = new VigenereCipher();
            VigenereCipher encryptorTwo = new VigenereCipher();
            TestCtor(encryptorOne);
            TestCtor(encryptorTwo);
            encryptorTwo.GenKey();
            encryptorOne.SetKey(encryptorTwo.GetKey());
            CompareKeys(encryptorTwo.GetKey(), encryptorOne.GetKey());
        }

        [TestMethod()]
        [TestCategory(MASC_CIPHER_TESTS)]
        public void SetKeyTest()
        {
            VigenereCipher encryptorOne = new VigenereCipher();
            VigenereCipher encryptorTwo = new VigenereCipher();
            TestCtor(encryptorOne);
            TestCtor(encryptorTwo);
            encryptorTwo.GenKey();
            encryptorOne.SetKey(encryptorTwo.GetKey());
            CompareKeys(encryptorTwo.GetKey(), encryptorOne.GetKey());
        }
        static void TestCtor(VigenereCipher cipher)
        {
            Assert.IsNull(cipher.GetKey(), "Incorrect intialized key Found");
        }
        static void TestStrEnc(VigenereCipher cipher, string encStr)
        {
            Assert.IsNotNull(cipher.GetKey(), "Key was not Generated");
            Assert.AreNotEqual(TEST_STR, encStr, "String did not encrypt");
        }
        void TestFileEnc()
        {
            CompareFile(System.IO.File.ReadAllBytes(BASE_FILE), System.IO.File.ReadAllBytes(ENC_FILE), false);
        }
        static void TestStrDec(string encStr, string decStr)
        {
            Assert.AreNotEqual(encStr, decStr, "string did not decrypt");
            Assert.AreEqual(TEST_STR, decStr, "string did not decrypt properly");
        }
        void TestFileDec()
        {
            byte[] baseFile = System.IO.File.ReadAllBytes(BASE_FILE);
            byte[] encFile = System.IO.File.ReadAllBytes(ENC_FILE);
            byte[] decFile = System.IO.File.ReadAllBytes(DEC_FILE);

            CompareFile(baseFile, encFile, false);
            CompareFile(encFile, decFile, false);
            CompareFile(baseFile, decFile, true);
        }
        static void CompareFile(byte[] fileOne, byte[] fileTwo, bool SameFile)
        {
            bool areEqual = true;
            int index = 0;
            areEqual = fileOne.Length == fileTwo.Length;
            while (areEqual == true && index < fileOne.Length)
            {
                areEqual = fileOne[index] == fileTwo[index];
                index++;
            }
            Assert.AreEqual(SameFile, areEqual, SameFile == true ? "mismatch of file found" : "files should be equal");
        }
        static void CompareKeys(byte[] keyOne, byte[] keyTwo)
        {
            bool equal = keyOne.Length == keyTwo.Length;
            int index = 0;
            while (equal && index < keyOne.Length)
            {
                equal = keyOne[index] == keyTwo[index];
                index++;
            }
            Assert.IsTrue(equal, "keys should be equal");
        }
    }
}