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
    public class MonoAlphaSubCipherTests
    {
        string BASE_FILE = @"..\..\TestFiles\SampleTxt.txt";
        string ENC_FILE = @"..\..\TestFiles\EncTxt.txt";
        string DEC_FILE = @"..\..\TestFiles\DecTxt.txt";
        const string MASC_CIPHER_TESTS = "MASC Tests";
        const string TEST_STR = "This is my Secret message.";
        byte[] TEST_KEY = { };

        [TestMethod()]
        [TestCategory(MASC_CIPHER_TESTS)]
        public void CTOR_Test()
        {
            TestCtor(new MonoAlphaSubCipher());
        }
        [TestMethod()]
        [TestCategory(MASC_CIPHER_TESTS)]
        public void EncryptStrTest()
        {
            MonoAlphaSubCipher myCipher = new MonoAlphaSubCipher();
            TestCtor(myCipher);
            myCipher.GenKey();
            TestStrEnc(myCipher, myCipher.Encrypt(TEST_STR));
        }
        [TestMethod()]
        [TestCategory(MASC_CIPHER_TESTS)]
        [ExpectedException(typeof(Cipher.InvalidKey))]
        public void EncryptNoKeyTest()
        {
            MonoAlphaSubCipher myCipher = new MonoAlphaSubCipher();
            TestCtor(myCipher);
            myCipher.Encrypt(TEST_STR);
        }
        [TestMethod()]
        [TestCategory(MASC_CIPHER_TESTS)]
        public void EncryptFileTest()
        {
            MonoAlphaSubCipher masc = new MonoAlphaSubCipher();
            masc.GenKey();
            masc.Encrypt(BASE_FILE, ENC_FILE);
            TestFileEnc();
        }

        [TestMethod()]
        [TestCategory(MASC_CIPHER_TESTS)]
        public void DecryptStrTest()
        {
            MonoAlphaSubCipher myCipher = new MonoAlphaSubCipher();
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
            MonoAlphaSubCipher myCipher = new MonoAlphaSubCipher();
            TestCtor(myCipher);
            myCipher.Decrypt(Convert.ToBase64String(Encoding.ASCII.GetBytes(TEST_STR)));
        }
        [TestMethod()]
        [TestCategory(MASC_CIPHER_TESTS)]
        public void DecryptFileTest()
        {
            MonoAlphaSubCipher masc = new MonoAlphaSubCipher();
            masc.GenKey();
            masc.Encrypt(BASE_FILE, ENC_FILE);
            TestFileEnc();
            masc.Decrypt(ENC_FILE, DEC_FILE);
            TestFileDec();
        }

        [TestMethod()]
        [TestCategory(MASC_CIPHER_TESTS)]
        public void GenKeyTest()
        {
            MonoAlphaSubCipher masc = new MonoAlphaSubCipher();
            TestCtor(masc);
            masc.GenKey();
            Assert.AreNotEqual(0, masc.GetKey(), "key was not intialized");
        }

        [TestMethod()]
        [TestCategory(MASC_CIPHER_TESTS)]
        public void GetKeyTest()
        {
            MonoAlphaSubCipher masc = new MonoAlphaSubCipher();
            TestCtor(masc);
            masc.SetKey(TEST_KEY);
            Assert.AreEqual(TEST_KEY, masc.GetKey(), "Incorrect key returned");
        }

        [TestMethod()]
        [TestCategory(MASC_CIPHER_TESTS)]
        public void SetKeyTest()
        {
            MonoAlphaSubCipher masc = new MonoAlphaSubCipher();
            TestCtor(masc);
            masc.SetKey(TEST_KEY);
            CompareKeys(TEST_KEY, masc.GetKey());
        }
        static void TestCtor(MonoAlphaSubCipher cipher)
        {
            Assert.IsNull(cipher.GetKey(), "Incorrect intialized key Found");
        }
        static void TestStrEnc(MonoAlphaSubCipher cipher, string encStr)
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