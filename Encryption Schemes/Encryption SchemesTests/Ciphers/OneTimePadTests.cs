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
    public class OneTimePadTests
    {
        string BASE_FILE = @"..\..\TestFiles\SampleTxt.txt";
        string ENC_FILE = @"..\..\TestFiles\EncFile.txt";
        string DEC_FILE = @"..\..\TestFiles\DecFile.txt";
        const string ONE_TIME_PAD_TESTS = "One Time Pad Tests";
        const string TEST_STR = "This is my Secret message.";

        [TestMethod()]
        [TestCategory(ONE_TIME_PAD_TESTS)]
        public void CTOR_Test()
        {
            TestCtor(new OneTimePad());
        }
        [TestMethod()]
        [TestCategory(ONE_TIME_PAD_TESTS)]
        public void EncryptStrTest()
        {
            OneTimePad myCipher = new OneTimePad(TEST_STR.Length);
            TestCtor(myCipher);
            myCipher.GenKey();
            TestStrEnc(myCipher, myCipher.Encrypt(TEST_STR), TEST_STR.Length);
        }
        [TestMethod()]
        [TestCategory(ONE_TIME_PAD_TESTS)]
        [ExpectedException(typeof(Cipher.InvalidKey))]
        public void EncryptNoKeyTest()
        {
            OneTimePad myCipher = new OneTimePad();
            TestCtor(myCipher);
            myCipher.Encrypt(TEST_STR);
        }
        [TestMethod()]
        [TestCategory(ONE_TIME_PAD_TESTS)]
        public void EncryptFileTest()
        {
            OneTimePad cipher = new OneTimePad();
            cipher.Encrypt(BASE_FILE, ENC_FILE);
            TestFileEnc();
        }

        [TestMethod()]
        [TestCategory(ONE_TIME_PAD_TESTS)]
        public void DecryptStrTest()
        {
            OneTimePad myCipher = new OneTimePad(TEST_STR.Length);
            TestCtor(myCipher);
            myCipher.GenKey();
            string encStr = myCipher.Encrypt(TEST_STR);
            TestStrEnc(myCipher, myCipher.Encrypt(TEST_STR), TEST_STR.Length);
            TestStrDec(encStr, myCipher.Decrypt(encStr));
        }
        [TestMethod()]
        [TestCategory(ONE_TIME_PAD_TESTS)]
        [ExpectedException(typeof(Cipher.InvalidKey))]
        public void DecryptNoKeyTest()
        {
            OneTimePad myCipher = new OneTimePad();
            TestCtor(myCipher);
            myCipher.Decrypt(Convert.ToBase64String(Encoding.ASCII.GetBytes(TEST_STR)));
        }
        [TestMethod()]
        [TestCategory(ONE_TIME_PAD_TESTS)]
        public void DecryptFileTest()
        {
            OneTimePad cipher = new OneTimePad();
            cipher.Encrypt(BASE_FILE, ENC_FILE);
            TestFileEnc();
            cipher.Decrypt(ENC_FILE, DEC_FILE);
            TestFileDec();
        }

        [TestMethod()]
        [TestCategory(ONE_TIME_PAD_TESTS)]
        public void GenKeyTest()
        {
            OneTimePad cipher = new OneTimePad(TEST_STR.Length);
            TestCtor(cipher);
            cipher.GenKey();
            Assert.IsNotNull(cipher.GetKey(), "key was not intialized");
            Assert.AreEqual(TEST_STR.Length, cipher.GetKey().Length, "Incorrect KeyLen Found");
        }
        [TestMethod()]
        [TestCategory(ONE_TIME_PAD_TESTS)]
        public void GetKeyTest()
        {
            const int KEY_LEN = 10;
            OneTimePad encryptorOne = new OneTimePad();
            OneTimePad encryptorTwo = new OneTimePad(KEY_LEN);
            TestCtor(encryptorOne);
            TestCtor(encryptorTwo);
            encryptorTwo.GenKey();
            encryptorOne.SetKey(encryptorTwo.GetKey());
            CompareKeys(encryptorTwo.GetKey(), encryptorOne.GetKey());
        }

        [TestMethod()]
        [TestCategory(ONE_TIME_PAD_TESTS)]
        public void SetKeyTest()
        {
            const int KEY_LEN = 10;
            OneTimePad encryptorOne = new OneTimePad();
            OneTimePad encryptorTwo = new OneTimePad(KEY_LEN);
            TestCtor(encryptorOne);
            TestCtor(encryptorTwo);
            encryptorTwo.GenKey();
            encryptorOne.SetKey(encryptorTwo.GetKey());
            CompareKeys(encryptorTwo.GetKey(), encryptorOne.GetKey());
        }
        static void TestCtor(OneTimePad cipher)
        {
            Assert.IsNull(cipher.GetKey(), "Incorrect intialized key Found");
        }
        static void TestStrEnc(OneTimePad cipher, string encStr, int keyLen)
        {
            byte[] generatedKey = cipher.GetKey();
            Assert.IsNotNull(generatedKey, "Key was not Generated");
            Assert.AreNotEqual(TEST_STR, encStr, "String did not encrypt");
            Assert.AreEqual(keyLen, generatedKey.Length);
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