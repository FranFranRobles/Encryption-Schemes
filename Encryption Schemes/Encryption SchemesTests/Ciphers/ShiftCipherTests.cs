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
    public class ShiftCipherTests
    {
        string BASE_FILE = @"..\..\TestFiles\SampleTxt.txt";
        string ENC_FILE = @"..\..\TestFiles\EncTxt.txt";
        string DEC_FILE = @"..\..\TestFiles\DecTxt.txt";
        const string SHIFT_CIPHER_TESTS = "Shift Cipher Tests";
        const string TEST_STR = "This is my Secret message.";
        const int TEST_SHIFT = 8;
        const int CEASERS_SHIFT = 3;
        const int ROT_13_SHIFT = 13;

        [TestMethod()]
        [TestCategory(SHIFT_CIPHER_TESTS)]
        public void CTOR_Test()
        {
            TestCtor(new ShiftCipher());
        }
        [TestMethod()]
        [TestCategory(SHIFT_CIPHER_TESTS)]
        public void EncryptStrTest()
        {
            ShiftCipher myCipher = new ShiftCipher();
            myCipher.GenKey();
            TestCtor(myCipher);
            TestStrEnc(myCipher, myCipher.Encrypt(TEST_STR));
        }

        [TestMethod()]
        [TestCategory(SHIFT_CIPHER_TESTS)]
        public void EncryptFileTest()
        {
            ShiftCipher shiftCipher = new ShiftCipher();
            shiftCipher.GenKey();
            shiftCipher.Encrypt(BASE_FILE, ENC_FILE);
            TestFileEnc();
        }

        [TestMethod()]
        [TestCategory(SHIFT_CIPHER_TESTS)]
        public void DecryptStrTest()
        {
            ShiftCipher myCipher = new ShiftCipher();
            myCipher.GenKey();
            TestCtor(myCipher);
            string encStr = myCipher.Encrypt(TEST_STR);
            TestStrEnc(myCipher, encStr);
            TestStrDec(encStr, myCipher.Decrypt(encStr));
        }

        [TestMethod()]
        [TestCategory(SHIFT_CIPHER_TESTS)]
        public void DecryptFileTest()
        {
            ShiftCipher shiftCipher = new ShiftCipher();
            shiftCipher.GenKey();
            shiftCipher.Encrypt(BASE_FILE, ENC_FILE);
            TestFileEnc();
            shiftCipher.Decrypt(ENC_FILE, DEC_FILE);
            TestFileDec();
        }

        [TestMethod()]
        [TestCategory(SHIFT_CIPHER_TESTS)]
        public void GenKeyTest()
        {
            ShiftCipher shiftCipher = new ShiftCipher();
            TestCtor(shiftCipher);
            shiftCipher.GenKey();
            Assert.AreNotEqual(0, shiftCipher.GetKey(), "key was not intialized");
        }

        [TestMethod()]
        [TestCategory(SHIFT_CIPHER_TESTS)]
        public void GetKeyTest()
        {
            ShiftCipher shiftCipher = new ShiftCipher();
            TestCtor(shiftCipher);
            shiftCipher.SetKey(TEST_SHIFT);
            Assert.AreEqual(TEST_SHIFT, shiftCipher.GetKey(), "Incorrect key returned");
        }

        [TestMethod()]
        [TestCategory(SHIFT_CIPHER_TESTS)]
        public void SetKeyTest()
        {
            ShiftCipher shiftCipher = new ShiftCipher();
            TestCtor(shiftCipher);
            shiftCipher.SetKey(TEST_SHIFT);
            Assert.AreEqual(TEST_SHIFT, shiftCipher.GetKey(), "Incorrect key returned");
        }
        [TestMethod()]
        [TestCategory(SHIFT_CIPHER_TESTS)]
        public void CEASERS_CIPHER()
        {
            ShiftCipher myCipher = new ShiftCipher(ShiftCipher.MODE.CEASER);
            Assert.AreEqual(ShiftCipher.MODE.CEASER, myCipher.GetMode(), "default shift mode not set correctly");
            Assert.AreEqual(0, myCipher.GetKey(), "Incorrect defualt shift amount found");
            myCipher.GenKey();
            Assert.AreEqual(CEASERS_SHIFT, myCipher.GetKey(), "Incorrect shift amount found");
            string encStr = myCipher.Encrypt(TEST_STR);
            TestStrEnc(myCipher, encStr);
            TestStrDec(encStr, myCipher.Decrypt(encStr));
        }
        [TestMethod()]
        [TestCategory(SHIFT_CIPHER_TESTS)]
        public void ROT_13_TEST()
        {
            ShiftCipher myCipher = new ShiftCipher(ShiftCipher.MODE.ROT13);
            Assert.AreEqual(ShiftCipher.MODE.CEASER, myCipher.GetMode(), "default shift mode not set correctly");
            Assert.AreEqual(0, myCipher.GetKey(), "Incorrect defualt shift amount found");
            myCipher.GenKey();
            Assert.AreEqual(ROT_13_SHIFT, myCipher.GetKey(), "Incorrect shift amount found");
            string encStr = myCipher.Encrypt(TEST_STR);
            TestStrEnc(myCipher, encStr);
            TestStrDec(encStr, myCipher.Decrypt(encStr));
        }
        static void TestCtor(ShiftCipher cipher)
        {
            Assert.AreEqual(ShiftCipher.MODE.SHIFT, cipher.GetMode(), "default shift mode not set correctly");
            Assert.AreEqual(0, cipher.GetKey(), "Incorrect defualt shift amount found");
        }
        static void TestStrEnc(ShiftCipher cipher, string encStr)
        {
            Assert.AreNotEqual(0, cipher.GetKey(), "Key was not Generated");
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
        static void CompareFile(byte[] fileOne, byte[] fileTwo, bool  SameFile)
        {
            bool areEqual = true;
            int index = 0;
            areEqual = fileOne.Length == fileTwo.Length;
            while (areEqual ==  true && index < fileOne.Length)
            {
                areEqual = fileOne[index] == fileTwo[index];
                index++;
            }
            Assert.AreEqual(SameFile, areEqual, SameFile == true ? "mismatch of file found" : "files should be equal");
        }
    }
}