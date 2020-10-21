using System;
using System.IO;
using System.Security.Cryptography;
using System.Text;

namespace UtilityClassDLL
{
    public class Conversion
    {
        public static string SHA512Encode(string input)
        {
            using (System.Security.Cryptography.SHA512Managed sha1 = new System.Security.Cryptography.SHA512Managed())
            {
                var hash = sha1.ComputeHash(Encoding.UTF8.GetBytes(input));
                StringBuilder result = new StringBuilder(hash.Length * 2);

                foreach (byte b in hash)
                {
                    result.Append(b.ToString("X2"));
                }

                return result.ToString();
            }
        }
        public static string Base64Encode(string input)
        {
            byte[] plainTextByte = System.Text.Encoding.UTF8.GetBytes(input);
            string resultText = Convert.ToBase64String(plainTextByte);

            return resultText;
        }
        public static string Base64Decoding(string input)
        {
            Encoding oEncoding = System.Text.Encoding.UTF8;

            byte[] Base64Byte = System.Convert.FromBase64String(input);
            return oEncoding.GetString(Base64Byte);
        }
        public static string HttpUrlEncoding(string input)
        {
            return System.Web.HttpUtility.UrlEncode(input);
        }
        public static string HttpUrlDeoding(string input)
        {
            return System.Web.HttpUtility.UrlDecode(input);
        }
        public static string EUC_KrEndcoding(string input)
        {
            System.Text.Encoding euckr = System.Text.Encoding.GetEncoding(51949);
            byte[] euckrBytes = euckr.GetBytes(input);

            string urlEncodingText = "";
            foreach (byte b in euckrBytes)
            {
                string addText = Convert.ToString(b, 16);
                urlEncodingText = urlEncodingText + "%" + addText;
            }
            return Convert.ToString(urlEncodingText);

        }
        public static string EUC_KrRangeEndcoding(string input)
        { // 한글과 특수문자만 인코딩한다.
            string result = "";
            for (byte i = 0; i < input.Length; i++)
            {
                char tmp = input[i];
                if (tmp >= 48 && tmp <= 57 || tmp >= 65 && tmp <= 90 || tmp >= 97 && tmp <= 122) result += input[i].ToString();
                else result += Conversion.EUC_KrEndcoding(input[i].ToString());
            }
            return result;

        }
        public static Encoding GetEUC_KrEncoding()
        {
            int euckrCodepage = 51949;
            Encoding encode = Encoding.GetEncoding(euckrCodepage);
            return encode;
        }

        public static string DES_Encrypt(string tag, string DESkey)
        {
            string result = "";
            

            while (true) //암호화할 문자열을 8의 배수로 맞춘다.
            {
                if (tag.Length % 8 != 0) tag += "\0";
                else break;
            }

            for (int i = 0; i < tag.Length; i += 8)
            {
                string tagTmp = "";
                for (int ii = 0; ii < 8; ii++)
                {
                    tagTmp += tag[i + ii].ToString();
                }
                byte[] clearData = Encoding.UTF8.GetBytes(tagTmp);
                byte[] key = Encoding.UTF8.GetBytes(DESkey);
                DES desEncrypt = new DESCryptoServiceProvider();
                desEncrypt.Mode = CipherMode.ECB; //암호 방식
                desEncrypt.Key = key;  //DES key
                desEncrypt.Padding = PaddingMode.PKCS7;
                ICryptoTransform transForm = desEncrypt.CreateEncryptor();
                MemoryStream encryptedStream = new MemoryStream();
                CryptoStream cryptoStream = new CryptoStream(encryptedStream, transForm, CryptoStreamMode.Write);
                cryptoStream.Write(clearData, 0, clearData.Length);
                byte[] encryptedData = encryptedStream.ToArray();
                for (byte ii = 0; ii < encryptedData.Length; ii++) result += StrToHex(encryptedData[ii]);
                
            }
            return "0x"+result;


        }
        public static string StrToHex(int data) //10진수를 16진수 문자열로 변환
        {
            string hex = data.ToString("x"); // 대문자 X일 경우 결과 hex값이 대문자로 나온다.
            if (hex.Length % 2 != 0)
            {
                hex = "0" + hex;
            }
            return hex;

        }


    }
}
