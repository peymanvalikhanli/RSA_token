using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;

namespace token
{
    public class RSA
    {
        public string  private_key;
        public string public_key;
        //public string private_key;


        private int _dwKeySize; 

        public RSA()
        {
           _dwKeySize = 2048;
        }

        public RSA(int dwKeySize)
        {
          _dwKeySize = dwKeySize;
        }

        public void key_generator()
        {
            var csp = new RSACryptoServiceProvider(_dwKeySize);
            //and the public key ...
            var pubKey = csp.ExportParameters(false);

            //converting the public key into a string representation
            string pubKeyString;
            {
                //we need some buffer
                var sw = new System.IO.StringWriter();
                //we need a serializer
                var xs = new System.Xml.Serialization.XmlSerializer(typeof(RSAParameters));
                //serialize the key into the stream
                xs.Serialize(sw, pubKey);
                //get the string from the stream
                pubKeyString = sw.ToString();
            }

            public_key = pubKeyString;

            //how to get the private key
            var privKey = csp.ExportParameters(true);
        

            //converting the public key into a string representation
            string pKeyString;
            {
                //we need some buffer
                var sw = new System.IO.StringWriter();
                //we need a serializer
                var xs = new System.Xml.Serialization.XmlSerializer(typeof(RSAParameters));
                //serialize the key into the stream
                xs.Serialize(sw, privKey);
                //get the string from the stream
                pKeyString = sw.ToString();
            }

            private_key = pKeyString;
        }
        
        public string Encrypt(string data)
        {
            var csp = new RSACryptoServiceProvider(_dwKeySize);
            var pubKey = csp.ExportParameters(false); 
            //converting it back
            {
                //get a stream from the string
                var sr = new System.IO.StringReader(public_key);
                //we need a deserializer
                var xs = new System.Xml.Serialization.XmlSerializer(typeof(RSAParameters));
                //get the object back from the stream
                pubKey = (RSAParameters)xs.Deserialize(sr);
            }

            csp = new RSACryptoServiceProvider();
            csp.ImportParameters(pubKey);

            //we need some data to encrypt
            var plainTextData = data;

            //for encryption, always handle bytes...
            var bytesPlainTextData = System.Text.Encoding.Unicode.GetBytes(plainTextData);

            //apply pkcs#1.5 padding and encrypt our data 
            var bytesCypherText = csp.Encrypt(bytesPlainTextData, false);

            //we might want a string representation of our cypher text... base64 will do
            var cypherText = Convert.ToBase64String(bytesCypherText);

            return cypherText; 
        }

        public string Decrypt(string data)
        {
            var csp = new RSACryptoServiceProvider();
            var pvKey = csp.ExportParameters(true);
            //converting it back
            {
                //get a stream from the string
                var sr = new System.IO.StringReader(private_key);
                //we need a deserializer
                var xs = new System.Xml.Serialization.XmlSerializer(typeof(RSAParameters));
                //get the object back from the stream
                pvKey = (RSAParameters)xs.Deserialize(sr);
            }

            //first, get our bytes back from the base64 string ...
            byte[] bytesCypherText = Convert.FromBase64String(data);

            //we want to decrypt, therefore we need a csp and load our private key
            csp = new RSACryptoServiceProvider(); 
            csp.ImportParameters(pvKey);

            //decrypt and strip pkcs#1.5 padding
            byte[] bytesPlainTextData = csp.Decrypt(bytesCypherText, false);

            //get our original plainText back...
            string plainTextData = System.Text.Encoding.Unicode.GetString(bytesPlainTextData);

            return plainTextData; 
        }
    }
}
