# RSA_token
c# RSA token library

sample code 

			token.RSA a = new token.RSA();
            a.key_generator();
            string rr = a.Encrypt("salamPeyman");

            token.RSA b = new token.RSA();
            b.public_key = a.public_key;
            b.private_key = a.private_key;
            string r = b.Decrypt(rr);
