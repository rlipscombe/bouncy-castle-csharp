using System;
using System.IO;
using System.Security.Cryptography.X509Certificates;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Crypto.Prng;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.Pkcs;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.Utilities;
using Org.BouncyCastle.X509;

namespace CreateSelfSigned
{
    static class Program
    {
        static int Main(string[] args)
        {
            if (args.Length != 2)
            {
                Console.WriteLine("CreateSelfSigned subject-name filename.pfx");
                return -1;
            }

            // Who is this certificate for? Pass, for example, "CN=foo"
            var subjectName = args[0];
            var outputFileName = args[1];

            // We're going to need some random numbers later, so create a RNG first.
            // Since we're on Windows, we'll use the CryptoAPI one (on the assumption
            // that it might have access to better sources of entropy than the built-in
            // Bouncy Castle ones):
            var randomGenerator = new CryptoApiRandomGenerator();
            var random = new SecureRandom(randomGenerator);

            var certificateGenerator = new X509V3CertificateGenerator();

            // The certificate needs a serial number. This is used for revocation,
            // and usually should be an incrementing index (which makes it easier to revoke a range of certificates).
            // Since we don't have anywhere to store the incrementing index, we can just use a random number.
            var serialNumber =
                BigIntegers.CreateRandomInRange(
                    BigInteger.One, BigInteger.ValueOf(Int64.MaxValue), random);
            certificateGenerator.SetSerialNumber(serialNumber);

            // Set the signature algorithm. This is used to generate the thumbprint which is then signed
            // with the issuer's private key. We'll use SHA-256, which is (currently) considered fairly strong.
            const string signatureAlgorithm = "SHA256WithRSA";
            certificateGenerator.SetSignatureAlgorithm(signatureAlgorithm);

            // It's self-signed, so these are the same.
            var subjectDN = new X509Name(subjectName);
            var issuerDN = subjectDN;
            certificateGenerator.SetIssuerDN(issuerDN);

            // Note: The subject can be omitted if you specify a subject alternative name (SAN).
            certificateGenerator.SetSubjectDN(subjectDN);

            // Our certificate needs valid from/to values.
            var notBefore = DateTime.UtcNow.Date;
            var notAfter = notBefore.AddYears(2);

            certificateGenerator.SetNotBefore(notBefore);
            certificateGenerator.SetNotAfter(notAfter);

            // Generate the subject's key pair. The strength is the key length.
            // For RSA, 2048 bits should be considered the minimum acceptable these days.
            const int strength = 2048;
            var keyGenerationParameters = new KeyGenerationParameters(random, strength);

            var keyPairGenerator = new RsaKeyPairGenerator();
            keyPairGenerator.Init(keyGenerationParameters);
            var subjectKeyPair = keyPairGenerator.GenerateKeyPair();

            // It's self-signed, so these are the same.
            var issuerKeyPair = subjectKeyPair;

            // The subject's public key goes in the certificate.
            certificateGenerator.SetPublicKey(subjectKeyPair.Public);

            // Add the Authority Key Identifier. According to http://www.alvestrand.no/objectid/2.5.29.35.html, this
            // identifies the public key to be used to verify the signature on this certificate.
            // In a certificate chain, this corresponds to the "Subject Key Identifier" on the issuer certificate.
            // The Bouncy Castle documentation, at http://www.bouncycastle.org/wiki/display/JA1/X.509+Public+Key+Certificate+and+Certification+Request+Generation,
            // shows how to create this from the issuing certificate. Since we're creating a self-signed certificate, we have to do this slightly differently.
            var issuerSerialNumber = serialNumber; // Self-signed, so it's the same serial number.

            var authorityKeyIdentifier =
                new AuthorityKeyIdentifier(
                    SubjectPublicKeyInfoFactory.CreateSubjectPublicKeyInfo(issuerKeyPair.Public),
                    new GeneralNames(new GeneralName(issuerDN)),
                    issuerSerialNumber);
            certificateGenerator.AddExtension(
                X509Extensions.AuthorityKeyIdentifier.Id, false, authorityKeyIdentifier);

            // Add the Subject Key Identifier.
            var subjectKeyIdentifier =
                new SubjectKeyIdentifier(
                    SubjectPublicKeyInfoFactory.CreateSubjectPublicKeyInfo(subjectKeyPair.Public));
            certificateGenerator.AddExtension(
                X509Extensions.SubjectKeyIdentifier.Id, false, subjectKeyIdentifier);

            // Add the "Basic Constraints" attribute.
            certificateGenerator.AddExtension(
                X509Extensions.BasicConstraints.Id, true, new BasicConstraints(false));

            // The certificate is signed with the issuer's private key.
            var certificate = certificateGenerator.Generate(issuerKeyPair.Private, random);

            // Now to convert the Bouncy Castle certificate to a .NET certificate.
            // See http://web.archive.org/web/20100504192226/http://www.fkollmann.de/v2/post/Creating-certificates-using-BouncyCastle.aspx
            // ...but, basically, we create a PKCS12 store (a .PFX file) in memory, and add the public and private key to that.
            var store = new Pkcs12Store();

            // What Bouncy Castle calls "alias" is the same as what Windows terms the "friendly name".
            string friendlyName = certificate.SubjectDN.ToString();

            // Add the certificate.
            var certificateEntry = new X509CertificateEntry(certificate);
            store.SetCertificateEntry(friendlyName, certificateEntry);

            // Add the private key.
            store.SetKeyEntry(friendlyName, new AsymmetricKeyEntry(subjectKeyPair.Private), new[] { certificateEntry });

            // Convert it to an X509Certificate2 object by saving/loading it from a MemoryStream.
            // It needs a password. Since we'll remove this later, it doesn't particularly matter what we use.
            const string password = "password";
            var stream = new MemoryStream();
            store.Save(stream, password.ToCharArray(), random);

            var convertedCertificate =
                new X509Certificate2(
                    stream.ToArray(), password,
                    X509KeyStorageFlags.PersistKeySet | X509KeyStorageFlags.Exportable);
            Console.WriteLine(convertedCertificate);

            File.WriteAllBytes(outputFileName, stream.ToArray());

            return 0;
        }
    }
}
