using System;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using Org.BouncyCastle.Bcpg.OpenPgp;
using System.IO;
using Org.BouncyCastle.Bcpg;
using PgpLibrary;


namespace PgpLibaryTests
{
    [TestClass]
    public class PgpVerifierTests
    {
        //Email and password used to sign messages for reference
        private static string email = "test@test.com";
        private static string password = "password";

        private static string publicKey = "-----BEGIN PGP PUBLIC KEY BLOCK-----\r\n" +
                                          "Version: BCPG v1.47\r\n\r\n" +
                                          "mQGiBFJdVcoRBADfRukL6FwlUN0N80dxd6WUw2MHAfYdzwuJaEJ98HoceSJWlLeK" +
                                          "AGPkLc7Fo514ITodAy6ZsJS6uftfVHz5Puz0KIyFcIrvP+P9IlTaVk2zPzxcpU0h" +
                                          "gpLOYBk5BYST8VueCc0F+iHKmNYH5H4MRs2FkBNaQYVFiw+b5nbi37wPQQCgotdH" +
                                          "tVW881m7mqVVs6F17Qo80csD/iN8yRbjQHXZfd0ZsL63Yli4JzciK6rJrxIvun/O" +
                                          "zbLRE64cn1vWOJVfBbRCHRL7vt2QkuGuQm2qpSp7MMBQKrAasexuKvukDSxQlSAX" +
                                          "sR1TwAT36/ZmAxHL2BlPsoUvX197puwQxGFrcu0mgNIZmr2YQvfDxEW021+cgiVS" +
                                          "nPKWA/9vYv4whXabmZT2I+WNPOxH0zrsDANIANqsp3gF26V3fXDocVzIDTuRbs2J" +
                                          "rETM+ZfNqDjXt9rOCLHUSVA2SSYTuGBJeMK+EJlFvNMuU6N//ZR7b5c65CoLvN7S" +
                                          "y62ZdTf+UFdP9l8JMWOM+yo6pfBmvVNK+2rbVLGvS9mL01gkJrQYdGVzdHBhaXIg" +
                                          "PHRlc3RAdGVzdC5jb20+iEYEExECAAYFAlJdVcoACgkQvE+l7g7ePbB0fwCeNmB2" +
                                          "0KCpxpRhR6xxDLPekKjWH2UAn1vmh7ktlb/0rZjCIjM2B/OrjZqJuMwEUl1VyhAC" +
                                          "AJSU/sCV87he4oZUKzg2/IGl3QoDSbTCOd04dE1IjPjjHbi8t9M7Qau55aM8ypFE" +
                                          "sc7zMslL8Fc78EejrKmM3zsB/RU9XWFyrbQwRbaK6OHeEHC2E3AFaG0p09c6d0kZ" +
                                          "loHuWyEsm5a/3PpbIM1eP9IESJXWCc+bQQt6DxLKHLmkKMwB/3rtkUtG7CpdKDmO" +
                                          "YTU15oK12ONvTcdUeIhWVDAbTCZ4mpR2Puz8WwUguuQI2fbC7IHGOPYWj94/C6Wv" +
                                          "Pe+Q2aCIRgQYEQIABgUCUl1VywAKCRC8T6XuDt49sAg3AKCBxt0vA3XKxlc8NuZY" +
                                          "eKwqU2E34QCfb6ed205eQoGjWMB8Hr2HV3UmveU=\r\n" +
                                          "=QQHY\r\n" +
                                          "-----END PGP PUBLIC KEY BLOCK-----\r\n";

        string ticket = "I pity the fool who dosen't sign messages.";

        string correctSignatureForTicket = "-----BEGIN PGP SIGNATURE-----\r\n" +
                                           "Version: BCPG v1.47\r\n\r\n" +
                                           "iGAEARECACAFAlJdVpwZHHRlc3RwYWlyIDx0ZXN0QHRlc3QuY29tPgAKCRC8T6Xu" +
                                           "Dt49sNoJAJ4moLkNl0UsxVwSsGXcq4ImRugucACfSkZkKFtntVH2rIxNm64N707c" +
                                           "oQA=\r\n" +
                                           "=6vfJ\r\n" +
                                           "-----END PGP SIGNATURE-----\r\n";

        [TestMethod]
        public void ShouldBeAbleToVerifyACorrectSignature()
        {
            Stream signatureStream = new System.IO.MemoryStream(System.Text.Encoding.UTF8.GetBytes(correctSignatureForTicket));
            Stream ticketStream = new System.IO.MemoryStream(System.Text.Encoding.UTF8.GetBytes(ticket));
            Stream keyString = new System.IO.MemoryStream(System.Text.Encoding.UTF8.GetBytes(publicKey));

            Assert.IsTrue(PgpVerifier.VerifyTicketWithSignature(ticketStream, signatureStream, keyString));
        }

        [TestMethod]
        public void ShouldFailOnACorruptedTicket()
        {
            String corruptTicket = "Mr T does not pity any fools.";
            Stream corruptTicketStream = new System.IO.MemoryStream(System.Text.Encoding.UTF8.GetBytes(corruptTicket));

            Stream signatureStream = new System.IO.MemoryStream(System.Text.Encoding.UTF8.GetBytes(correctSignatureForTicket));
            Stream keyString = new System.IO.MemoryStream(System.Text.Encoding.UTF8.GetBytes(publicKey));
            
            Assert.IsFalse(PgpVerifier.VerifyTicketWithSignature(corruptTicketStream, signatureStream, keyString));
        }

        [TestMethod]
        public void ShouldThrowExceptionOnInvalidSignature()
        {
            string corruptSignature = "-----BEGIN PGP SIGNATURE-----\r\n" +
                                      "Version: BCPG v1.47\r\n\r\n" +
                                      "My spoon is too big\r\n" +
                                      "=6vfJ\r\n" +
                                      "-----END PGP SIGNATURE-----\r\n";

            Stream signatureStream = new System.IO.MemoryStream(System.Text.Encoding.UTF8.GetBytes(corruptSignature));
            Stream ticketStream = new System.IO.MemoryStream(System.Text.Encoding.UTF8.GetBytes(ticket));
            Stream keyString = new System.IO.MemoryStream(System.Text.Encoding.UTF8.GetBytes(publicKey));

            try
            {
                PgpVerifier.VerifyTicketWithSignature(ticketStream, signatureStream, keyString);
            }
            catch(IOException e) 
            {
                StringAssert.Contains(e.Message, "unknown object in stream");
                return;
            }
            Assert.Fail();
        }

        [TestMethod]
        public void ShouldThrowExceptionOnIncorrectPublicKey()
        {
            string corruptPublicKey = "-----BEGIN PGP PUBLIC KEY BLOCK-----\r\n" +
                                          "Version: BCPG v1.47\r\n\r\n" +
                                          "eKwqU2E34QCfb6ed205eQoGjWMB8Hr2HV3UmveU=\r\n" +
                                          "=QQHY\r\n" +
                                      "-----END PGP PUBLIC KEY BLOCK-----\r\n";

            Stream signatureStream = new System.IO.MemoryStream(System.Text.Encoding.UTF8.GetBytes(correctSignatureForTicket));
            Stream ticketStream = new System.IO.MemoryStream(System.Text.Encoding.UTF8.GetBytes(ticket));
            Stream keyString = new System.IO.MemoryStream(System.Text.Encoding.UTF8.GetBytes(corruptPublicKey));

            try
            {
                PgpVerifier.VerifyTicketWithSignature(ticketStream, signatureStream, keyString);
            }
            catch (IOException e)
            {
                StringAssert.Contains(e.Message, "unknown object in stream");
                return;
            }

            Assert.Fail();
        }

        [TestMethod]
        public void ShouldThrowExceptionOnInvalidHeader()
        {

            string publicKeyInvalidHeader = "-----BEGIN PGP PUBLIC KEY BLOCK-----\r\n" +
                                            "Version: BCPG v1.47\r\n\r\n" +
                                            "I am a banana\r\n" +
                                            "=QQHY\r\n" +
                                            "-----END PGP PUBLIC KEY BLOCK-----\r\n";

            Stream signatureStream = new System.IO.MemoryStream(System.Text.Encoding.UTF8.GetBytes(correctSignatureForTicket));
            Stream ticketStream = new System.IO.MemoryStream(System.Text.Encoding.UTF8.GetBytes(ticket));
            Stream invalidHeaderKeyString = new System.IO.MemoryStream(System.Text.Encoding.UTF8.GetBytes(publicKeyInvalidHeader));

            try
            {
                PgpVerifier.VerifyTicketWithSignature(ticketStream, signatureStream, invalidHeaderKeyString);
            }
            catch (IOException e)
            {
                StringAssert.Contains(e.Message, "invalid header encountered");
                return;
            }
            Assert.Fail();
        }
    }
}
