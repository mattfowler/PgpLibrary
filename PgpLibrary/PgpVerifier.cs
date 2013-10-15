using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.IO;
using Org.BouncyCastle.Bcpg.OpenPgp;

namespace PgpLibrary
{
    public class PgpVerifier
    {
        public static bool VerifyTicketWithSignature(Stream ticketStream, Stream signatureStream, Stream publicKeyStream)
        {
            signatureStream = PgpUtilities.GetDecoderStream(signatureStream);

            PgpObjectFactory pgpFact = new PgpObjectFactory(signatureStream);
            PgpSignatureList signatureList = (PgpSignatureList)pgpFact.NextPgpObject();

            PgpSignature signature = signatureList[0];

            PgpPublicKeyRingBundle pgpRing = new PgpPublicKeyRingBundle(PgpUtilities.GetDecoderStream(publicKeyStream));
            PgpPublicKey key = pgpRing.GetPublicKey(signature.KeyId);

            signature.InitVerify(key);

            int ch;
            while ((ch = ticketStream.ReadByte()) >= 0)
            {
                signature.Update((byte)ch);
            }
            return signature.Verify();
        }
    }
}
