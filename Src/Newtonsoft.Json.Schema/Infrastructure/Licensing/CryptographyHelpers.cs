#region License
// Copyright (c) Newtonsoft. All Rights Reserved.
// License: https://raw.github.com/JamesNK/Newtonsoft.Json.Schema/master/LICENSE.md
#endregion

using System;
using System.IO;
using System.Reflection;
using System.Linq;
#if !PORTABLE || NETSTANDARD1_3
using System.Security.Cryptography;
#endif

namespace Newtonsoft.Json.Schema.Infrastructure.Licensing
{
    internal static class CryptographyHelpers
    {
        private const string PublicKey = "<RSAKeyValue><Modulus>wNE8tiipWCy2LmB3cZYW8nj5Nm/fn3X2GYsoSx6XE1yfvW96Ul/vRBw6/jAAwk9aZIdix9+gleh5x7XE8snzZlNMDDCmIFz2SWY9f7SdYYD5gif2rIpeeIDS/5J731d6XX/BKISwtM+MRWakY6ihNU1SUIGsKH6HxUXPm80Q66s=</Modulus><Exponent>AQAB</Exponent></RSAKeyValue>";
        private const string PublicKeyCsp = "BgIAAACkAABSU0ExAAQAAAEAAQCr6xDNm89FxYd+KKyBUFJNNaGoY6RmRYzPtLCEKMF/XXpX33uS/9KAeF6KrPYngvmAYZ20fz1mSfZcIKYwDExTZvPJ8sS1x3nolaDfx2KHZFpPwgAw/jocRO9fUnpvvZ9cE5ceSyiLGfZ1n99vNvl48haWcXdgLrYsWKkotjzRwA==";

        internal static bool ValidateData(byte[] data, byte[] signature)
        {
            bool valid;

            //RSA rsa = RSA.Create();
            //rsa.FromXmlString(PublicKey);
            //rsa.

#if true || (NETSTANDARD1_3)
            RSA rsa = RSA.Create();
            rsa.FromXmlString(PublicKey);
            valid = rsa.VerifyData(data, signature, HashAlgorithmName.SHA1, RSASignaturePadding.Pkcs1);

            //RSACryptoServiceProvider rsaCryptoServiceProvider = new RSACryptoServiceProvider();
            //rsaCryptoServiceProvider.ImportCspBlob(Convert.FromBase64String(PublicKeyCsp));

            valid = rsaCryptoServiceProvider.VerifyData(data, SHA1.Create(), signature);
#elif (PORTABLE && !NETSTANDARD1_3)
            try
            {
                Type rsaCryptoServiceProviderType = Type.GetType("System.Security.Cryptography.RSACryptoServiceProvider");
                MethodInfo importCspBlobMethod = rsaCryptoServiceProviderType.GetTypeInfo().GetDeclaredMethod("ImportCspBlob");
                MethodInfo verifyDataMethod = rsaCryptoServiceProviderType.GetTypeInfo().GetDeclaredMethod("VerifyData");
                Type sha1CryptoServiceProviderType = Type.GetType("System.Security.Cryptography.SHA1CryptoServiceProvider");

                object rsaCryptoServiceProvider = Activator.CreateInstance(rsaCryptoServiceProviderType);

                importCspBlobMethod.Invoke(rsaCryptoServiceProvider, new object[] { Convert.FromBase64String(PublicKeyCsp) });

                valid = (bool)verifyDataMethod.Invoke(rsaCryptoServiceProvider, new object[] { data, Activator.CreateInstance(sha1CryptoServiceProviderType), signature });
            }
            catch (InvalidOperationException)
            {
                // WinRT - Microsoft why do you do this? STAHP!

                Type asymmetricKeyAlgorithmProviderType = Type.GetType("Windows.Security.Cryptography.Core.AsymmetricKeyAlgorithmProvider, Windows.Security, ContentType=WindowsRuntime");
                MethodInfo openAlgorithmMethod = asymmetricKeyAlgorithmProviderType.GetTypeInfo().GetDeclaredMethod("OpenAlgorithm");
                MethodInfo importPublicKeyMethod = asymmetricKeyAlgorithmProviderType.GetTypeInfo().DeclaredMethods.Single(m => m.Name == "ImportPublicKey" && m.GetParameters().Length == 2);

                Type cryptographicBufferType = Type.GetType("Windows.Security.Cryptography.CryptographicBuffer, Windows.Security, ContentType=WindowsRuntime");
                MethodInfo decodeFromBase64StringMethod = cryptographicBufferType.GetTypeInfo().GetDeclaredMethod("DecodeFromBase64String");
                MethodInfo createFromByteArrayMethod = cryptographicBufferType.GetTypeInfo().GetDeclaredMethod("CreateFromByteArray");

                Type cryptographicEngineType = Type.GetType("Windows.Security.Cryptography.Core.CryptographicEngine, Windows.Security, ContentType=WindowsRuntime");
                MethodInfo verifySignatureMethod = cryptographicEngineType.GetTypeInfo().GetDeclaredMethod("VerifySignature");

                object algorithmProvider = openAlgorithmMethod.Invoke(null, new object[] { "RSASIGN_PKCS1_SHA1" });
                object publicKeyBuffer = decodeFromBase64StringMethod.Invoke(null, new object[] { PublicKeyCsp });
                object publicKey = importPublicKeyMethod.Invoke(algorithmProvider, new object[] { publicKeyBuffer, 3 });
                object dataBuffer = createFromByteArrayMethod.Invoke(null, new object[] { data });
                object signatureBuffer = createFromByteArrayMethod.Invoke(null, new object[] { signature });

                valid = (bool)verifySignatureMethod.Invoke(null, new object[] { publicKey, dataBuffer, signatureBuffer });
            }
#else
            RSACryptoServiceProvider rsaCryptoServiceProvider = new RSACryptoServiceProvider();
            rsaCryptoServiceProvider.ImportCspBlob(Convert.FromBase64String(PublicKeyCsp));

            valid = rsaCryptoServiceProvider.VerifyData(data, new SHA1CryptoServiceProvider(), signature);
#endif

            return valid;
        }

        internal static RSAParameters ToRSAParameters(this byte[] cspBlob, bool includePrivateParameters)
        {
            try
            {
                BinaryReader br = new BinaryReader(new MemoryStream(cspBlob));

                byte bType = br.ReadByte();    // BLOBHEADER.bType: Expected to be 0x6 (PUBLICKEYBLOB) or 0x7 (PRIVATEKEYBLOB), though there's no check for backward compat reasons. 
                byte bVersion = br.ReadByte(); // BLOBHEADER.bVersion: Expected to be 0x2, though there's no check for backward compat reasons.
                br.ReadUInt16();               // BLOBHEADER.wReserved
                int algId = br.ReadInt32();    // BLOBHEADER.aiKeyAlg
                if (algId != CALG_RSA_KEYX)
                    throw new PlatformNotSupportedException();  // The FCall this code was ported from supports other algid's but we're only porting what we use.

                int magic = br.ReadInt32();    // RSAPubKey.magic: Expected to be 0x31415352 ('RSA1') or 0x32415352 ('RSA2') 
                int bitLen = br.ReadInt32();   // RSAPubKey.bitLen

                int modulusLength = bitLen / 8;
                int halfModulusLength = (modulusLength + 1) / 2;

                uint expAsDword = br.ReadUInt32();

                RSAParameters rsaParameters = new RSAParameters();
                rsaParameters.Exponent = ExponentAsBytes(expAsDword);
                rsaParameters.Modulus = br.ReadReversed(modulusLength);
                if (includePrivateParameters)
                {
                    rsaParameters.P = br.ReadReversed(halfModulusLength);
                    rsaParameters.Q = br.ReadReversed(halfModulusLength);
                    rsaParameters.DP = br.ReadReversed(halfModulusLength);
                    rsaParameters.DQ = br.ReadReversed(halfModulusLength);
                    rsaParameters.InverseQ = br.ReadReversed(halfModulusLength);
                    rsaParameters.D = br.ReadReversed(modulusLength);
                }

                return rsaParameters;
            }
            catch (EndOfStreamException)
            {
                // For compat reasons, we throw an E_FAIL CrytoException if CAPI returns a smaller blob than expected.
                // For compat reasons, we ignore the extra bits if the CAPI returns a larger blob than expected.
                throw E_FAIL.ToCryptographicException();
            }
        }
    }
}