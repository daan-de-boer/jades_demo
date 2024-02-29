import * as dotenv from "dotenv";
import * as fs from "fs";
import * as jose from "jose";
import { Asn1Helper } from "./asn1-helper";
import { CertificateHelper } from "./certificate-helper";

dotenv.config();

const certificatePath = process.env.CERTIFICATE_PATH!;
const certificatePassword = process.env.CERTIFICATE_PASSWORD!;
const certificateBytes = fs.readFileSync(certificatePath);

// This is the example JSON object we are going to sign.
// This can be any object.
const jsonToSign = {
  refKey: "34a260e4-c98f-43b6-a451-f9805ae0e231",
  itemType: "tsvjBatch",
  items: [
    {
      refKey: "4265094b-4eea-4f03-8cd1-0c8e5f931f76",
      itemType: "tsvjCreateCertificate",
      initialBalance: {
        balance: 12,
        source: "royDataInsurer",
      },
      certificateHolder: {
        certificateHolderType: "naturalPerson",
        initials: "JWS",
        prefixes: "",
        surname: "JWS demo",
        birthDate: "1990-01-01",
        postalCode: "5511AA",
        houseNumber: 9,
        houseNumberAddition: "",
        country: "NL",
      },
      object: {
        entityType: "motorVehicle",
        licensePlate: "8KKT26",
      },
      policy: {
        contractNumber: "p.jws.00001",
        effectiveDate: "2024-01-01",
        coverages: [
          {
            entityType: "thirdPartyLiability",
            coverageCode: "2001",
          },
        ],
      },
    },
  ],
};

(async () => await main())();

async function main() {
  // Extract some info from the PFX certificate that we need to supply to the JWS signer class.
  const parsedPfx = await CertificateHelper.parsePfxBytes(
    certificateBytes,
    certificatePassword
  );

  // Create an instance of the JWS signer.
  const jsonToSignBuffer = Buffer.from(JSON.stringify(jsonToSign));
  const jwsSigner = new jose.GeneralSign(jsonToSignBuffer);

  // Prepare some values that we need to add to the protected header of the JWS.
  const keyIdAsn1 = Asn1Helper.createIssuerSerialAsn1(
    parsedPfx.signingCertificate
  );
  const keyIdBase64 = Asn1Helper.encodeAsn1AsBase64(keyIdAsn1);
  const certificateChainDerEncoded = parsedPfx.certificateChain.map(
    CertificateHelper.getCertificateDer
  );

  // Sign the payload with given 'settings'.
  // This combination of settings and their values is what makes this JWS a JAdES (Baseline-B) compliant JWS.
  const jadesSignature = await jwsSigner
    .addSignature(parsedPfx.signingCertificatePrivateKey, {
      crit: {
        // Indicates which non-standard fields are going to be added in the protected header
        sigT: true,
      },
    })
    .setProtectedHeader({
      // Signing algorithm
      alg: "RS256",

      // Content type
      cty: "json",

      // The content type of the resulting signature object.
      typ: "jose+json",

      // Key ID. This value helpts to identify the certificate that was used to sign the object.
      // It is a base64 encoded string of a DER encoded instance of 'IssuerSerial'.
      // This 'IssuerSerial' type is defined in IETF RFC 5035. Its details are specified here: https://datatracker.ietf.org/doc/html/rfc5035.
      // This is hard to summarize in a few words, but essentially it combines ASN1 data structures of the certificate's issuer and serial-number.
      // Alternativly, refer to `Asn1Helper.createIssuerSerialAsn1` to see how it is constructed.
      kid: keyIdBase64,

      // A base64 encoded string of the SHA256 hash of the DER encoded certificate.
      // In steps:
      // X509 certificate -> Convert to DER encoded string -> Hash using SHA256 (hex representation) -> Encode as Base64.
      "x5t#S256": Buffer.from(
        CertificateHelper.getCertificateThumbprint(
          parsedPfx.signingCertificate
        ),
        "hex"
      ).toString("base64url"),

      // An array of DER encoded public keys of each certificate in the certificate chain.
      x5c: certificateChainDerEncoded,

      // The timestamp the signature was computed at.
      // According to the JAdES specification that may be a full ISO string.
      // However, the EU's own validation tool doesn't accept the timestamp with a milliseconds component,
      // so we strip it from the ISO string.
      // XChains accepts either format.
      sigT: new Date().toISOString().split(".")[0] + "Z",

      // Array of non-standard JWS field that we also added to the header.
      // For JAdES, this is only 'sigT'.
      crit: ["sigT"],
    })
    .sign();

  // Print the result
  const signatureJsonString = JSON.stringify(jadesSignature, undefined, 2);
  console.log(signatureJsonString);
}
