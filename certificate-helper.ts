import * as forge from "node-forge";
import NodeRSA from "node-rsa";
import * as jose from "jose";

interface ParsePfxResult {
  /**
   * The full certificate chain of the PFX file.
   */
  certificateChain: forge.pki.Certificate[];
  /**
   * The certificate that we will use to sign.
   */
  signingCertificate: forge.pki.Certificate;
  /**
   * The private key (PKCS#8 format) of the certificate to use to sign.
   */
  signingCertificatePrivateKey: jose.KeyLike;
}

export class CertificateHelper {
  /**
   * Parse info about given PFX bytes
   */
  static async parsePfxBytes(
    pfxFile: Buffer,
    pfxPassword: string
  ): Promise<ParsePfxResult> {
    const pkcs12Asn1 = forge.asn1.fromDer(pfxFile.toString("binary"));
    const pkcs12 = forge.pkcs12.pkcs12FromAsn1(pkcs12Asn1, pfxPassword);

    const certificateBags = this.getBags(pkcs12, forge.pki.oids.certBag!);
    const certificateChain = certificateBags
      .filter((bag) => bag.cert !== undefined)
      .map((bag) => bag.cert!)
      .sort((certA, certB) => {
        // Sort the chain from so the bottom-most child is first, and the root certificate is the last.
        if (certB.isIssuer(certA)) {
          return 1;
        }

        if (certA.isIssuer(certB)) {
          return -1;
        }

        return 0;
      });

    const certificate = certificateChain.find(
      (cert) => !certificateChain.some((c) => c.isIssuer(cert))
    )!;

    const privateKeyStr = this.getPkcs8PrivateKeyFromPkcs12(pkcs12);
    const privateKey = await jose.importPKCS8(privateKeyStr, "RS256");

    return {
      certificateChain,
      signingCertificate: certificate,
      signingCertificatePrivateKey: privateKey,
    };
  }

  /**
   * Convert given certificate to a DER formatted string
   */
  static getCertificateDer(certificate: forge.pki.Certificate): string {
    const pem = forge.pki.certificateToPem(certificate);
    const der = pem
      .split("\r\n")
      .filter((line) => !line.startsWith("-----"))
      .join("");
    return der;
  }

  /**
   * Get the HEX formatted thumbprint of given certificate
   */
  static getCertificateThumbprint(certificate: forge.pki.Certificate): string {
    const messageDigest = forge.md.sha256.create();
    messageDigest.update(
      forge.asn1.toDer(forge.pki.certificateToAsn1(certificate)).getBytes()
    );
    return messageDigest.digest().toHex();
  }

  /**
   * Get the private key in PKCS#8 format.
   */
  private static getPkcs8PrivateKeyFromPkcs12(
    pkcs12: forge.pkcs12.Pkcs12Pfx
  ): string {
    const privateKeyBags = this.getBags(
      pkcs12,
      forge.pki.oids.pkcs8ShroudedKeyBag!
    );
    const privateKeyBag = privateKeyBags[0]!;
    const privateKeyPkcs1 = forge.pki.privateKeyToPem(privateKeyBag.key!);

    // Convert the private key from PKCS#1 to PKCS#8 format.
    const nodeRsa = new NodeRSA();
    const nodeRsaKey = nodeRsa.importKey(privateKeyPkcs1, "pkcs1-private-pem");
    const privateKeyPkcs8 = nodeRsaKey.exportKey("pkcs8-private-pem");

    return privateKeyPkcs8;
  }

  /**
   * Get bags from given PKC12 certificate. A bag is roughly a (key + value) property.
   */
  private static getBags(
    pkcs12: forge.pkcs12.Pkcs12Pfx,
    bagType: string
  ): forge.pkcs12.Bag[] {
    const filteredBags = pkcs12.getBags({ bagType: bagType });
    const bags = filteredBags[bagType] ?? [];

    return bags;
  }
}
