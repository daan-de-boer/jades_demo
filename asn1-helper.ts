import forge from "node-forge";

export class Asn1Helper {
  /**
   * Create an ASN1 object that contains the issuer of a certificate
   */
  static createIssuerAsn1(certificate: forge.pki.Certificate): forge.asn1.Asn1 {
    const attributes = certificate.issuer.attributes;

    const relativeDistinguishedNames = attributes
      .filter(
        (attribute) =>
          attribute.name !== undefined && attribute.value !== undefined
      )
      .map((attribute) => {
        const oid = forge.pki.oids[attribute.name!];

        if (oid === undefined) {
          throw new Error(`Attribute with unknown oid: ${attribute.name}`);
        }

        return forge.asn1.create(
          forge.asn1.Class.UNIVERSAL,
          forge.asn1.Type.SET,
          true,
          [
            forge.asn1.create(
              forge.asn1.Class.UNIVERSAL,
              forge.asn1.Type.SEQUENCE,
              true,
              [
                forge.asn1.create(
                  forge.asn1.Class.UNIVERSAL,
                  forge.asn1.Type.OID,
                  false,
                  forge.asn1.oidToDer(oid).getBytes()
                ),
                forge.asn1.create(
                  forge.asn1.Class.UNIVERSAL,
                  attribute.valueTagClass as number as forge.asn1.Type,
                  false,
                  attribute.value!
                ),
              ]
            ),
          ]
        );
      });

    return forge.asn1.create(
      forge.asn1.Class.UNIVERSAL,
      forge.asn1.Type.SEQUENCE,
      true,
      relativeDistinguishedNames
    );
  }

  /**
   * Create an ASN1 object that contains the serial number of a certificate
   */
  static createSerialNumberAsn1(
    certificate: forge.pki.Certificate
  ): forge.asn1.Asn1 {
    return forge.asn1.create(
      forge.asn1.Class.UNIVERSAL,
      forge.asn1.Type.INTEGER,
      false,
      Buffer.from(certificate.serialNumber, "hex").toString("binary")
    );
  }

  /**
   * Create an ASN1 object that contains the RFC5035 IssuerSerial type for a certificate.
   */
  static createIssuerSerialAsn1(
    certificate: forge.pki.Certificate
  ): forge.asn1.Asn1 {
    const serialNumber = this.createSerialNumberAsn1(certificate);
    const issuer = this.createIssuerAsn1(certificate);

    return forge.asn1.create(
      forge.asn1.Class.UNIVERSAL,
      forge.asn1.Type.SEQUENCE,
      true,
      [
        forge.asn1.create(
          forge.asn1.Class.UNIVERSAL,
          forge.asn1.Type.SEQUENCE,
          true,
          [
            forge.asn1.create(
              forge.asn1.Class.CONTEXT_SPECIFIC,
              forge.asn1.Type.OCTETSTRING,
              true,
              [issuer]
            ),
          ]
        ),
        serialNumber,
      ]
    );
  }

  /**
   * Encodes an ASN.1 object as base64 string.
   */
  static encodeAsn1AsBase64(asn1Object: forge.asn1.Asn1): string {
    const der = forge.asn1.toDer(asn1Object);
    return forge.util.encode64(der.data);
  }
}
