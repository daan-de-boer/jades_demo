# JAdES demo

This reposity demonstrates signing a JSON object to create a JAdES (Baseline-B) compliant JWS signature.
It is a TypeScript app that mainly depends on two packages:
- `jose`: For JSON signing
- `node-forge`: For working with certificates

# Setting up and running the app

- Make sure you have a version of [Node.js](https://nodejs.org/en) installed.
- Create a `.env` file in the root of this repository, with two variables:
  - `CERTIFICATE_PATH`: Relative path (from the root of this repository) to a .pfx certificate file. The certificate must have its private key included in the file (PKCS#12 format).
  - `CERTIFICATE_PASSWORD`: Password of the .pfx file.

Example .env file:

```.env
CERTIFICATE_PATH=certificates/my-certificate.pfx
CERTIFICATE_PASSWORD=my-password
```

- Run `npm install`
- Run `npm run start` to run the app. The app should print out the signature to console

The signature is computed over a hard coded object. Feel free to adjust the variable `jsonToSign` in `app.ts` any way you like.

# Files

The file `app.ts` is the main example of this app, specifically the function call chain that signs the object: `jwsSigner.addSignature(..).setProtectedHeader(..).sign();`

Most notably are the parameters of the `setProtectedHeader` function. These configure how and in what way the JWS signature is created. Each individual property of the protected header is annotated with an explanation of what the field is and how its value is constructed.

The file `certificate-helper.ts` contains various functions to interact with the certificate, such as extracting information from them, converting formats, etc.

The file `asn1-helper.ts` contains various functions to build ASN1 data structures.
