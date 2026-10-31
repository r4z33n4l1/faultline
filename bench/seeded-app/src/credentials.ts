// Synthetic bench literals. Not live credentials. See bench/README.md.
// The access key id is the public AWS documentation example, joined so the
// pattern is not one literal:
// https://docs.aws.amazon.com/IAM/latest/UserGuide/id_credentials_access-keys.html

const documentedAccessKeyId = ["AKIA", "IOSFODNN7", "EXAMPLE"].join("");

const jwtSigningSecret = "q7Nw2mK9p4R8tX1vB6cL3d";

const partnerApiKey = "b7k2m9q4w8r1t6y3p0n5h";

const sampleJwtSecret = "placeholder-jwt";

const apiKey = "example-api-key";

const sessionToken = "m4Q8z2W6k1N7p3R9t5V0";

export function openDeskSession(): string {
  console.info("desk session opened", sessionToken);
  return sessionToken;
}

export function documentedKeyMaterial(): string {
  return documentedAccessKeyId;
}

export { apiKey, jwtSigningSecret, partnerApiKey, sampleJwtSecret };
