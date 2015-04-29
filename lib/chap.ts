/// <reference path="../typings/node/node.d.ts" />
import crypto = require("crypto");

module chap {
  export type Password = string|Buffer;

  export class CHAP {
    // See http://tools.ietf.org/html/rfc1994#section-2 and https://tools.ietf.org/html/rfc2865#section-7.2
    static ChallengeResponse(id: Buffer, password: string, challenge: Buffer): Buffer {
      var md5 = crypto.createHash("md5");
      md5.update(id.slice(0, 1)); // Take only the first octet as the CHAP ID.
      md5.update(password);
      md5.update(challenge);
      return md5.digest();
    }
  }

  export class MSCHAPv1 {
    // See http://tools.ietf.org/html/rfc2433  -  Appendix A

    static LmChallengeResponse(challenge: Buffer, password: string): Buffer {
      var ucasePassword = password.toUpperCase();

      var passwordBuffer = new Buffer(ucasePassword); // This should be OEM, but maybe utf8/unicode will do?
      var finalPasswordBuffer = new Buffer(14);

      finalPasswordBuffer.fill(0);
      passwordBuffer.copy(finalPasswordBuffer);

      var passwordHash1 = this.DesHash(passwordBuffer.slice(0, 7));
      var passwordHash2 = this.DesHash(passwordBuffer.slice(7, 14));

      var passwordHash = new Buffer(16);
      passwordHash1.copy(passwordHash, 0);
      passwordHash2.copy(passwordHash, 8);

      return this.ChallengeResponse(challenge, passwordHash);
    }

    static NtChallengeResponse(challenge: Buffer, password: Password): Buffer {
      var passwordBuffer: Buffer = new Buffer(<string>password, "utf16le");
      
      var md4 = crypto.createHash("md4");
      md4.update(passwordBuffer);

      var passwordHash = md4.digest();

      return this.ChallengeResponse(challenge, passwordHash);
    }

    static ChallengeResponse(challenge: Buffer, passwordHash: Buffer): Buffer {
      var zPasswordHash = new Buffer(21);
      zPasswordHash.fill(0);
      passwordHash.copy(zPasswordHash);

      var res1 = this.DesEncrypt(challenge, zPasswordHash.slice(0, 7)); //   1st 7 octets of zPasswordHash as key.
      var res2 = this.DesEncrypt(challenge, zPasswordHash.slice(7, 14)); //  2nd 7 octets of zPasswordHash as key.
      var res3 = this.DesEncrypt(challenge, zPasswordHash.slice(14, 21)); // 3rd 7 octets of zPasswordHash as key.

      var resBuffer = new Buffer(24);

      res1.copy(resBuffer, 0);
      res2.copy(resBuffer, 8);
      res3.copy(resBuffer, 16);

      return resBuffer;
    }

    private static DesHash(key: Buffer): Buffer {
      return this.DesEncrypt(new Buffer("KGS!@#$%", "ascii"), key);
    }

    static DesEncrypt(clear: Buffer, key: Buffer): Buffer {
      var des = crypto.createCipheriv("des-ecb", this._ParityKey(key), new Buffer(0));
      des.setAutoPadding(false);

      return Buffer.concat([des.update(clear), des.final()]);
    }

    private static _ParityKey(key: Buffer): Buffer {
      var parityKey = new Buffer(8);
      var next: number = 0;
      var working: number = 0;

      for (var i = 0; i < 7; i++) {
        working = key[i];

        parityKey[i] = (working >> i) | next | 1;

        next = working << (7 - i);
      }

      parityKey[i] = next | 1;

      return parityKey;
    }
  }

  export class MSCHAPv2 {
    // See http://tools.ietf.org/html/rfc2759#section-8.7

    /**
     * Generate an authenticator response for MS-CHAPv2.
     * 
     * @param password                Password max length is 256 Unicode characters.
     * @param NT_response             An array of 24 Buffer bytes.
     * @param peer_challenge          An array of 16 Buffer bytes.
     * @param authenticator_challenge An array of 16 Buffer bytes.
     * @param username                Username max length is 256 ASCII characters.
     * @returns {string}              The authenticator response as "S=" followed by 40 hexadecimal digits.
     */
    static GenerateAuthenticatorResponse(password: string, NT_response: Buffer, peer_challenge: Buffer, authenticator_challenge: Buffer, username: string): string {
      password = password || "";
      username = username || "";
      if (NT_response.length !== 24 || peer_challenge.length !== 16 || authenticator_challenge.length !== 16) return null;

      var Magic1 = new Buffer(
        [0x4D, 0x61, 0x67, 0x69, 0x63, 0x20, 0x73, 0x65, 0x72, 0x76,
        0x65, 0x72, 0x20, 0x74, 0x6F, 0x20, 0x63, 0x6C, 0x69, 0x65,
        0x6E, 0x74, 0x20, 0x73, 0x69, 0x67, 0x6E, 0x69, 0x6E, 0x67,
        0x20, 0x63, 0x6F, 0x6E, 0x73, 0x74, 0x61, 0x6E, 0x74]);
      var Magic2 = new Buffer(
        [0x50, 0x61, 0x64, 0x20, 0x74, 0x6F, 0x20, 0x6D, 0x61, 0x6B,
        0x65, 0x20, 0x69, 0x74, 0x20, 0x64, 0x6F, 0x20, 0x6D, 0x6F,
        0x72, 0x65, 0x20, 0x74, 0x68, 0x61, 0x6E, 0x20, 0x6F, 0x6E,
        0x65, 0x20, 0x69, 0x74, 0x65, 0x72, 0x61, 0x74, 0x69, 0x6F,
        0x6E]);

      var md4 = crypto.createHash("md4");
      md4.update(password, "utf16le");
      var passwordHash = md4.digest();

      md4 = crypto.createHash("md4");
      md4.update(passwordHash);
      var passwordHashHash = md4.digest();

      var sha1 = crypto.createHash("sha1");
      sha1.update(passwordHashHash);
      sha1.update(NT_response);
      sha1.update(Magic1);
      var passwordDigest = sha1.digest();


      sha1 = crypto.createHash("sha1");
      sha1.update(peer_challenge);
      sha1.update(authenticator_challenge);
      sha1.update(username, "ascii");
      var challenge = sha1.digest().slice(0, 8); // Return the first 8 bytes from the SHA1 digest.

      sha1 = crypto.createHash("sha1");
      sha1.update(passwordDigest);
      sha1.update(challenge);
      sha1.update(Magic2);
      var authenticatorResponse: string = sha1.digest("hex");


      return "S=" + authenticatorResponse.toUpperCase();
    }
  }
}


export = chap;