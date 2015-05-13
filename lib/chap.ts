/// <reference path="../typings/node/node.d.ts" />
import crypto = require("crypto");

module chap {
  export type Password = string|Buffer;

  export module CHAP {
    // See http://tools.ietf.org/html/rfc1994#section-2 and https://tools.ietf.org/html/rfc2865#section-7.2
    export function ChallengeResponse(id: Buffer, password: string, challenge: Buffer): Buffer {
      var md5 = crypto.createHash("md5");
      md5.update(id.slice(0, 1)); // Take only the first octet as the CHAP ID.
      md5.update(password);
      md5.update(challenge);
      return md5.digest();
    }
  }

  export module MSCHAPv1 {
    // See http://tools.ietf.org/html/rfc2433  -  Appendix A

    export function LmPasswordHash(password: string): Buffer {
      var ucasePassword = password.toUpperCase();

      var passwordBuffer = new Buffer(ucasePassword); // This should be OEM, but maybe utf8/unicode will do?
      var finalPasswordBuffer = new Buffer(14);

      finalPasswordBuffer.fill(0);
      passwordBuffer.copy(finalPasswordBuffer);

      var passwordHash1 = DesHash(passwordBuffer.slice(0, 7));
      var passwordHash2 = DesHash(passwordBuffer.slice(7, 14));

      var passwordHash = new Buffer(16);
      passwordHash1.copy(passwordHash, 0);
      passwordHash2.copy(passwordHash, 8);

      return passwordHash;
    }

    export function NtPasswordHash(password: Password): Buffer {
      var passwordBuffer: Buffer = new Buffer(<string>password, "utf16le");

      var md4 = crypto.createHash("md4");
      md4.update(passwordBuffer);

      return md4.digest();
    }

    export function LmChallengeResponse(challenge: Buffer, password: string): Buffer {
      var passwordHash = LmPasswordHash(password);

      return ChallengeResponse(challenge, passwordHash);
    }

    export function NtChallengeResponse(challenge: Buffer, password: Password): Buffer {
      var passwordHash = NtPasswordHash(password);

      return ChallengeResponse(challenge, passwordHash);
    }

    export function ChallengeResponse(challenge: Buffer, passwordHash: Buffer): Buffer {
      var zPasswordHash = new Buffer(21);
      zPasswordHash.fill(0);
      passwordHash.copy(zPasswordHash);
      
      var res1 = DesEncrypt(challenge, zPasswordHash.slice(0, 7)); //   1st 7 octets of zPasswordHash as key.
      var res2 = DesEncrypt(challenge, zPasswordHash.slice(7, 14)); //  2nd 7 octets of zPasswordHash as key.
      var res3 = DesEncrypt(challenge, zPasswordHash.slice(14, 21)); // 3rd 7 octets of zPasswordHash as key.

      var resBuffer = new Buffer(24);

      res1.copy(resBuffer, 0);
      res2.copy(resBuffer, 8);
      res3.copy(resBuffer, 16);

      return resBuffer;
    }

    export function DesHash(key: Buffer): Buffer {
      return DesEncrypt(new Buffer("KGS!@#$%", "ascii"), key);
    }

    export function DesEncrypt(clear: Buffer, key: Buffer): Buffer {
      var des = crypto.createCipheriv("des-ecb", _ParityKey(key), new Buffer(0));
      des.setAutoPadding(false);

      return Buffer.concat([des.update(clear), des.final()]);
    }

    function _ParityKey(key: Buffer): Buffer {
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



    //#region "MPPE methods"

    /***
     * This is to generate a Session key for MPPE.
     * 
     * See: https://www.ietf.org/rfc/rfc3079.txt Section 2 (esp. 2.4) for use information.
     * 
     * @param initialSessionKey The initial key, derived from the LmPassword or the NtPassword (depending on 40, 56 or 128 bit key).
     * @param currentSessionKey If this is for a new session, then the current key is the same as the initial key.
     * @param lengthOfKey 8 for 40 and 56 bit keys, 16 for 128 bit keys.
     */
    export function GetKey(initialSessionKey: Buffer, currentSessionKey: Buffer, lengthOfKey: number): Buffer {
      var SHApad1 = new Buffer(40);
      var SHApad2 = new Buffer(40);
      SHApad1.fill(0);
      SHApad2.fill(0xf2);

      var sha1 = crypto.createHash("sha1");

      sha1.update(initialSessionKey.slice(0, lengthOfKey));
      sha1.update(SHApad1);
      sha1.update(currentSessionKey.slice(0, lengthOfKey));
      sha1.update(SHApad2);

      return sha1.digest().slice(0, lengthOfKey);
    }

    /**
     * This is to generate an initial key for a 128-bit Session key for MPPE.
     * 
     * See: https://www.ietf.org/rfc/rfc3079.txt Section 2 (esp. 2.4) for use information.
     */
    export function GetStartKey(challenge: Buffer, ntPasswordHashHash: Buffer): Buffer {
      var sha1 = crypto.createHash("sha1");

      sha1.update(ntPasswordHashHash.slice(0, 16));
      sha1.update(ntPasswordHashHash.slice(0, 16));
      sha1.update(challenge.slice(0, 8));

      return sha1.digest().slice(0, 16);
    }


    function _getKey_8(lmPassword: string, currentSessionKey?: Buffer): Buffer {
      var lmPasswordHash = LmPasswordHash(lmPassword);

      return GetKey(lmPasswordHash, currentSessionKey || lmPasswordHash, 8);
    }

    /**
     * Generate a 40-bit session key, as per the specs: https://www.ietf.org/rfc/rfc3079.txt Section 2.1
     */
    export function GetKey_40bit(lmPassword: string, currentSessionKey?: Buffer): Buffer {
      var sessionKey = _getKey_8(lmPassword, currentSessionKey);

      sessionKey[0] = 0xd1;
      sessionKey[1] = 0x26;
      sessionKey[2] = 0x9e;

      return sessionKey;
    }

    /**
     * Generate a 56-bit session key, as per the specs: https://www.ietf.org/rfc/rfc3079.txt Section 2.2
     */
    export function GetKey_56bit(lmPassword: string, currentSessionKey?: Buffer): Buffer {
      var sessionKey = _getKey_8(lmPassword, currentSessionKey);

      sessionKey[0] = 0xd1;

      return sessionKey;
    }

    /**
     * Generate a 128-bit session key, as per the specs: https://www.ietf.org/rfc/rfc3079.txt Section 2.3
     */
    export function GetKey_128bit(challenge: Buffer, ntPassword: string, currentSessionKey?: Buffer): Buffer {
      var ntPasswordHash = NtPasswordHash(ntPassword);
      var ntPasswordHashHash = NtPasswordHash(ntPasswordHash.slice(0, 16));

      var initialSessionKey = GetStartKey(challenge, ntPasswordHashHash);

      var sessionKey = GetKey(initialSessionKey, currentSessionKey || initialSessionKey, 16);

      return sessionKey;
    }

    //#endregion
  }

  export module MSCHAPv2 {
    // See http://tools.ietf.org/html/rfc2759#section-8.7

    export function NtPasswordHash(password: Password): Buffer {
      return MSCHAPv1.NtPasswordHash(password);
    }

    export function GenerateNTResponse(authChallenge: Buffer, peerChallenge: Buffer, username: string, password: Password): Buffer {
      var challenge = MSCHAPv2.ChallengeHash(peerChallenge, authChallenge, username);

      var passwordHash = MSCHAPv1.NtPasswordHash(password);

      return MSCHAPv2.ChallengeResponse(challenge, passwordHash);
    }

    export function ChallengeHash(peerChallenge: Buffer, authChallenge: Buffer, username: string): Buffer {
      var sha1 = crypto.createHash("sha1");

      sha1.update(peerChallenge.slice(0, 16));
      sha1.update(authChallenge.slice(0, 16));
      sha1.update(new Buffer(username, "ascii"));
      
      return sha1.digest().slice(0, 8);
    }

    export function ChallengeResponse(challenge: Buffer, passwordHash: Buffer): Buffer {
      return MSCHAPv1.ChallengeResponse(challenge.slice(0, 8), passwordHash.slice(0, 16));
    }

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
    export function GenerateAuthenticatorResponse(password: string, NT_response: Buffer, peer_challenge: Buffer, authenticator_challenge: Buffer, username: string): string {
      password = password || "";
      username = username || "";

      if (NT_response.length < 24 || peer_challenge.length < 16 || authenticator_challenge.length < 16) return null;

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

      var passwordHash = MSCHAPv1.NtPasswordHash(password);

      var passwordHashHash = MSCHAPv1.NtPasswordHash(passwordHash);

      var sha1 = crypto.createHash("sha1");
      sha1.update(passwordHashHash);
      sha1.update(NT_response.slice(0, 24));
      sha1.update(Magic1);
      var passwordDigest = sha1.digest();


      sha1 = crypto.createHash("sha1");
      sha1.update(peer_challenge.slice(0, 16));
      sha1.update(authenticator_challenge.slice(0, 16));
      sha1.update(username, "ascii");
      var challenge = sha1.digest().slice(0, 8); // Return the first 8 bytes from the SHA1 digest.

      sha1 = crypto.createHash("sha1");
      sha1.update(passwordDigest);
      sha1.update(challenge);
      sha1.update(Magic2);
      var authenticatorResponse: string = sha1.digest("hex");


      return "S=" + authenticatorResponse.toUpperCase();
    }

    
    //#region "MPPE methods"

    export function GetMasterKey(passwordHashHash: Buffer, NT_response: Buffer): Buffer {
      var Magic1 = new Buffer
        ([
          0x54, 0x68, 0x69, 0x73, 0x20, 0x69, 0x73, 0x20, 0x74,
          0x68, 0x65, 0x20, 0x4d, 0x50, 0x50, 0x45, 0x20, 0x4d,
          0x61, 0x73, 0x74, 0x65, 0x72, 0x20, 0x4b, 0x65, 0x79
        ]);

      var sha = crypto.createHash("sha1");

      sha.update(passwordHashHash.slice(0, 16));
      sha.update(NT_response.slice(0, 24));
      sha.update(Magic1);

      return sha.digest().slice(0, 16);
    }

    export function GetAsymmetricStartKey(masterKey: Buffer, keyLength: number, isSend: boolean, isServer: boolean): Buffer {
      var SHApad1 = new Buffer(40);
      var SHApad2 = new Buffer(40);
      SHApad1.fill(0);
      SHApad2.fill(0xf2);

      var Magic2 = new Buffer
        ([
          0x4f, 0x6e, 0x20, 0x74, 0x68, 0x65, 0x20, 0x63, 0x6c, 0x69,
          0x65, 0x6e, 0x74, 0x20, 0x73, 0x69, 0x64, 0x65, 0x2c, 0x20,
          0x74, 0x68, 0x69, 0x73, 0x20, 0x69, 0x73, 0x20, 0x74, 0x68,
          0x65, 0x20, 0x73, 0x65, 0x6e, 0x64, 0x20, 0x6b, 0x65, 0x79,
          0x3b, 0x20, 0x6f, 0x6e, 0x20, 0x74, 0x68, 0x65, 0x20, 0x73,
          0x65, 0x72, 0x76, 0x65, 0x72, 0x20, 0x73, 0x69, 0x64, 0x65,
          0x2c, 0x20, 0x69, 0x74, 0x20, 0x69, 0x73, 0x20, 0x74, 0x68,
          0x65, 0x20, 0x72, 0x65, 0x63, 0x65, 0x69, 0x76, 0x65, 0x20,
          0x6b, 0x65, 0x79, 0x2e
        ]);
      var Magic3 = new Buffer
        ([
          0x4f, 0x6e, 0x20, 0x74, 0x68, 0x65, 0x20, 0x63, 0x6c, 0x69,
          0x65, 0x6e, 0x74, 0x20, 0x73, 0x69, 0x64, 0x65, 0x2c, 0x20,
          0x74, 0x68, 0x69, 0x73, 0x20, 0x69, 0x73, 0x20, 0x74, 0x68,
          0x65, 0x20, 0x72, 0x65, 0x63, 0x65, 0x69, 0x76, 0x65, 0x20,
          0x6b, 0x65, 0x79, 0x3b, 0x20, 0x6f, 0x6e, 0x20, 0x74, 0x68,
          0x65, 0x20, 0x73, 0x65, 0x72, 0x76, 0x65, 0x72, 0x20, 0x73,
          0x69, 0x64, 0x65, 0x2c, 0x20, 0x69, 0x74, 0x20, 0x69, 0x73,
          0x20, 0x74, 0x68, 0x65, 0x20, 0x73, 0x65, 0x6e, 0x64, 0x20,
          0x6b, 0x65, 0x79, 0x2e
        ]);

      var s = isSend == isServer ? Magic3 : Magic2;

      var sha = crypto.createHash("sha1");
      sha.update(masterKey.slice(0, 16));
      sha.update(SHApad1);
      sha.update(s);
      sha.update(SHApad2);

      return sha.digest().slice(0, keyLength);
    }

    export function GetNewKeyFromSHA(startKey: Buffer, sessionKey: Buffer, keyLength: number): Buffer {
      var SHApad1 = new Buffer(40);
      var SHApad2 = new Buffer(40);
      SHApad1.fill(0);
      SHApad2.fill(0xf2);

      var sha1 = crypto.createHash("sha1");

      sha1.update(startKey.slice(0, keyLength));
      sha1.update(SHApad1);
      sha1.update(sessionKey.slice(0, keyLength));
      sha1.update(SHApad2);

      return sha1.digest().slice(0, keyLength);
    }




    export interface SessionKeys {
      SendSessionKey: Buffer;
      RecvSessionKey: Buffer;
    }

    function _getSessionKeys(password: Password, NT_response: Buffer, keyLength: number): SessionKeys {
      var passwordHash = NtPasswordHash(password);
      var passwordHashHash = NtPasswordHash(passwordHash.slice(0, 16));
      
      var masterKey = GetMasterKey(passwordHashHash, NT_response);

      var masterSendKey = GetAsymmetricStartKey(masterKey, keyLength, true, true);
      var masterRecvKey = GetAsymmetricStartKey(masterKey, keyLength, false, true);

      var sessionKeys: SessionKeys = {
        SendSessionKey: masterSendKey,
        RecvSessionKey: masterRecvKey,
      };

      return sessionKeys;
    }

    /**
     * Generate 64-bit send and receive start session keys for use in 40-bit and 56-bit session keys, as per the specs: https://www.ietf.org/rfc/rfc3079.txt Section 3.2
     * 
     * If prevSessionKey parameter is not given then it is assumed that the session has just started without a previous session key.
     */
    export function GetSessionKeys_64bit(password: Password, NT_response: Buffer): SessionKeys {
      var sessionKeys = _getSessionKeys(password, NT_response, 8);

      return sessionKeys;
    }

    /**
     * Generate 128-bit send and receive start session keys, as per the specs: https://www.ietf.org/rfc/rfc3079.txt Section 3.3
     * 
     * If prevSessionKey parameter is not given then it is assumed that the session has just started without a previous session key.
     */
    export function GetSessionKeys_128bit(password: Password, NT_response: Buffer): SessionKeys {
      return _getSessionKeys(password, NT_response, 16);
    }

    //#endregion
  }
}


export = chap;