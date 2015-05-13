# node-chap - A CHAP library for Node.js

node-chap creates CHAP, MS-CHAPv1 and MS-CHAPv2 challenge-responses, which can be used as an authenticator or to verify authentication against a known password.

## Classes

### CHAP

#### ChallengeResponse(id: Buffer, password: string, challenge: Buffer)

Returns a Buffer 16 octets long.

### MSCHAPv1

#### LmPasswordHash(password: string)

This will return a buffer containing the hash of the LM Password.

#### NtPasswordHash(password: string|Buffer)

This will return a buffer contain the hash of the given NT Password/PasswordHash.

#### LmChallengeResponse(challenge: Buffer, password: string)

This will return a buffer 24 octets long.

#### NtChallengeResponse(challenge: Buffer, password: string)

This will return a buffer 24 octets long.

#### ChallengeResponse(challenge: Buffer, passwordHash: Buffer)

This function generates the challenge response for both LmChallengeResponse and NtChallengeResponse. The only difference between the two is how the passwordHash is created.

This will return a buffer 24 octets long.

#### GetKey_40bit(lmPassword: string, currentSessionKey?: Buffer)

This will return a new 40-bit current session key given the authentication credentials. If currentSessionKey is not provided, then it is assumed that it is a new session and will use the generated initial session key as current.

#### GetKey_56bit(lmPassword: string, currentSessionKey?: Buffer)

This will return a new 56-bit current session key given the authentication credentials. If currentSessionKey is not provided, then it is assumed that it is a new session and will use the generated initial session key as current.

#### GetKey_128bit(challenge: Buffer, ntPassword: string, currentSessionKey?: Buffer)

This will return a new 128-bit current session key given the authentication credentials. If currentSessionKey is not provided, then it is assumed that it is a new session and will use the generated initial session key as current.

#### GetKey(initialSessionKey: Buffer, currentSessionKey: Buffer, lengthOfKey: number)

This function returns a buffer of the new current session key for MPPE. If it is a new session, then the initial session key and current session key are both the same. otherwise provide the previous current session key.

For convenience, the methods GetKey_40bit, GetKey_56bit and GetKey_128bit methods have been implemented to generate the correct initial session key given the MS-CHAPv1 authentication data.

#### GetStartKey(challenge: Buffer, ntPasswordHashHash: Buffer)

This will return a buffer of the initial session key for a 128-bit session key.

For convenience, the methods GetKey_40bit, GetKey_56bit and GetKey_128bit have been implemented to generate the correct initial session key given the MS-CHAPv1 authentication data.


### MSCHAPv2

#### NtPasswordHash(password: string|Buffer)

This will return a buffer contain the hash of the given NT Password/PasswordHash.

#### GenerateAuthenticatorResponse(password: string, NT_response: Buffer, peer_challenge: Buffer, authenticator_challenge: Buffer, username: string)

This will generate an authenticator response, returning a 42 character string, starting with "S=" followed by 40 hexadecimal characters, in upper case.

#### GetSessionKeys_64bit(password: Password, NT_response: Buffer)

Return a `SessionKeys` object with the 40-bit/56-bit start send/receive keys.

#### GetSessionKeys_128bit(password: Password, NT_response: Buffer)

Return a `SessionKeys` object with the 128-bit start send/receive keys.

#### SessionKeys

This is an interface describing an object that looks like this:

```
{
    SendSessionKey: Buffer,
    RecvSessionKey: Buffer
}
````

#### GetMasterKey(passwordHashHash: Buffer, NT_response: Buffer)

This returns a buffer of the master key from the given passwordHashHash and NTResponse buffers.

For convenience, the methods GetSessionKeys_40bit, GetSessionKeys_56bit and GetSessionKeys_128bit have been implemented to generate the correct session keys given the MS-CHAPv2 authentication data.

#### GetAsymmetricStartKey(masterKey: Buffer, keyLength: number, isSend: boolean, isServer: boolean)

This returns a buffer of either a send or receive key generated from the given master key and desired key length.

For convenience, the methods GetSessionKeys_40bit, GetSessionKeys_56bit and GetSessionKeys_128bit have been implemented to generate the correct session keys given the MS-CHAPv2 authentication data.

#### GetNewKeyFromSHA(startKey: Buffer, sessionKey: Buffer, keyLength: number)

This returns a buffer of the final send/receive key given. If it is a new session, startKey should be given as the sessionKey argument, otherwise the previous session key should be given.

For convenience, the methods GetSessionKeys_40bit, GetSessionKeys_56bit and GetSessionKeys_128bit have been implemented to generate the correct session keys given the MS-CHAPv2 authentication data.

## Notes

This project is still very young, although I have kept to relevant standards, there may be bugs about.

Contribution is welcome, if someone wants to contribute tests that would be helpful.