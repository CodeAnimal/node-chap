# node-chap - A CHAP library for Node.js

node-chap creates CHAP, MS-CHAPv1 and MS-CHAPv2 challenge-responses, which can be used as an authenticator or to verify authentication against a known password.

## Classes

### CHAP

#### ChallengeResponse(id: Buffer, password: string, challenge: Buffer)

Returns a Buffer 16 octets long.

### MSCHAPv1

#### LmChallengeResponse(challenge: Buffer, password: string)

This will return a buffer 24 octets long.

#### NtChallengeResponse(challenge: Buffer, password: string)

This will return a buffer 24 octets long.

#### ChallengeResponse(challenge: Buffer, passwordHash: Buffer)

This function generates the challenge response for both LmChallengeResponse and NtChallengeResponse. The only difference between the two is how the passwordHash is created.

This will return a buffer 24 octets long.


### MSCHAPv2

#### GenerateAuthenticatorResponse(password: string, NT_response: Buffer, peer_challenge: Buffer, authenticator_challenge: Buffer, username: string)

This will generate an authenticator response, returning a 42 character string, starting with "S=" followed by 40 hexadecimal characters, in upper case.

## Notes

This project is still very young, although I have kept to relevant standards, there may be bugs about.

Contribution is welcome, if someone wants to contribute tests that would be helpful.