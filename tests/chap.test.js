var assert = require('assert');
var chap = require("../lib/chap");
describe("CHAP, MS-CHAPv1 and MS-CHAPv2 library for Node.js", function () {
    describe("CHAP methods", function () {
        it("ChallengeResponse method", function () {
            var chapID = new Buffer([1]);
            var challenge = new Buffer("c49c74a7d3f8fa006ea57190f28ab34c", "hex");
            var password = "MyPw";
            assert.equal(chap.CHAP.ChallengeResponse(chapID, password, challenge).toString("base64"), "giwrxlSx0Kjb6oc3+73eDg==");
        });
    });
    describe("MS-CHAPv1", function () {
        describe("Authentication", function () {
            it("LmPasswordHash method", function () {
                var password = "clientPass";
                assert.equal(chap.MSCHAPv1.LmPasswordHash(password).toString("hex"), "76a152936096d7830e2390227404afd2");
            });
            it("NtPasswordHash method", function () {
                var password = "clientPass";
                assert.equal(chap.MSCHAPv1.NtPasswordHash(password).toString("hex"), "44ebba8d5312b8d611474411f56989ae");
            });
            it("LmChallengeResponse method", function () {
                var challenge = new Buffer("bd332a369b6d33e7", "hex");
                var password = "MyPw";
                assert.equal(chap.MSCHAPv1.LmChallengeResponse(challenge, password).toString("base64"), "lrdNlCKhor03G7XsxVsNlZeh7vMaKe53");
            });
            it("NtChallengeResponse method", function () {
                var challenge = new Buffer("102db5df085d3041", "hex");
                var password = "MyPw";
                assert.equal(chap.MSCHAPv1.NtChallengeResponse(challenge, password).toString("base64"), "Tp08j5z9OF1b9NMkZ5GVbKTDUatAmj1h");
            });
        });
        describe("MPPE", function () {
            it("GetKey method generating key 8 octets long", function () {
                var password = "clientPass";
                var passwordHash = chap.MSCHAPv1.LmPasswordHash(password);
                var sessionKey = new Buffer(passwordHash.length);
                passwordHash.copy(sessionKey);
                assert.equal(chap.MSCHAPv1.GetKey(passwordHash, sessionKey, 8).toString("hex"), "d80801538cec4a08");
            });
            it("GetKey method generating key 16 octets long", function () {
                var initialSessionKey = new Buffer("a8947850cfc0acc1d1789fb62ddcddb0", "hex");
                assert.equal(chap.MSCHAPv1.GetKey(initialSessionKey, initialSessionKey, 16).toString("hex"), "59d159bc09f76f1da2a86a28ffec0b1e");
            });
            it("GetStartKey method", function () {
                var challenge = new Buffer("102db5df085d3041", "hex");
                var passwordHashHash = new Buffer("41c00c584bd2d91c4017a2a12fa59f3f", "hex");
                assert.equal(chap.MSCHAPv1.GetStartKey(challenge, passwordHashHash).toString("hex"), "a8947850cfc0acc1d1789fb62ddcddb0");
            });
            it("40-bit Key Derivation without current key", function () {
                var password = "clientPass";
                assert.equal(chap.MSCHAPv1.GetKey_40bit(password).toString("hex"), "d1269e538cec4a08");
            });
            it("56-bit Key Derivation without current key", function () {
                var password = "clientPass";
                assert.equal(chap.MSCHAPv1.GetKey_56bit(password).toString("hex"), "d10801538cec4a08");
            });
            it("128-bit Key Derivation without current key", function () {
                var challenge = new Buffer("102db5df085d3041", "hex");
                var password = "clientPass";
                assert.equal(chap.MSCHAPv1.GetKey_128bit(challenge, password).toString("hex"), "59d159bc09f76f1da2a86a28ffec0b1e");
            });
        });
    });
    describe("MS-CHAPv2", function () {
        describe("Authentication", function () {
            var username = "User";
            var password = "clientPass";
            var ntResponse = new Buffer("82309ECD8D708B5EA08FAA3981CD83544233114A3D85D6DF", "hex");
            var peerChallenge = new Buffer("21402324255E262A28295F2B3A337C7E", "hex");
            var authChallenge = new Buffer("5B5D7C7D7B3F2F3E3C2C602132262628", "hex");
            it("NtPasswordHash method", function () {
                var password = "clientPass";
                assert.equal(chap.MSCHAPv2.NtPasswordHash(password).toString("base64"), chap.MSCHAPv1.NtPasswordHash(password).toString("base64"));
            });
            it("GenerateNTResponse method", function () {
                assert.equal(chap.MSCHAPv2.GenerateNTResponse(authChallenge, peerChallenge, username, password).toString("base64"), ntResponse.toString("base64"));
            });
            it("GenerateAuthenticatorResponse method", function () {
                assert.equal(chap.MSCHAPv2.GenerateAuthenticatorResponse(password, ntResponse, peerChallenge, authChallenge, username), "S=407A5589115FD0D6209F510FE9C04566932CDA56");
            });
        });
        describe("MPPE", function () {
            it("GetMasterKey method", function () {
                var passwordHashHash = new Buffer("41C00C584BD2D91C4017A2A12FA59F3F", "hex");
                var NT_response = new Buffer("82309ECD8D708B5EA08FAA3981CD83544233114A3D85D6DF", "hex");
                assert.equal(chap.MSCHAPv2.GetMasterKey(passwordHashHash, NT_response).toString("hex"), "fdece3717a8c838cb388e527ae3cdd31");
            });
            it("GetNewKeyFromSHA method 8 octets long", function () {
                var SendStartKey40 = new Buffer("8B7CDC149B993A1B", "hex");
                assert.equal(chap.MSCHAPv2.GetNewKeyFromSHA(SendStartKey40, SendStartKey40, 8).toString("hex"), "965c00c49fa62e3e");
            });
            it("GetAsymmetricStartKey method 8 octets long", function () {
                var masterKey = new Buffer("fdece3717a8c838cb388e527ae3cdd31", "hex");
                assert.equal(chap.MSCHAPv2.GetAsymmetricStartKey(masterKey, 8, true, true).toString("hex"), "8b7cdc149b993a1b");
            });
            it("GetNewKeyFromSHA method 16 octets long", function () {
                var SendStartKey128 = new Buffer("8B7CDC149B993A1BA118CB153F56DCCB", "hex");
                assert.equal(chap.MSCHAPv2.GetNewKeyFromSHA(SendStartKey128, SendStartKey128, 16).toString("hex"), "405cb2247a7956e6e211007ae27b22d4");
            });
            it("GetAsymmetricStartKey method 16 octets long", function () {
                var masterKey = new Buffer("fdece3717a8c838cb388e527ae3cdd31", "hex");
                assert.equal(chap.MSCHAPv2.GetAsymmetricStartKey(masterKey, 16, true, true).toString("hex"), "8b7cdc149b993a1ba118cb153f56dccb");
            });
            it("64-bit session keys (for use in 40-bit and 56-bit session keys)", function () {
                var password = "clientPass";
                var NT_response = new Buffer("82309ECD8D708B5EA08FAA3981CD83544233114A3D85D6DF", "hex");
                var keys = chap.MSCHAPv2.GetSessionKeys_64bit(password, NT_response);
                assert.equal(keys.SendSessionKey.toString("hex"), "8b7cdc149b993a1b");
                assert.equal(keys.RecvSessionKey.toString("hex"), "d5f0e9521e3ea958");
            });
            it("128-bit session keys", function () {
                var password = "clientPass";
                var NT_response = new Buffer("82309ECD8D708B5EA08FAA3981CD83544233114A3D85D6DF", "hex");
                var keys = chap.MSCHAPv2.GetSessionKeys_128bit(password, NT_response);
                assert.equal(keys.SendSessionKey.toString("hex"), "8b7cdc149b993a1ba118cb153f56dccb");
                assert.equal(keys.RecvSessionKey.toString("hex"), "d5f0e9521e3ea9589645e86051c82226");
            });
        });
    });
});
//# sourceMappingURL=chap.test.js.map