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
    describe("MS-CHAPv1 methods", function () {
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
    describe("MS-CHAPv2 methods", function () {
        it("GenerateAuthenticatorResponse method", function () {
            var username = "User";
            var password = "clientPass";
            var ntResponse = new Buffer("82309ECD8D708B5EA08FAA3981CD83544233114A3D85D6DF", "hex");
            var peerChallenge = new Buffer("21402324255E262A28295F2B3A337C7E", "hex");
            var authChallenge = new Buffer("5B5D7C7D7B3F2F3E3C2C602132262628", "hex");
            assert.equal(chap.MSCHAPv2.GenerateAuthenticatorResponse(password, ntResponse, peerChallenge, authChallenge, username), "S=407A5589115FD0D6209F510FE9C04566932CDA56");
        });
    });
});
//# sourceMappingURL=chap.test.js.map