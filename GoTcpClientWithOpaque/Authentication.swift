//
//  Authentication.swift
//  GoTcpClientWithOpaque
//
//  Created by Alina Alinovna on 09.08.2021.
//

import Foundation
import EllipticCurveKit
import CryptoSwift


struct AuthClientSession {
    let userName: String
    let a: AffinePoint<Secp256r1>
    let r: Number
    let password: String
    let nonceU: Data
    let ephemeralKeyPairU: KeyPair<Secp256r1>
    init(_ userName: String, _ a: AffinePoint<Secp256r1>, _ r: Number, _ password: String, _ nonceU: Data, _ ephemeralKeyPairU: KeyPair<Secp256r1>){
        self.userName = userName
        self.a = a
        self.r = r
        self.password = password
        self.nonceU = nonceU
        self.ephemeralKeyPairU = ephemeralKeyPairU
    }
    
}

struct AuthMsg1 {
    let userName: String
    let a: AffinePoint<Secp256r1>
    let ePubU: PublicKey<Secp256r1>
    let nonceU: Data
    init(_ userName: String, _ a: AffinePoint<Secp256r1>, _ ePubU: PublicKey<Secp256r1>, _ nonceU: Data){
        self.userName = userName
        self.a = a
        self.ePubU = ePubU
        self.nonceU = nonceU
    }
}


struct AuthMsg2ForParsing : Codable {
    var B: Point
    var EphemeralPubS: Point
    var NonceS: String
    var EnvU: String
    var Mac1: String
}
struct AuthMsg2 {
    let b: AffinePoint<Secp256r1>
    let envU: Data
    let nonceS: Data
    let ePubS: PublicKey<Secp256r1>
    let mac1: Data
    init(_ b: AffinePoint<Secp256r1>, _ envU: Data, _ nonceS: Data, _ ePubS: PublicKey<Secp256r1>, _ mac1: Data){
        self.b = b
        self.envU = envU
        self.nonceS = nonceS
        self.ePubS = ePubS
        self.mac1 = mac1
    }
}

struct AuthMsg3 {
    let mac2: Data
    init(_ mac2: Data){
        self.mac2 = mac2
    }
}

struct AuthInitResult {
    let authClientSession: AuthClientSession
    let authMsg1: AuthMsg1
    init(_ authClientSession: AuthClientSession, _ authMsg1: AuthMsg1) {
        self.authMsg1 = authMsg1
        self.authClientSession = authClientSession
    }
}

class Authentication {
    let crypto = Crypto()
    
    func createAuthMsg1JSon(_ msg1: AuthMsg1) throws -> String {
        var data: [String : Any] = [:]
        data["UserName"] = msg1.userName
        data["A"] = ["x" : msg1.a.x.asDecimalString(), "y" : msg1.a.y.asDecimalString()]
        data["NonceU"] = msg1.nonceU.hexEncodedString()
        data["EphemeralPubU"] = ["x" : msg1.ePubU.point.x.asDecimalString(), "y" : msg1.ePubU.point.y.asDecimalString()]
        let jsonData = try JSONSerialization.data(withJSONObject: data)
        let jsonString = String(data: jsonData, encoding: .utf8)!
        print(jsonString)
        return jsonString
    }
    
    // AuthInit initiates the authentication protocol. It's run on the client and,
    // on success, returns a nil error, a client auth session, and an AuthMsg1
    // struct. The AuthMsg1 struct should be sent to the server.
    func authInit(_ username: String, _ password: String) throws -> AuthInitResult {
        print("Client started computations for authInit...")
        let dhOprf1Res: DhOprf1Result = crypto.dhOprf1(Data(_ : password.bytes))
        let ephemeralKeyPairU = AnyKeyGenerator<Secp256r1>.generateNewKeyPair()
        let nonceU = try ByteArrayAndHexHelper().randomData(Crypto.NONCE_LEN)
        let msg1 = AuthMsg1(username, dhOprf1Res.a, ephemeralKeyPairU.publicKey, nonceU)
        let session = AuthClientSession(username, dhOprf1Res.a, dhOprf1Res.r, password, nonceU, ephemeralKeyPairU)
        return AuthInitResult(session, msg1)
    }
    
    // Auth2 is the processing done by the client when it receives an AuthMsg2
    // struct. On success a nil error is returned together with a secret byte slice
    // and an AuthMsg3 struct. The AuthMsg3 struct should be sent to the server. On
    // a successful completion of the protocol the secret will be shared between the
    // client and the server. Auth2 is the final round in the authentication
    // protocol for the client.
    func auth2(session: AuthClientSession, msg2:  AuthMsg2) throws -> AuthMsg3 {
        let randomizedPassword = try crypto.dhOprf3(Data(_ : session.password.bytes), msg2.b, r: session.r)
        print("randomizedPassword from authentication flow = " + randomizedPassword.hexEncodedString())
        let nonce = Data(_ : msg2.envU[0..<Crypto.NONCE_LEN])
        let commonKeys = try crypto.produceKeysToEncryptEnvelope(nonce, randomizedPassword)
        let keyEnc: Data = commonKeys.keyEnc
        let keyMac: Data = commonKeys.keyMac
        let skUBytes = try AuthEnc().decrypt(msg2.envU, keyEnc, keyMac)
        let skU = skUBytes.toNumber()
        print("skUBytes = " + skUBytes.hexEncodedString())
        let pubSX = msg2.envU[64..<96]
        let pubSY = msg2.envU[96..<128]
        let pubS = AffinePoint<Secp256r1>(
            x: pubSX.toNumber(),
            y: pubSY.toNumber()
        )
        
      
        var XCrypt = Data(_ : session.a.x.asTrimmedData())
        XCrypt.append(session.a.y.asTrimmedData())
        XCrypt.append(session.nonceU)
        XCrypt.append(session.userName.toData())
        XCrypt.append(session.ephemeralKeyPairU.publicKey.x.asTrimmedData())
        XCrypt.append(session.ephemeralKeyPairU.publicKey.y.asTrimmedData())
        XCrypt.append(msg2.b.x.asTrimmedData())
        XCrypt.append(msg2.b.y.asTrimmedData())
        XCrypt.append(msg2.envU)
        XCrypt.append(msg2.nonceS)
        XCrypt.append(msg2.ePubS.x.asTrimmedData())
        XCrypt.append(msg2.ePubS.y.asTrimmedData())
        
        var info = Data(_: "HMQVKeys".bytes)
        info.append(session.nonceU)
        //info.append(msg2.nonceS)
       // info.append(session.userName.toData())
        print("session.nonceU = " + session.nonceU.hexEncodedString())
        print("XCrypt = " + XCrypt.hexEncodedString())
        print("info = " + info.hexEncodedString())
        
        
        var Q1Input = Data(_ : session.ephemeralKeyPairU.publicKey.x.asTrimmedData())
        Q1Input.append(session.ephemeralKeyPairU.publicKey.y.asTrimmedData())
        Q1Input.append("user".toData())
        Q1Input.append(info)
        
        var Q2Input = Data(_ : msg2.ePubS.x.asTrimmedData())
        Q2Input.append(msg2.ePubS.y.asTrimmedData())
        Q2Input.append("srvr".toData())
        Q2Input.append(info)
        
        print("Q1Input.hash() = " + Q1Input.hash().hexEncodedString())
        print("Q2Input.hash() = " + Q2Input.hash().hexEncodedString())
        
        let Q1 = Q1Input.hash().toNumber()
        let Q2 = Q2Input.hash().toNumber()
        
        
        
        let exp = Q2 * skU + session.ephemeralKeyPairU.privateKey.number
        let pubSQ1: AffinePoint<Secp256r1> = pubS * Q1
        let ikmU = AffinePoint<Secp256r1>.addition(msg2.ePubS.point, pubSQ1)!
        
        print("ikmU.x = " + ikmU.x.asDecimalString())
        print("ikmU.y = " + ikmU.y.asDecimalString())
        
        var secret = Data(_ : ikmU.x.asTrimmedData())
        secret.append(ikmU.y.asTrimmedData())
        
        let hkdf = try HKDF(password: Array(secret), salt: Array(Data(count: 32)), info: Array(info), keyLength: 96, variant: .sha256)
        let keyStream = try hkdf.calculate()
        
        let keyStreamData = keyStream.asData
        let SK: Data = keyStreamData[0..<32]
        print("SK = " + SK.hexEncodedString())
        
        let Km2: Data = keyStreamData[32..<64]
        print("Km2 = " + Km2.hexEncodedString())
        let Km3: Data = keyStreamData[64..<96]
        print("Km3 = " + Km3.hexEncodedString())
        let res = HmacHelper().verifyHmac(key: Km3, data: XCrypt, macToVerify: msg2.mac1)
        if (!res) {
            throw "Mac is corrupted!"
        }
        var XCrypt2 = "Finish".toData()
        XCrypt2.append(XCrypt)
        let mac2 = HmacHelper().computeHmac(key: Km3, data: XCrypt2)
        return AuthMsg3(mac2)
//        let mac2 = Data(_ : [])
        
    }
    
}



