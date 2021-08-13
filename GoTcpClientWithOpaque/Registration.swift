//
//  Registration.swift
//  GoTcpClientWithOpaque
//
//  Created by Alina Alinovna on 09.08.2021.
//

import Foundation
import EllipticCurveKit
import CryptoSwift

struct PwRegMsg1 {
    let userName: String
    let a: AffinePoint<Secp256r1>
    init(_ userName: String, _ a: AffinePoint<Secp256r1>){
        self.userName = userName
        self.a = a
    }
}

struct PwRegMsg2ForParsing : Codable {
    var B: Point
    var PubS: Point
}

struct PwRegMsg2 {
    let B: AffinePoint<Secp256r1>
    let PubS: PublicKey<Secp256r1>
    init(_ b: AffinePoint<Secp256r1>, _ pubS: PublicKey<Secp256r1>){
        self.PubS = pubS
        self.B = b
    }
}

struct PwRegMsg3 {
    let EnvU: Data
    let PubU: PublicKey<Secp256r1>
    init(_ envU: Data, _ pubU: PublicKey<Secp256r1>){
        self.EnvU = envU
        self.PubU = pubU
    }
}

struct PwRegClientSession {
    let userName: String
    let a: AffinePoint<Secp256r1>
    let r: Number
    let password: String
    init(_ userName: String, _ a: AffinePoint<Secp256r1>, _ r: Number, _ password: String){
        self.userName = userName
        self.a = a
        self.r = r
        self.password = password
    }
}

struct RegInitResult {
    let pwRegClientSession: PwRegClientSession
    let pwRegMsg1:PwRegMsg1
    init(_ pwRegClientSession: PwRegClientSession, _ pwRegMsg1:PwRegMsg1) {
        self.pwRegMsg1 = pwRegMsg1
        self.pwRegClientSession = pwRegClientSession
    }
}

class Registration {
    
    let crypto = Crypto()
    
    func createPwRegMsg1JSon(_ msg1: PwRegMsg1) throws -> String {
        var data: [String : Any] = [:]
        data["userName"] = msg1.userName
        data["a"] = ["x" : msg1.a.x.asDecimalString(), "y" : msg1.a.y.asDecimalString()]
        let jsonData = try JSONSerialization.data(withJSONObject: data)
        let jsonString = String(data: jsonData, encoding: .utf8)!
        print("Prepared data for Server #1:")
        print(jsonString)
        return jsonString
    }
    
    func createPwRegMsg3JSon(_ msg3: PwRegMsg3) throws -> String {
        var data: [String : Any] = [:]
        data["EnvU"] = msg3.EnvU.asData.hexEncodedString()
        data["PubU"] = ["x" : msg3.PubU.x.asDecimalString(), "y" : msg3.PubU.y.asDecimalString()]
        let jsonData = try JSONSerialization.data(withJSONObject: data)
        let jsonString = String(data: jsonData, encoding: .utf8)!
        print(jsonString)
        return jsonString
    }
    
    // regInit initiates the password registration protocol. It's invoked by the
    // client. The bits argument specifies the number of bits that should be used in
    // the client-specific RSA key.
    //
    // On success a nil error is returned together with a client session and a
    // PwRegMsg1 struct. The PwRegMsg1 struct should be sent to the server. A
    // precondition of the password registration protocol is that it's running over
    // an authenticated connection.
    func regInit(_ username: String, _ password: String) -> RegInitResult {
        print("Client started computations for regInit...")
        let dhOprf1Res: DhOprf1Result = crypto.dhOprf1(Data(_ : password.bytes))
        let session = PwRegClientSession(username, dhOprf1Res.a, dhOprf1Res.r, password)
        let msg1 = PwRegMsg1(username, dhOprf1Res.a)
        return RegInitResult(session, msg1)
    }
    
    // reg2 is invoked on the client when it has received a PwRegMsg2 struct from
    // the server.
    // From the I-D:
    //   U: upon receiving values b and v, set the PRF output to H(x, bˆ{-r})
    //   U generates an "envelope" EnvU defined as EnvU = AuthEnc(RwdU; PrivU, PubU,
    //   PubS, vU)
    func reg2(session: PwRegClientSession, msg2: PwRegMsg2) throws -> PwRegMsg3 {
        let randomizedPassword = try crypto.dhOprf3(Data(_ : session.password.bytes), msg2.B, r: session.r)
        print("randomizedPassword from registration flow = " + randomizedPassword.hexEncodedString())
        let keyPairU = AnyKeyGenerator<Secp256r1>.generateNewKeyPair()
        let nonce = try ByteArrayAndHexHelper().randomData(Crypto.NONCE_LEN)
        print("Nonce = " + nonce.hexEncodedString())
        print("privateKeyU = " + keyPairU.privateKey.asData.hexEncodedString())
        print("privateKeyU length = " +  String(keyPairU.privateKey.asData.count))
        let envKeys = try crypto.produceKeysToEncryptEnvelope(nonce, randomizedPassword)
        let keyEnc: Data = envKeys.keyEnc
        let keyMac: Data = envKeys.keyMac
        let secEnvelope: Data = keyPairU.privateKey.asData
        var clearEnvelope = Data(_ : msg2.PubS.point.x.asTrimmedData())
      //  print(msg2.PubS.point.x.asTrimmedData().count)
       // print(msg2.PubS.point.x.asData.count)
        clearEnvelope.append(msg2.PubS.point.y.asTrimmedData())
      //  print(msg2.PubS.point.y.asTrimmedData().count)
        clearEnvelope.append(keyPairU.publicKey.point.x.asTrimmedData())
       // print(keyPairU.publicKey.point.x.asTrimmedData().count)
        clearEnvelope.append(keyPairU.publicKey.point.y.asTrimmedData())
      //  print(keyPairU.publicKey.point.y.asTrimmedData().count)
        clearEnvelope.append(contentsOf: session.userName.bytes)
        let envelopeU = try AuthEnc().encrypt(secEnvelope, clearEnvelope, nonce, keyEnc, keyMac)
        return PwRegMsg3(envelopeU, keyPairU.publicKey)
    }
    
}

