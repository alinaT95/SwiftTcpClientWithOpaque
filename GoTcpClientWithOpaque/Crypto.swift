//
//  Crypto.swift
//  GoTcpClientWithOpaque
//
//  Created by Alina Alinovna on 09.08.2021.
//

import Foundation
import EllipticCurveKit
import CryptoSwift

class DhOprf1Result {
    let r: Number
    let a: AffinePoint<Secp256r1>
    
    init(_ r: Number, _ a: AffinePoint<Secp256r1>) {
        self.a = a
        self.r = r
    }
    
}

class CommonSecretKeys {
    let keyEnc: Data
    let keyMac: Data
    init(_ keyEnc: Data, _ keyMac: Data){
        self.keyMac = keyMac
        self.keyEnc = keyEnc
    }
}

class Crypto {
    func hashToECDummy(_ data: Data) -> AffinePoint<Secp256r1> {
        let G = Secp256r1.G
        print(G.x)
        print(G.y)
        let hash = data.hash() //sha256
        print(data.hexEncodedString())
        print(hash.hexEncodedString())
        let res: AffinePoint<Secp256r1> = G * hash.toNumber()
        return res
    }
    
    //see https://www.normalesup.org/~tibouchi/papers/phd-slides.pdf
    /*func hashToECIterative(data: Data) -> AffinePoint<Secp256r1> {
        
    }*/
    
   
    // dhOprf1 is the first step in computing DF-OPRF. dhOprf1 is executed on the
    // client.
    //
    // From the I-D:
    //     Protocol for computing DH-OPRF, U with input x and S with input k:
    //     U: choose random r in [0..q-1], send a=H'(x)^r to S
    //
    // x is typically the password.
    func dhOprf1(_ x: Data) -> DhOprf1Result {
        let keyPair = AnyKeyGenerator<Secp256r1>.generateNewKeyPair()
        let r = keyPair.privateKey.number
        let hashedXToEC = hashToECDummy(x)
        let a = hashedXToEC * r
        return DhOprf1Result(r, a)
    }
    
    func dhOprf3(_ x: Data, _ b: AffinePoint<Secp256r1>, r: Number) throws -> Data {
        if (!b.isOnCurve()) {
            throw "B is not on EC!"
        }
        //check smallgroup
        let rInv = r.inverse(Secp256r1.order)
        let z = b * rInv!
        var dataToHash = Data(_: [])
        dataToHash.append(x)
        dataToHash.append(z.x.asTrimmedData())
        dataToHash.append(z.y.asTrimmedData())
        return dataToHash.hash()
    }
    
    func produceSessionKeys(_ nonce: Data, _ randomizedPassword: Data) throws -> CommonSecretKeys {
        var info = Data(_ : nonce.bytes)
        info.append(contentsOf: "EnvU".bytes)
        let hkdf = try HKDF(password: Array(randomizedPassword), salt: nil, info: Array(info), keyLength: 96, variant: .sha256)
        let keyStream = try hkdf.calculate()
        let keyStreamData = keyStream.asData
        let keyEnc: Data = keyStreamData[0..<32]
        let keyMac: Data = keyStreamData[32..<64]
        return CommonSecretKeys(keyEnc, keyMac)
    }
}

extension Data {
    func toNumber() -> Number {
        return Number(data: self)
    }
}
