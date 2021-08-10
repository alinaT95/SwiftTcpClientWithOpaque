//
//  AuthEnc.swift
//  GoTcpClientWithOpaque
//
//  Created by Alina Alinovna on 09.08.2021.
//

import Foundation

class AuthEnc{
    func encrypt(_ secEnvelope: Data, _ clearEnvelope: Data, _ nonce: Data, _ keyEnc: Data, _ keyMac: Data) throws -> Data {
        //check lens
        let ciphertext = xorTransform(secEnvelope, keyEnc)
        var e = Data(_ : nonce.bytes)
        e.append(ciphertext)
        e.append(clearEnvelope)
        let mac = HmacHelper().computeHmac(key: keyMac, data: e)
        var envelopeU = Data(_: e.bytes)
        envelopeU.append(mac)
        return envelopeU
    }
    
    func xorTransform(_ text: Data, _ key: Data) -> Data {
        //check lens
        var xored = Data(_ : [])
        for index in 0...text.count-1 {
            xored.append(text[index] ^ key[index])
        }
        return xored
    }
    
    func decrypt(_ envelopeU: Data, _ keyEnc: Data, _ keyMac: Data) throws -> Data {
        let res = HmacHelper().verifyHmac(key: keyMac, data: envelopeU[0..<envelopeU.count-32], macToVerify: envelopeU[envelopeU.count-32..<envelopeU.count])
        if (!res) {
            throw "Mac is corrupted."
        }
        let ciphertext = envelopeU[32..<64]
        let plaintext = xorTransform(ciphertext, keyEnc)
        return plaintext
    }
}
