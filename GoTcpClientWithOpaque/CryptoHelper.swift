//
//  Crypto.swift
//  GoTcpClientWithOpaque
//
//  Created by Alina Alinovna on 09.08.2021.
//

import Foundation

import CommonCrypto
import CryptoKit

extension Data {
  func authenticationCode(secretKey: Data) -> Data {
    let hashBytes = UnsafeMutablePointer<UInt8>.allocate(capacity:Int(CC_SHA256_DIGEST_LENGTH))
    defer { hashBytes.deallocate() }
    withUnsafeBytes { (bytes) -> Void in
      secretKey.withUnsafeBytes { (secretKeyBytes) -> Void in
        CCHmac(CCHmacAlgorithm(kCCHmacAlgSHA256), secretKeyBytes, secretKey.count, bytes, count, hashBytes)
      }
    }
    return Data(bytes: hashBytes, count: Int(CC_SHA256_DIGEST_LENGTH))
  }
  
  func hash() -> Data {
    let hashBytes = UnsafeMutablePointer<UInt8>.allocate(capacity: Int(CC_SHA256_DIGEST_LENGTH))
    defer { hashBytes.deallocate() }
    withUnsafeBytes { (buffer) -> Void in
      CC_SHA256(buffer.baseAddress!, CC_LONG(buffer.count), hashBytes)
    }
    return Data(bytes: hashBytes, count: Int(CC_SHA256_DIGEST_LENGTH))
  }
  
}

@available(iOS 13.0, *)
class HmacHelper {
    static var hmacHelper : HmacHelper?
    static func getInstance() -> HmacHelper {
        if (hmacHelper == nil) {
            hmacHelper = HmacHelper()
        }
        return hmacHelper!
    }
    
    func computeHmac(key : Data, data : Data) -> Data {
        let key256 = SymmetricKey(data: key)
        let sha512MAC = HMAC<SHA256>.authenticationCode(
          for: data, using: key256)
        print(String(describing: sha512MAC))
        let authenticationCodeData = Data(sha512MAC)
        print(authenticationCodeData)
        return authenticationCodeData
    }
    
    func verifyHmac(key : Data, data : Data, macToVerify: Data) -> Bool {
        let mac = computeHmac(key: key, data: data)
        return mac == macToVerify
    }
}

