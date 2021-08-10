//
//  ByteArrayAndHexHelper.swift
//  GoTcpClientWithOpaque
//
//  Created by Alina Alinovna on 09.08.2021.
//

import Foundation

public class ByteArrayAndHexHelper {
    
    public func randomData(_ length: Int) throws -> Data {
        var bytes = [UInt8](repeating: 0, count: length)
        let status = SecRandomCopyBytes(kSecRandomDefault, length, &bytes)
        if status == errSecSuccess {
            return Data(bytes: bytes)
        }
        throw "Can not generate random data."
    }
    
    
    public static func digitalStrIntoAsciiUInt8Array(digitalStr : String) -> [UInt8]{
      var bytes = [UInt8]()
      for s in digitalStr {
        if let byte = UInt8(String(s)) {
          bytes.append(0x30 + byte)
        }
      }
      return bytes
    }
    
    public static func hexStrToUInt8Array(hexStr: String) -> [UInt8] {
      var startIndex = hexStr.startIndex
      return (0..<hexStr.count/2).compactMap { _ in
        let endIndex = hexStr.index(after: startIndex)
        defer { startIndex = hexStr.index(after: endIndex) }
        return UInt8(hexStr[startIndex...endIndex], radix: 16)
      }
    }
    
    public static func hex(from string: String) -> Data {
      .init(stride(from: 0, to: string.count, by: 2).map {
        string[string.index(string.startIndex, offsetBy: $0) ... string.index(string.startIndex, offsetBy: $0 + 1)]
      }.map {
        UInt8($0, radix: 16)!
      })
    }
    
    public static func makeShort(src: [UInt8], srcOff : Int) -> Int {
      // if (srcOff < 0  ||  src.length < (srcOff + 2))
      //   throw new IllegalArgumentException("Bad args!");
      let b0 = Int(src[srcOff] & 0xFF);
      let b1 = Int(src[srcOff + 1] & 0xFF);
      return (b0 << 8) + b1
    }
    
}
