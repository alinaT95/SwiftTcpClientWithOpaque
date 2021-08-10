//
//  ViewController.swift
//  GoTcpClientWithOpaque
//
//  Created by Alina Alinovna on 08.08.2021.
//

import UIKit
import EllipticCurveKit
import PromiseKit

class ViewController: UIViewController {
    
    @IBOutlet weak var userName: UITextField!
    
    @IBOutlet weak var password: UITextField!
    
    let userNameStr = "Alina"
    let passwordStr = "123456"
    let registrator = Registration()
    let authenticator = Authentication()
    let ipServer = "5.165.180.12"
    let port = 9999
    
    let decoder = JSONDecoder()
    
    var regClientSession: PwRegClientSession?
    
    override func viewDidLoad() {
        super.viewDidLoad()
        // Do any additional setup after loading the view.
    }
    
    
    @IBAction func logIn(_ sender: Any) {
        let client = TCPClient(address: "5.166.239.215", port: 9999)
        
        // Do any additional setup after loading the view.
        
        /*   let expected = AffinePoint<Secp256r1>(
         x: 1,
         y: 0
         )
         let expected2 = AffinePoint<Secp256r1>(
         x: 0,
         y: 2
         )*/
        // guard let x = Number("89", radix: 10) else { return <#default value#> }
        // _ = expected * x
        
        //  let G = Secp256r1.G
        // let nPlusOne = Secp256r1.order + 1
        
        
        /*  let pointNPlusOne: AffinePoint<Secp256r1> = expected * nPlusOne
         let publicKey = PublicKey<Secp256r1>(point: Secp256r1.G * nPlusOne)
         
         let pointNPlus: AffinePoint<Secp256r1> =  AffinePoint<Secp256r1>.addition(expected, expected2) ?? G*/
        
        /*     let point: AffinePoint<Secp256r1> =  Crypto().hashToECDummy(Data(_: [0x01, 0x02]))
         print("here")
         print(point.x)
         print(point.y)*/
        
        /*  switch client.connect(timeout: 10) {
         case .success:
         print("y")
         case .failure(let error):
         print("n")
         }*/
        
    }
    
    
    
    @IBAction func signUp(_ sender: Any) {
        let client = TCPClient(address: ipServer, port: Int32(port))
        switch client.connect(timeout: 100) {
        case .success:
            Promise<Data> { promise in
                let result = self.registrator.regInit(self.userNameStr, self.passwordStr)
                self.regClientSession = result.pwRegClientSession
                var data: [String : Any] = [:]
                data["userName"] = self.userNameStr
                data["a"] = ["x" : result.pwRegMsg1.a.x.asDecimalString(), "y" : result.pwRegMsg1.a.y.asDecimalString()]
                
                let jsonData = try JSONSerialization.data(withJSONObject: data)
                let jsonString = String(data: jsonData, encoding: .utf8)!
                print(jsonString)
                
                var dataFinal = Data("pwreg\n".bytes)
                dataFinal.append(contentsOf: jsonString.bytes)
                dataFinal.append(contentsOf: "\n".bytes)
                
                switch client.send(data: dataFinal) {
                case .success:
                    print("pwreg and reginit are sent")
                    promise.fulfill(Data(_ : []))
                case .failure(let error):
                    promise.reject(error)
                    print(error)
                }
            }
            .then{(dummyResponse : Data)  -> Promise<Data> in
                return Promise { promise in
                    guard let data = client.read(1024*10, timeout: 100) else {
                        promise.reject(NSError(domain:"", code:44, userInfo:nil))
                        return
                    }
                    if let response = String(bytes: data, encoding: .utf8) {
                        promise.fulfill(Data(_ :data))
                    }
                    else{
                        promise.reject(NSError(domain:"", code:44, userInfo:nil))
                    }
                }
                
            }
            .then{(response : Data)  -> Promise<Data> in
                return Promise { promise in
                    if let json = String(bytes: response, encoding: .utf8) {
                        print(json)
                        let parsed = try self.decoder.decode(PwRegMsg2ForParsing.self, from: response.asData)
                        print("This is Parsed:")
                        print(parsed)
                        
                        let B = AffinePoint<Secp256r1>(
                            x: Number(parsed.B.X)!,
                            y: Number(parsed.B.Y)!
                        )
                        let PubSPoint = AffinePoint<Secp256r1>(
                            x: Number(parsed.PubS.X)!,
                            y: Number(parsed.PubS.Y)!
                        )
                        let PubS = PublicKey<Secp256r1>(point: PubSPoint)
                        
                        let msg2 = PwRegMsg2(B, PubS)
                        print(msg2.B.x.asDecimalString())
                        
                        
                        let msg3 = try self.registrator.reg2(session: self.regClientSession!, msg2: msg2)
                        
                        print("msg3:")
                        print(msg3.PubU.x.asDecimalString())
                        print(msg3.EnvU.asData.count)
                        
                        var data: [String : Any] = [:]
                        data["EnvU"] = msg3.EnvU.asData.hexEncodedString()
                        data["PubU"] = ["x" : msg3.PubU.x.asDecimalString(), "y" : msg3.PubU.y.asDecimalString()]
                        
                        let jsonData = try JSONSerialization.data(withJSONObject: data)
                        let jsonString = String(data: jsonData, encoding: .utf8)!
                        print(jsonString)
                        
                        var dataFinal = Data(jsonString.bytes)
                        dataFinal.append(contentsOf: "\n".bytes)
                        
                        switch client.send(data: dataFinal) {
                        case .success:
                            print("reg2 is sent")
                            promise.fulfill(Data(_ : []))
                        case .failure(let error):
                            promise.reject(error)
                            print(error)
                        }
                        
                    }
                    else{
                        promise.reject(NSError(domain:"", code:44, userInfo:nil))
                    }
                }
            }
            .then{(dummyResponse : Data)  -> Promise<Data> in
                return Promise { promise in
                    guard let data = client.read(1024*10, timeout: 100) else {
                        promise.reject(NSError(domain:"", code:44, userInfo:nil))
                        return
                    }
                    if let response = String(bytes: data, encoding: .utf8) {
                        print(response)
                        promise.fulfill(Data(_ :data))
                    }
                    else{
                        promise.reject(NSError(domain:"", code:44, userInfo:nil))
                    }
                }
                
            }
            
            .done{response in
                print("Done")
            }
            .catch{ error in
                print("Error happened : " + error.localizedDescription)
            }
        case .failure(let error):
            print(error)
        }
        
    }
}

