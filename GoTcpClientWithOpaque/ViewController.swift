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
    
  //  let userNameStr = "Alina"
 //   let passwordStr = "123456"
    let registrator = Registration()
    let authenticator = Authentication()
    let ipServer = "37.112.236.247"
    let port = 9999
    
    let decoder = JSONDecoder()
    
    var regClientSession: PwRegClientSession?
    
    override func viewDidLoad() {
        super.viewDidLoad()
        // Do any additional setup after loading the view.
    }
    
    
    @IBAction func logIn(_ sender: Any) {
        let client = TCPClient(address: ipServer, port: Int32(port))
        
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
        print("Start sign up...")
        let userNameStr = userName.text ?? "Alina"
        let passwordStr = password.text ?? "123456"
        let client = TCPClient(address: ipServer, port: Int32(port))
        switch client.connect(timeout: 100) {
        case .success:
            print("Connected to server...")
            Promise<Data> { promise in
                print("Start client registration...")
                let regInitRes = self.registrator.regInit(userNameStr, passwordStr)
                self.regClientSession = regInitRes.pwRegClientSession
                let msg1JsonString = try self.registrator.createPwRegMsg1JSon(userNameStr, regInitRes.pwRegMsg1)
                
                var dataFinal = Data("pwreg\n".bytes)
                dataFinal.append(contentsOf: msg1JsonString.bytes)
                dataFinal.append(contentsOf: "\n".bytes)
                
                switch client.send(data: dataFinal) {
                case .success:
                    print("Registration init request was sent succesfully.")
                    promise.fulfill(Data(_ : []))
                case .failure(let error):
                    print("Registration init request was failed.")
                    print(error)
                    promise.reject(error)
                }
            }
            .then{(dummyResponse : Data)  -> Promise<Data> in
                return Promise { promise in
                    guard let data = client.read(1024*10, timeout: 100) else {
                        promise.reject(NSError(domain:"", code:0, userInfo: [NSLocalizedDescriptionKey: "Can not read data from server."]))
                        return
                    }
                    if let response = String(bytes: data, encoding: .utf8) {
                        print("Got json from server:")
                        print(response)
                        promise.fulfill(Data(_ :data))
                    }
                    else{
                        promise.reject(NSError(domain:"", code:0, userInfo: [NSLocalizedDescriptionKey: "Data from server is corrupted."] ))
                    }
                }
                
            }
            .then{(response : Data)  -> Promise<Data> in
                return Promise { promise in
                    if let json = String(bytes: response, encoding: .utf8) {
                        let parsed = try self.decoder.decode(PwRegMsg2ForParsing.self, from: response.asData)
                        print("Parsed json from server:")
                        print(parsed)
                        
                        //Todo: check the validity of parsed.B.X (and othhers coordinates) format
                        //must be decimal or hex string
                        
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
                        print(msg2.B.y.asDecimalString())
                        print(msg2.PubS.x.asDecimalString())
                        print(msg2.PubS.y.asDecimalString())
                        
                        //Todo: check regClientSession is good.
                        
                        print("Start step 2 of registration (form user's envelope)...")
                        
                        let msg3 = try self.registrator.reg2(session: self.regClientSession!, msg2: msg2)
                        
                        print("msg3:")
                        print(msg3.PubU.point.x.asDecimalString())
                        print(msg3.PubU.point.x.asTrimmedData().count)
                        print(msg3.PubU.point.y.asDecimalString())
                        print(msg3.PubU.point.y.asTrimmedData().count)
                        print(msg3.EnvU.asData.count)
                        
                        let msg3JsonString = try self.registrator.createPwRegMsg3JSon(msg3)
                        var dataFinal = Data(msg3JsonString.bytes)
                        dataFinal.append(contentsOf: "\n".bytes)
                        
                        switch client.send(data: dataFinal) {
                        case .success:
                            print("Step 2 of registration is done.")
                            promise.fulfill(Data(_ : []))
                        case .failure(let error):
                            print("Step 2 of registration failed.")
                            print(error)
                            promise.reject(error)
                        }
                        
                    }
                    else{
                        promise.reject(NSError(domain:"", code:44, userInfo:[NSLocalizedDescriptionKey: "Data from server is corrupted."]))
                    }
                }
            }
            .then{(dummyResponse : Data)  -> Promise<Data> in
                return Promise { promise in
                    guard let data = client.read(1024*10, timeout: 100) else {
                        promise.reject(NSError(domain:"", code:0, userInfo:[NSLocalizedDescriptionKey: "Data from server is corrupted."] ))
                        return
                    }
                    if let response = String(bytes: data, encoding: .utf8) {
                        print(response)
                        promise.fulfill(Data(_ :data))
                    }
                    else{
                        promise.reject(NSError(domain:"", code:0, userInfo:nil))
                    }
                }
                
            }
    
            .done{response in
                print("Done")
                let alert = UIAlertController(title: "Notification", message: "User password was registered on server.", preferredStyle: UIAlertController.Style.alert)
                alert.addAction(UIAlertAction(title: "OK", style: UIAlertAction.Style.default, handler: nil))
                self.present(alert, animated: true, completion: nil)
            }
            .catch{ error in
                print("Error happened : " + error.localizedDescription)
            }
        case .failure(let error):
            print("Can not establish TCP connection with server having IP address " + ipServer + ".")
        }
        
    }
}

