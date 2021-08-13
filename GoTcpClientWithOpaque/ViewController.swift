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
    let ipServer = "127.0.0.1"//"94.180.60.101"
    let port = 9999
    
    let decoder = JSONDecoder()
    
    var regClientSession: PwRegClientSession?
    var authClientSession: AuthClientSession?
    
    override func viewDidLoad() {
        super.viewDidLoad()
        // Do any additional setup after loading the view.
    }
    
    
    @IBAction func logIn(_ sender: Any) {
        print("\n \n Start log in...")
        let userNameStr = userName.text ?? "Alina"
        let passwordStr = password.text ?? "123456"
        let client = TCPClient(address: ipServer, port: Int32(port))
        switch client.connect(timeout: 100) {
        case .success:
            print("Connected to server...")
            Promise<Data> { promise in
                print("Start client authentication...")
                let authInitRes = try self.authenticator.authInit(userNameStr, passwordStr)
                self.authClientSession = authInitRes.authClientSession
                let msg1JsonString = try self.authenticator.createAuthMsg1JSon(authInitRes.authMsg1)
                print("===============================")
                
                var dataFinal = Data("auth\n".bytes)
                dataFinal.append(contentsOf: msg1JsonString.bytes)
                dataFinal.append(contentsOf: "\n".bytes)
                
                switch client.send(data: dataFinal) {
                case .success:
                    print("Authentication init request was sent succesfully.")
                    promise.fulfill(Data(_ : []))
                case .failure(let error):
                    print("Authentication init request was failed.")
                    print(error)
                    promise.reject(error)
                }
                
                promise.fulfill(Data(_ : []))
            
            }
            .then{(dummyResponse : Data)  -> Promise<Data> in
                return Promise { promise in
                    guard let data = client.read(1024*10, timeout: 100) else {
                        promise.reject(NSError(domain:"", code:0, userInfo: [NSLocalizedDescriptionKey: "Can not read data from server."]))
                        return
                    }
                    if let response = String(bytes: data, encoding: .utf8) {
                        
                        if response.contains("No such user") {
                            promise.reject(NSError(domain:"", code:0, userInfo: [NSLocalizedDescriptionKey: "No such user on server."] ))
                        }
                        else {
                            print("Got json from server:")
                            print(response)
                            promise.fulfill(Data(_ :data))
                        }
                    }
                    else{
                        promise.reject(NSError(domain:"", code:0, userInfo: [NSLocalizedDescriptionKey: "Data from server is corrupted."] ))
                    }
                }
                
            }
            .then{(response : Data)  -> Promise<Data> in
                return Promise { promise in
                    if let json = String(bytes: response, encoding: .utf8) {
                        let parsed = try self.decoder.decode(AuthMsg2ForParsing.self, from: response.asData)
                        print("Parsed json from server:")
                        print(parsed)
                        
                        //Todo: check the validity of parsed.B.X (and othhers coordinates) format
                        //must be decimal or hex string
                        
                        let B = AffinePoint<Secp256r1>(
                            x: Number(parsed.B.X)!,
                            y: Number(parsed.B.Y)!
                        )
                        let EPubSPoint = AffinePoint<Secp256r1>(
                            x: Number(parsed.EphemeralPubS.X)!,
                            y: Number(parsed.EphemeralPubS.Y)!
                        )
                        let EPubS = PublicKey<Secp256r1>(point: EPubSPoint)
                        
                        let envUData = Data (_ :ByteArrayAndHexHelper.hexStrToUInt8Array(hexStr: parsed.EnvU))
                        let nonceSData = Data (_ :ByteArrayAndHexHelper.hexStrToUInt8Array(hexStr: parsed.NonceS))
                        let mac1Data = Data (_ :ByteArrayAndHexHelper.hexStrToUInt8Array(hexStr: parsed.Mac1))
                        let msg2 = AuthMsg2(B, envUData, nonceSData, EPubS, mac1Data)
                        
                        
                        //Todo: check authClientSession is good.
                        
                       print("Start step 2 of registration (form user's envelope)...")
                        
                        let msg3 = try self.authenticator.auth2(session: self.authClientSession!, msg2: msg2)
                        
                        print("msg3:")
                        print(msg3.mac2.hexEncodedString())
                        
                        let msg3JsonString = try self.authenticator.createAuthMsg3JSon(msg3)
                        var dataFinal = Data(msg3JsonString.bytes)
                        dataFinal.append(contentsOf: "\n".bytes)
                        
                        switch client.send(data: dataFinal) {
                        case .success:
                            print("Step 2 of authentication is done.")
                            promise.fulfill(Data(_ : []))
                        case .failure(let error):
                            print("Step 2 of authentication failed.")
                            print(error)
                            promise.reject(error)
                        }
                        promise.fulfill(Data(_ : []))
                    }
                    else{
                        promise.reject(NSError(domain:"", code:44, userInfo:[NSLocalizedDescriptionKey: "Data from server is corrupted."]))
                    }
                }
            }
            .done{response in
                print("Done")
                self.authClientSession = nil
                let alert = UIAlertController(title: "Notification", message: "User was authenticated on server.", preferredStyle: UIAlertController.Style.alert)
                alert.addAction(UIAlertAction(title: "OK", style: UIAlertAction.Style.default, handler: nil))
                self.present(alert, animated: true, completion: nil)
            }
            .catch{ error in
                print("Error happened : " + error.localizedDescription)
                self.authClientSession = nil
                let alert = UIAlertController(title: "Error", message: error.localizedDescription, preferredStyle: UIAlertController.Style.alert)
                alert.addAction(UIAlertAction(title: "OK", style: UIAlertAction.Style.default, handler: nil))
                self.present(alert, animated: true, completion: nil)
            }
        case .failure(let error):
            print("Can not establish TCP connection with server having IP address " + ipServer + ".")
        }
        
    }
    
    
    
    @IBAction func signUp(_ sender: Any) {
        print("\n \n Start sign up...")
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
                let msg1JsonString = try self.registrator.createPwRegMsg1JSon(regInitRes.pwRegMsg1)
                print("===============================")
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
                        print("===============================")
                        print("Start step 2 of registration (form user's envelope)...")
                        
                        let msg3 = try self.registrator.reg2(session: self.regClientSession!, msg2: msg2)
                        
                        print("Prepared data for Server #2:")
                        print("===============================")
                        print("PubU:")
                        print("X: "  + msg3.PubU.point.x.asDecimalString())
                        print("Y: " + msg3.PubU.point.y.asDecimalString())
                        print("Env: " + msg3.EnvU.asData.hexEncodedString())
                        print("===============================")
                        
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
                self.regClientSession = nil
                let alert = UIAlertController(title: "Notification", message: "User password was registered on server.", preferredStyle: UIAlertController.Style.alert)
                alert.addAction(UIAlertAction(title: "OK", style: UIAlertAction.Style.default, handler: nil))
                self.present(alert, animated: true, completion: nil)
            }
            .catch{ error in
                print("Error happened : " + error.localizedDescription)
                self.regClientSession = nil
                
                let alert = UIAlertController(title: "Error", message: error.localizedDescription, preferredStyle: UIAlertController.Style.alert)
                alert.addAction(UIAlertAction(title: "OK", style: UIAlertAction.Style.default, handler: nil))
                self.present(alert, animated: true, completion: nil)
            }
        case .failure(let error):
            print("Can not establish TCP connection with server having IP address " + ipServer + ".")
        }
        
    }
}

