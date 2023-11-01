//
//  TidepoolSecurity.swift
//  TidepoolSecurity
//
//  Created by Nathaniel Hamming on 2023-09-05.
//  Copyright © 2023 Tidepool Project. All rights reserved.
//

import DeviceCheck
import CryptoKit
import os.log
import LoopKit
import TidepoolServiceKit
import TidepoolKit

public protocol SecurePersistentAttestationKeyID {
    func setAttestationKeyID(_ password: String?, for keyService: String?) throws
    func getAttestationKeyID(for keyService: String?) -> String?
}

public final class TidepoolSecurity: StatefulPluggable {
    public var isOnboarded: Bool {
        tidepoolService != nil
    }
    
    public static let securityIdentifier = "TidepoolSecurity"
    
    public var pluginIdentifier: String { Self.securityIdentifier }
    
    private let log = OSLog(category: "TidepoolSecurity")
    
    private var tidepoolService: TidepoolService?
    
    public weak var stateDelegate: StatefulPluggableDelegate?
    
    let appAttestService = DCAppAttestService.shared
    
    private(set) var attestationKeyID: String? {
        didSet {
            stateDelegate?.pluginDidUpdateState(self)
        }
    }
    
    public init() {
        attestationKeyID = nil
    }
    
    public init?(rawState: RawStateValue = [:]) {
        self.attestationKeyID = rawState["attestationKeyID"] as? String
    }
    
    public var rawState: RawStateValue {
        var rawState: RawStateValue = [:]
        rawState["attestationKeyID"] = attestationKeyID
        return rawState
    }
    
    public func initializationComplete(for pluggables: [Pluggable]) {
        if let tidepoolService = pluggables.first(where: { $0 as? TidepoolService != nil }) as? TidepoolService {
            self.tidepoolService = tidepoolService
        }
    }
    
    public func verifyiOSDevice(completion: @escaping (Result<Bool, Error>) -> Void) {
        guard let tidepoolService = tidepoolService else {
            log.info("%{public}@ TidepoolService is missing", #function)
            completion(.failure(SecurityError.unexpectedState))
            return
        }
        
        // If the device does not require verification (i.e. simulator), mark as valid
        guard deviceRequiresVerification else {
            log.info("%{public}@ Device verification not required", #function)
            completion(.success(true))
            return
        }
        
        guard !JailbrokenDeviceDetector.isJailbrokenDevice() else {
            log.info("%{public}@ Device jailbroken", #function)
            completion(.success(false))
            return
        }
        
        // if the device does not support DCDevice API, mark as invalid
        guard DCDevice.current.isSupported else {
            log.info("%{public}@ DCDevice API not supported, device token cannot be generated, validation failure", #function)
            completion(.success(false))
            return
        }
        
        DCDevice.current.generateToken { token, error in
            Task {
                guard error == nil, let token = token else {
                    self.log.info("%{public}@ Device token generation failed [error=%{public}@]", #function, error.debugDescription)
                    completion(.failure(SecurityError.unexpectedError))
                    return
                }
                
                do {
                    let deviceValid = try await tidepoolService.tapi.verifyDevice(deviceToken: token)
                    completion(.success(deviceValid))
                } catch {
                    // Should this use one of the following networkFailure, authenticationFailure, resourceNotFound
                    completion(.failure(SecurityError.unexpectedError))
                }
            }
        }
    }
    
    private var deviceRequiresVerification: Bool {
        #if targetEnvironment(simulator)
        return false
        #else
        return true
        #endif
    }
    
    public func verifyApp() async throws -> Bool {
        guard let tidepoolService = tidepoolService else {
            log.info("%{public}@ TidepoolService is missing", #function)
            throw SecurityError.unexpectedState
        }
        
        // If the app does not require verification (i.e. simulator), mark as valid
        guard appRequiresVerification else {
            log.info("%{public}@ App verification not required", #function)
            return true
        }
        
        // if the device does not support DCAppAttestService API, mark as invalid
        let appAttestService = DCAppAttestService.shared
        guard appAttestService.isSupported else {
            log.info("%{public}@ DCAppAttestService API not supported, app key ID cannot be generated, validation failure", #function)
            return false
        }
        
        do {
            let attestationKeyID = try await appAttestService.generateKey()
            
            let challenge = try await tidepoolService.tapi.getAttestationChallenge(keyID: attestationKeyID)
            
            let hash = Data(SHA256.hash(data: Array(challenge.utf8)))
            
            let attestation = try await appAttestService.attestKey(attestationKeyID, clientDataHash: hash)
            
            let appValid = try await tidepoolService.tapi.verifyAttestation(keyID: attestationKeyID, challenge: challenge, attestation: attestation.base64EncodedString())
            
            self.attestationKeyID = attestationKeyID
            return appValid
        } catch let error {
            self.log.info("%{public}@ App attestation verification failed [error=%{public}@]", #function, String(describing: error.localizedDescription.debugDescription))
            self.attestationKeyID = nil
            // Should this use one of the following networkFailure, authenticationFailure, resourceNotFound
            throw error
        }
    }
    
    private var appRequiresVerification: Bool {
#if targetEnvironment(simulator)
        return false
#else
        return true
#endif
    }
    
    public var appAttestationSupported: Bool {
        appAttestService.isSupported
    }
    
    public func sendAppAssertion(partnerIdentifier: String, partnerData: [String: String]) async throws -> Data {
        guard let tidepoolService = tidepoolService else {
            log.info("%{public}@ TidepoolService is missing", #function)
            throw SecurityError.unexpectedState
        }
        
        // if the device does not support DCAppAttestService API
        let appAttestService = DCAppAttestService.shared
        guard appAttestService.isSupported else {
            log.info("%{public}@ DCAppAttestService API not supported, app key ID cannot be generated, validation failure", #function)
            throw SecurityError.unexpectedState
        }
        
        do {
            if self.attestationKeyID == nil {
                guard try await verifyApp() else {
                    fatalError("could not create attestation key ID")
                }
            }
            
            let attestationKeyID = self.attestationKeyID!
            let challenge = try await tidepoolService.tapi.getAssertionChallenge(keyID: attestationKeyID)
            let clientData = TClientData(challenge: challenge, partner: partnerIdentifier, partnerData: partnerData)
            let clientDataHash = Data(SHA256.hash(data: try JSONEncoder.tidepool.encode(clientData) ))
            let assertion = try await appAttestService.generateAssertion(attestationKeyID, clientDataHash: clientDataHash)
            return try await tidepoolService.tapi.verifyAssertion(keyID: attestationKeyID, challenge: challenge, assertion: assertion.base64EncodedString(), clientData: clientData)
        } catch let error {
            self.log.info("%{public}@ App assertion verification failed [error=%{public}@]", #function, String(describing: error.localizedDescription.debugDescription))
            // Should this use one of the following networkFailure, authenticationFailure, resourceNotFound
            throw error
        }
    }
}
