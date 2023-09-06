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

public protocol SecurePersistentAttestationKeyID {
    func setAttestationKeyID(_ password: String?, for keyService: String?) throws
    func getAttestationKeyID(for keyService: String?) -> String?
}

public final class TidepoolSecurity: Security {
    
    public static let identifier = "TidepoolSecurity"

    private let log = OSLog(category: "TidepoolSecurity")
    
    private var tidepoolService: TidepoolService?
    
    let appAttestService = DCAppAttestService.shared
    
    private var attestationKeyIDServiceIdentifier: String = "org.tidepool.TidepoolSecurity.Attestation.KeyID"
    
    private var securePersistentAttestationKeyID: () -> SecurePersistentAttestationKeyID
    
    private(set) var attestationKeyID: String? {
        get {
            return securePersistentAttestationKeyID().getAttestationKeyID(for: attestationKeyIDServiceIdentifier)
        }
        set {
            guard let attestationKeyID = newValue else {
                return
            }

            try? securePersistentAttestationKeyID().setAttestationKeyID(attestationKeyID, for: attestationKeyIDServiceIdentifier)
        }
    }

    public init(securePersistentAttestationKeyID: @escaping () -> SecurePersistentAttestationKeyID = { KeychainManager() }) {
        self.securePersistentAttestationKeyID = securePersistentAttestationKeyID
    }
    
    public func initializationComplete(for services: [LoopKit.Service]) {
        if let tidepoolService = services.first(where: { $0 as? TidepoolService != nil }) as? TidepoolService {
            self.tidepoolService = tidepoolService
        }
    }
    
    public func verifyDevice(completion: @escaping (Result<Bool,SecurityError>) -> Void) {
        guard let tidepoolService = tidepoolService else {
            log.info("%{public}@ TidepoolService is missing", #function)
            completion(.failure(.unexpectedState))
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
            Task { @MainActor in
                guard error == nil, let token = token else {
                    self.log.info("%{public}@ Device token generation failed [error=%{public}@]", #function, error.debugDescription)
                    completion(.failure(.unexpectedError))
                    return
                }

                do {
                    let deviceValid = try await tidepoolService.tapi.verifyDevice(deviceToken: token)
                    completion(.success(deviceValid))
                } catch {
                    // Should this use one of the following networkFailure, authenticationFailure, resourceNotFound
                    completion(.failure(.unexpectedError))
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
    
    public func verifyApp(completion: @escaping (Result<Bool,SecurityError>) -> Void) {
        guard let tidepoolService = tidepoolService else {
            log.info("%{public}@ TidepoolService is missing", #function)
            completion(.failure(.unexpectedState))
            return
        }

        // If the app does not require verification (i.e. simulator), mark as valid
        guard appRequiresVerification else {
            log.info("%{public}@ App verification not required", #function)
            completion(.success(true))
            return
        }

        // if the device does not support DCAppAttestService API, mark as invalid
        let appAttestService = DCAppAttestService.shared
        guard appAttestService.isSupported else {
            log.info("%{public}@ DCAppAttestService API not supported, app key ID cannot be generated, validation failure", #function)
            completion(.success(false))
            return
        }

        Task { @MainActor in
            do {
                let attestationKeyID: String
                if self.attestationKeyID != nil {
                    attestationKeyID = self.attestationKeyID!
                } else {
                    attestationKeyID = try await appAttestService.generateKey()
                }

                let challenge = try await tidepoolService.tapi.getAttestationChallenge(keyID: attestationKeyID)

                let hash = Data(SHA256.hash(data: Array(challenge.utf8)))

                let attestation = try await appAttestService.attestKey(attestationKeyID, clientDataHash: hash)

                let appValid = try await tidepoolService.tapi.verifyAttestation(keyID: attestationKeyID, challenge: challenge, attestation: attestation.base64EncodedString())

                self.attestationKeyID = attestationKeyID
                completion(.success(appValid))
            } catch {
                self.log.info("%{public}@ App attestation verification failed [error=%{public}@]", #function, String(describing: error.localizedDescription))
                self.attestationKeyID = nil
                // Should this use one of the following networkFailure, authenticationFailure, resourceNotFound
                completion(.failure(.unexpectedError))
            }
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
}

extension KeychainManager: SecurePersistentAttestationKeyID {
    public func setAttestationKeyID(_ password: String?, for keyService: String?) throws {
        if let keyService = keyService {
            try replaceGenericPassword(password, forService: keyService)
        }
    }
    
    public func getAttestationKeyID(for keyService: String?) -> String? {
        guard let keyService = keyService else {
            return nil
        }
        return try? getGenericPasswordForService(keyService)
    }
}
