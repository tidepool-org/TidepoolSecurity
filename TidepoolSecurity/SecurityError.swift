//
//  SecurityError.swift
//  TidepoolSecurity
//
//  Created by Nathaniel Hamming on 2023-09-05.
//  Copyright © 2023 Tidepool Project. All rights reserved.
//

public enum SecurityError: LocalizedError {
    case unexpectedError
    case unexpectedState
    case networkFailure
    case authenticationFailure
    case resourceNotFound

    public var errorDescription: String? {
        switch self {
        case .unexpectedError:
            return LocalizedString("An unexpected error occurred.", comment: "Error description for an unexpected error.")
        case .unexpectedState:
            return LocalizedString("An unexpected state occurred.", comment: "Error description for an unexpected state.")
        case .networkFailure:
            return LocalizedString("Poor network connection detected. Please check your connectivity and try again.", comment: "Error description for a network failure.")
        case .authenticationFailure:
            return LocalizedString("An authentication error occurred.", comment: "Error description for an authentication failure.")
        case .resourceNotFound:
            return LocalizedString("A network error occurred.", comment: "Error description for a resource not found.")
        }
    }
}
