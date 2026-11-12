//
//  JailbrokenDeviceDetector.swift
//  TidepoolSecurity
//
//  Created by Nathaniel Hamming on 2023-09-05.
//  Copyright © 2023 Tidepool Project. All rights reserved.
//

import UIKit

struct JailbrokenDeviceDetector {
    // Each scheme must also be listed under LSApplicationQueriesSchemes in the app's Info.plist.
    // cydia:// is deliberately absent: an App Store app has registered it, causing false positives.
    private static let jailbreakURLSchemes = [
        "sileo",
        "zbra",
        "dopamine",
        "palera1n",
    ]

    private static let jailbreakFilePaths = [
        "/Applications/Cydia.app",
        "/Applications/Sileo.app",
        "/Applications/Zebra.app",
        "/Library/MobileSubstrate/MobileSubstrate.dylib",
        "/bin/bash",
        "/usr/sbin/sshd",
        "/etc/apt",
        "/usr/bin/ssh",
        "/var/jb",
    ]

    // Rootless jailbreaks link /var/jb to their bootstrap; the link can outlive its target after a reboot.
    private static let rootlessJailbreakLink = "/var/jb"

    static public func isJailbrokenDevice() -> Bool {
        #if targetEnvironment(simulator)
        return false
        #else
        let hasJailbreakApp = jailbreakURLSchemes.contains { scheme in
            guard let url = URL(string: "\(scheme)://") else {
                return false
            }
            return UIApplication.shared.canOpenURL(url)
        }
        if hasJailbreakApp {
            return true
        }

        if jailbreakFilePaths.contains(where: { FileManager.default.fileExists(atPath: $0) }) {
            return true
        }

        return (try? FileManager.default.destinationOfSymbolicLink(atPath: rootlessJailbreakLink)) != nil
        #endif
    }
}
