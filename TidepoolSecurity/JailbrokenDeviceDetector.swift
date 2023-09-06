//
//  JailbrokenDeviceDetector.swift
//  TidepoolSecurity
//
//  Created by Nathaniel Hamming on 2023-09-05.
//  Copyright © 2023 Tidepool Project. All rights reserved.
//

import UIKit

struct JailbrokenDeviceDetector {
    static public func isJailbrokenDevice() -> Bool {
        #if targetEnvironment(simulator)
        return false
        #else
        if let url = URL(string: "cydia://"),
           UIApplication.shared.canOpenURL(url)
        {
            return true
        }


        if FileManager.default.fileExists(atPath: "/Applications/Cydia.app") ||
            FileManager.default.fileExists(atPath: "/Library/MobileSubstrate/MobileSubstrate.dylib") ||
            FileManager.default.fileExists(atPath: "/bin/bash") ||
            FileManager.default.fileExists(atPath: "/usr/sbin/sshd") ||
            FileManager.default.fileExists(atPath: "/etc/apt") ||
            FileManager.default.fileExists(atPath: "/usr/bin/ssh")
        {
            return true
        }

        return false
        #endif
    }
}
