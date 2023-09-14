//
//  TidepoolSecurityPlugin.swift
//  TidepoolSecurityPlugin
//
//  Created by Nathaniel Hamming on 2023-09-01.
//  Copyright © 2023 Tidepool Project. All rights reserved.
//

import os.log
import LoopKit
import TidepoolSecurity

class TidepoolSecurityPlugin: NSObject, StatefulPlugin {
    
    private let log = OSLog(category: "TidepoolSecurityPlugin")

    public var pluginType: StatefulPluggable.Type? { TidepoolSecurity.self }
    
    override init() {
        super.init()
        log.default("Instantiated")
    }
}
