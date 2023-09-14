//
//  Data.swift
//  TidepoolSecurity
//
//  Created by Nathaniel Hamming on 2023-09-13.
//  Copyright © 2023 Tidepool Project. All rights reserved.
//

extension Data {
    var hexadecimalString: String {
        return map { String(format: "%02hhx", $0) }.joined()
    }
}
