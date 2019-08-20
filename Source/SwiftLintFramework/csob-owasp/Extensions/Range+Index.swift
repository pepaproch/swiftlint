//
//  NSRange+Index.swift
//  swiftlint
//
//  Created by Vladimír Nevyhoštěný on 26/10/2017.
//  Copyright © 2017 Realm. All rights reserved.
//

import Foundation

//==============================================================================
extension Range where Bound == String.Index
{
    var nsRange: NSRange {
        return NSRange(location: self.lowerBound.encodedOffset,
                       length: self.upperBound.encodedOffset -
                        self.lowerBound.encodedOffset)
    }
}

