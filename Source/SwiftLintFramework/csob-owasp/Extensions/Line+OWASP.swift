//
//  Line+OWASP.swift
//  SwiftLintFramework
//
//  Created by Vladimír Nevyhoštěný on 08/11/2017.
//  Copyright © 2017 Realm. All rights reserved.
//

import Foundation
import SourceKittenFramework

//==============================================================================
extension Line
{
    //--------------------------------------------------------------------------
    func substring(withStatement statement: [String: SourceKitRepresentable]) -> String?
    {
        guard let offset = statement.bodyOffset, let length = statement.bodyLength else {
            return nil
        }
        
        let startLocation = offset - self.byteRange.location
        let realLength    = startLocation + length < self.content.count - 1 ? length : self.content.count - startLocation - 1
        
        guard startLocation >= 0, realLength > 0, realLength < self.content.count else {
            return nil
        }
        
        return self.content.substring(from: startLocation, length: realLength)
    }
    
    //--------------------------------------------------------------------------
    func align(_ other: NSRange) -> NSRange
    {
        let lineLength = self.content.count
        let length     = ((other.location - self.range.location) + other.length) < lineLength ? other.length : lineLength - (other.location - self.range.location) - 1
        
        return NSRange(location: other.location, length: length)
    }
}

//==============================================================================
extension Array where Element == Line
{
    //--------------------------------------------------------------------------
    public func matching(lvalue: String, excludeLine line: Line? = nil) -> [Line]
    {
        var results      = [Line]()
        let regParam     = "\\s*\(lvalue)\\s*="
        
        guard let regexp = regexOpt(regParam) else {
            print("Wrong regex parameter: \(regParam)")
            return results
        }
        
        let matchedLines  = self.filter {!regexp.matches(in: $0.content, options: [], range: NSRange(location: 0, length: $0.content.count)).isEmpty && (line == nil || (line != nil &&  $0.range.location != line!.range.location))}
        
        for line in matchedLines {
            if let _ = line.content.rvalue(lvalue: lvalue) {
                results.append(line)
            }
        }
        
        return results
    }
}
