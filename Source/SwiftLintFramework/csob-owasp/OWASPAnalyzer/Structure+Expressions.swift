//
//  Structure+Expressions.swift
//  SwiftLintFramework
//
//  Created by Vladimír Nevyhoštěný on 06/11/2017.
//  Copyright © 2017 Realm. All rights reserved.
//

import Foundation
import SourceKittenFramework

//==============================================================================
extension Structure
{
    //-------------------------------------------------------------------------
    func calls(ofMethodName methodName: String) -> [[String: SourceKitRepresentable]]
    {
        var results = [[String: SourceKitRepresentable]]()
        
        func parse(_ dictionary: [String: SourceKitRepresentable])
        {
            if dictionary.kind == SwiftExpressionKind.call.rawValue,
               let name        = dictionary.name,
               name.contains(methodName) {
                    results.append(dictionary)
            }
            
            dictionary.substructure.forEach(parse)
        }
        
        parse(self.dictionary)
        
        return results
    }
    
    //--------------------------------------------------------------------------
    func arguments(ofFunction funcDictionary: [String: SourceKitRepresentable]) -> [[String: SourceKitRepresentable]]
    {
        var results = [[String: SourceKitRepresentable]]()
        
        func parse(_ dictionary: [String: SourceKitRepresentable])
        {
            if dictionary.kind == "source.lang.swift.expr.argument" {
                results.append(dictionary)
            }
            
            dictionary.substructure.forEach(parse)
        }
        
        parse(funcDictionary)
        
        return results
    }
    
    //--------------------------------------------------------------------------
    func statement(forLine line: Line, ofKind kind: String? = nil) -> [String: SourceKitRepresentable]?
    {
        var result:     [String: SourceKitRepresentable]? = nil
        
        var current   = self.dictionary
        var last:       [String: SourceKitRepresentable]?
        
        //----------------------------------------------------------------------
        func parse(_ dictionary: [String: SourceKitRepresentable])
        {
            guard result == nil else {
                return
            }
            
            last           = current
            current        = dictionary
            
            if let offset = current.bodyOffset, let length = current.bodyLength {
                let currentRange = NSRange(location: offset, length: length)
                if line.range.intersects(currentRange) {
                //if currentRange.location >= line.range.location && currentRange.length <= line.range.length {
                    result = current
                    return
                }
            }
            
            current.substructure.forEach(parse)
        }
        
        parse(self.dictionary)
        
        return result
    }

}

