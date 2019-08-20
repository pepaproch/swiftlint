//
//  String+Regexp.swift
//  swiftlint
//
//  Created by Vladimír Nevyhoštěný on 23/10/2017.
//  Copyright © 2017 Realm. All rights reserved.
//

import Foundation

let FuncRegexpMap: [Character:String] = [
    "."                     : "\\.",
    "("                     : "\\s*\\(\\s*",
    ")"                     : "\\s*\\)\\s*",
    ":"                     : "\\s*:\\s*",
    ","                     : "\\s*,\\s*"
]

//==============================================================================
extension String
{
    var regexp: String {
        var result = "\\s*"
        for char in self {
            if let transformed = FuncRegexpMap [char] {
                result.append(transformed)
            }
            else {
                result.append(char)
            }
        }
        return result
    }
}


//==============================================================================
extension String
{
    //--------------------------------------------------------------------------
    func substring(withRange r: Range<Int>) -> String
    {
        let fromIndex = self.index(self.startIndex, offsetBy: r.lowerBound)
        let toIndex   = self.index(self.startIndex, offsetBy: r.upperBound)
        return String(self [fromIndex..<toIndex])
    }
}

//==============================================================================
extension String
{
    var toParamName: String {
        if let startRange = self.range(of: "("), let endRange = self.range(of: ":") {
            return String(self [self.index(after: startRange.lowerBound)..<endRange.lowerBound]).trimmingCharacters(in: .whitespacesAndNewlines)
        }
        return self
    }
    
    //--------------------------------------------------------------------------
    func substringBetween(_ lower: String, _ upper: String) -> String
    {
        if let startRange = self.range(of: lower), let endRange = self.range(of: upper) {
            return String(self [self.index(after: startRange.lowerBound)..<endRange.lowerBound]).trimmingCharacters(in: .whitespacesAndNewlines)
        }
        return self
    }
    
    
    
    //--------------------------------------------------------------------------
    func paramName(labelName: String) -> String?
    {
        let filtered    = self.trimmingCharacters(in: OWASPAnalyzer.stripParamCharSet)

        let components = filtered.components(separatedBy: ":")
        for (index, component) in components.enumerated() {
            if component.range(of: labelName) != nil && index < components.count - 1 {
                
                let paramExpression = components [index + 1].trimmingCharacters(in: OWASPAnalyzer.stripParamCharSet)
                let matchedRanges   = regex("[A-z]+[A-Za-z0-9]").matches(in: paramExpression, options: [], range: NSRange(location: 0, length: paramExpression.count)).map {$0.range}
                
                if matchedRanges.isEmpty {
                    return nil
                }
                else {
                    let range = matchedRanges.first!
                    return paramExpression.substring(from: range.location, length: range.length)
                }
            }
        }
        
        return nil
    }
    
    //--------------------------------------------------------------------------
    func paramName() -> String
    {
        let leftBracketsCount  = [Character](self.filter {$0 == "("}).count
        let rightBracketsCount = [Character](self.filter {$0 == ")"}).count
        
        var toRemoveSet: CharacterSet!
        
        if leftBracketsCount == 1, rightBracketsCount >= leftBracketsCount, let range = self.range(of: ")")?.nsRange {
            toRemoveSet = CharacterSet(charactersIn: " ")
            return self.prefix(range.location + 1).trimmingCharacters(in: toRemoveSet)
        }
        else {
            toRemoveSet = leftBracketsCount == rightBracketsCount ? CharacterSet(charactersIn: " ,{}\"\n") : CharacterSet(charactersIn: " ,){}\"\n")
            return self.trimmingCharacters(in: toRemoveSet)
        }
    }
    
    //--------------------------------------------------------------------------
    func rangesMatching(regexp pattern: String) -> [NSRange]
    {
        guard let regExp = regexOpt(pattern) else {
            return []
        }
        
        let fullRange  = NSRange(location: 0, length: self.count)
        let ranges     = regExp.matches(in: self, options: [], range: fullRange).map {$0.range}
        
        return ranges
    }
    
    //--------------------------------------------------------------------------
    func rvalue(lvalue: String) -> String?
    {
        let ranges = regexOpt("\\s*\(lvalue)\\s*=")?.matches(in: self, options: [], range: NSRange(location: 0, length: self.count)).map {$0.range}
        guard let range = ranges?.first else {
            return nil
        }

        let aux         = String(self.substring(from: range.location + range.length))
        let toRemoveSet = CharacterSet(charactersIn: " ,;){}\"\n")
        let result      = aux.trimmingCharacters(in: toRemoveSet)
        
        return result
    }
    
    //--------------------------------------------------------------------------
    func substringFrom(_ offset: Int, maxLength length: Int? = 0) -> String
    {
        let startOffset = offset < 0 || offset >= self.count ? 0 : offset
        let maxLength   = startOffset + (length ?? 0) < self.count ? (length ?? 0) : self.count - startOffset - 1
        return self.substring(from: startOffset, length: maxLength)
    }
}
