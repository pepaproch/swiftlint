//
//  OWASPAnalyzer.swift
//  SwiftLintFramework
//
//  Created by Vladimír Nevyhoštěný on 29/10/2017.
//  Copyright © 2017 Realm. All rights reserved.
//

import Foundation
import SourceKittenFramework

/**
 * Failable variant of the regex() function.
 */
//------------------------------------------------------------------------------
internal func regexOpt(_ pattern: String, options: NSRegularExpression.Options? = nil) -> NSRegularExpression?
{
    return try? .cached(pattern: pattern, options: options ?? [.anchorsMatchLines, .dotMatchesLineSeparators])
}


//==============================================================================
extension Line
{
    var lineRange: NSRange {
        return NSRange(location: 0, length: self.content.count)
    }
}

//==============================================================================
public class OWASPAnalyzer
{
    static let methodCallKinds: Set<SwiftDeclarationKind> = [.functionFree, .functionConstructor, .functionDestructor, .functionMethodStatic, .functionMethodClass, .functionMethodInstance]
    static let passphrasePatterns: Set<String>            = ["password", "pwd", "heslo", "passwort", "passphrase"]
    static let stripParamCharSet                          = CharacterSet(charactersIn: " ,){}\"\n")
    static let lintSyncQueue                              = DispatchQueue(label: "cz.owaspAnalyzer.sync", qos: .userInitiated)
    
    public private (set) var lines:                      [Line]
    public private (set) var comments:                   [Line]
    public private (set) var dictionary:                 [String: SourceKitRepresentable]
    public private (set) var structure:                  Structure
    
    private static var scannedFiles: Set<String>       = Set<String>()
    
    //--------------------------------------------------------------------------
    init(lines: [Line], dictionary: [String: SourceKitRepresentable]? = nil)
    {
        self.lines      = lines
        
        if let dictionary = dictionary {
            self.dictionary = dictionary
        }
        else {
            self.dictionary = [String: SourceKitRepresentable]()
        }
        self.structure  = Structure(sourceKitResponse: self.dictionary)
        
        self.comments   = [Line]()
        
        self.parse()
    }
/*
    //--------------------------------------------------------------------------
    init(contents: String)
    {
        self.dictionary = [String: SourceKitRepresentable]()
        self.structure  = Structure(sourceKitResponse: self.dictionary)
        Line
        self.lines      = contents.components(separatedBy: "\n")
        self.comments   = [Line]()
    }
*/
    //---------------------------------------------------------------------------
    private func parse()
    {
        var isComment      = false
        
        for line in lines {
            let rawString = line.content.trimmingCharacters(in: .whitespacesAndNewlines)
            
            if rawString.hasPrefix("//") && !isComment {
                self.comments.append(line)
            }
            if rawString.hasPrefix("/*") {
                isComment = true
            }
            if rawString.hasPrefix("*/") {
                self.comments.append(line)
                isComment = false
            }
            if isComment {
                self.comments.append(line)
            }
        }
    }
    
    //--------------------------------------------------------------------------
    func isComment(line: Line) -> Bool
    {
        return !self.comments.filter {$0.index == line.index}.isEmpty
    }
    
    //--------------------------------------------------------------------------
    func lines(before line: Line, includeComments: Bool = false) -> [Line]?
    {
        return includeComments ? self.lines.filter {$0.index < line.index} : self.lines.filter {$0.index < line.index && !self.isComment(line: $0)}
    }
    
    //--------------------------------------------------------------------------
    func lines(matching pattern: String, dictionary: [String: SourceKitRepresentable]? = nil) -> [Line]
    {
        var result       = [Line]()
        let regExp       = regex(pattern)
        
        var searchDictionary: [String: SourceKitRepresentable]?
        if let dictionary = dictionary {
            searchDictionary = dictionary
        }
        else {
            if !self.dictionary.isEmpty {
                searchDictionary = self.dictionary
            }
        }
        
        var linesForScan: [Line]?
        if let dictionary = searchDictionary, let startLocation = dictionary.bodyOffset, let length = dictionary.bodyLength {
            let endLocation = startLocation + length
            linesForScan    = self.lines.filter {$0.range.location >= startLocation && $0.range.location <= endLocation}
        }
        else {
            linesForScan = self.lines
        }
        
        for line in linesForScan! {
            let statementRange       = NSRange(location: 0, length: line.content.count)
            let ranges               = regExp.matches(in: line.content, options: [], range: statementRange).map {$0.range}
            if !ranges.isEmpty {
                result.append(line)
            }
        }
        
        return result
    }
    
    //--------------------------------------------------------------------------
    public func lines(excludeLine line: Line? = nil, forLvalue lvalue: String, includeComments: Bool = false) -> [Line]
    {
        var results      = [Line]()
        let regParam     = "\\s*\(lvalue)\\s*="
        
        guard let regexp = regexOpt(regParam) else {
            print("Wrong regex parameter: \(regParam)")
            return results
        }
        
        let matchedLines  = self.lines.filter {!regexp.matches(in: $0.content, options: [], range: NSRange(location: 0, length: $0.content.count)).isEmpty && (line == nil || (line != nil &&  $0.range.location != line!.range.location)) && (includeComments || (!includeComments && !self.isComment(line: $0)))}
        
        for line in matchedLines {
            if let _ = line.content.rvalue(lvalue: lvalue) {
                results.append(line)
            }
        }
        
        return results
    }
    
    //--------------------------------------------------------------------------
    func lineAt(location: Int) -> Line?
    {
        for line in self.lines {
            if line.range.contains(location) {
                return line
            }
        }
        return nil
    }
    
    //--------------------------------------------------------------------------
    public func lines(forDictionary dictionary: [String: SourceKitRepresentable]) -> [Line]
    {
        guard let startLocation = dictionary.offset,
              let length        = dictionary.length else {
                return []
        }
        let endLocation = startLocation + length
        return self.lines.filter {$0.byteRange.location >= startLocation && $0.byteRange.location <= endLocation}
    }
    
    
    //--------------------------------------------------------------------------
    func isParameterModified(_ parameter: String, onLine line: Line) -> Bool
    {
        if self.isComment(line: line) {
            return false
        }
        
        // Paramater has method
        
        if (regexOpt("\(parameter)\\s*.")?.numberOfMatches(in: line.content, options: [], range: line.lineRange) ?? 0) >= 1 {
            return true
        }
        
        // Parameter is used in expression
        
        if (regexOpt("\(parameter)\\s*=\\s*.*(.*)")?.numberOfMatches(in: line.content, options: [], range: line.lineRange) ?? 0 ) >= 1 {
            return true
        }
        
        // Parameter is inout ...
        
        if (regexOpt("\\s*&\(parameter)")?.numberOfMatches(in: line.content, options: [], range: line.lineRange) ?? 0 ) >= 1 {
            return true
        }
        
        if (regexOpt("\\s*\(parameter)\\s*in\\s*.*")?.numberOfMatches(in: line.content, options: [], range: line.lineRange) ?? 0 ) >= 1 {
            return true
        }
        
        return false
    }
    
    //--------------------------------------------------------------------------
    func linesBetween(lines: [Line], topPattern: String, bottomPattern: String) -> [Line]
    {
        var result  = [Line]()
        var addLine = false
        
        lines.forEach {
            if addLine {
                if $0.content.contains(bottomPattern) {
                    addLine = false
                }
                result.append($0)
            }
            else {
                if $0.content.contains(topPattern) {
                    addLine = true
                    result.append($0)
                }
            }
        }
        
        return result
    }
    
    //--------------------------------------------------------------------------
    class func rvalue(withLvalue lvalue: String, inLine line: Line) -> (NSRange, String)?
    {
        return OWASPAnalyzer.rvalueInternal(parameter: lvalue, regexp: "(?<=\\=)\\s*.[[:alnum:]]*", line: line)
    }
    
    //--------------------------------------------------------------------------
    class func rvalue(withParameter parameter: String, inLine line: Line) -> (NSRange, String)?
    {
        return OWASPAnalyzer.rvalueInternal(parameter: parameter, regexp: "\\s*[[:alnum:]]*[^\\,\\ \\:\\s\\+\\-\\*\\/)]", line: line)
    }
    
    //--------------------------------------------------------------------------
    class func firstScanOf(fileName: String?, forRule rule: String) -> Bool
    {
        guard let fileName = fileName else {
            return false // We won't scan undefined source file.
        }
        
        let pattern = "\(rule):\(fileName)"
        if OWASPAnalyzer.scannedFiles.contains(pattern) {
            return false
        }
        OWASPAnalyzer.scannedFiles.insert(pattern)
        return true
    }
    
    //--------------------------------------------------------------------------
    private class func rvalueInternal(parameter: String, regexp: String, line: Line) -> (NSRange, String)?
    {
        if let lvalueRange = regex(parameter.regexp).firstMatch(in: line.content, options: [], range: NSRange(location: 0, length: line.content.count))?.range {
            let rvalueSubstring = line.content.substring(from: lvalueRange.location + lvalueRange.length)
            if let rvalueRange  = regex(regexp).firstMatch(in: rvalueSubstring, options: [], range: NSRange(location: 0, length: rvalueSubstring.count))?.range {
                let auxRange      = NSRange(location: lvalueRange.location + lvalueRange.length + rvalueRange.location, length: rvalueRange.length)
                let toRemoveSet   = CharacterSet(charactersIn: " ,){}\"\n")
                let rvalueLiteral = line.content.substring(from: auxRange.location, length: auxRange.length).trimmingCharacters(in: toRemoveSet)
                if let rvalueExactRange = line.content.range(of: rvalueLiteral)?.nsRange {
                    return (NSRange(location: line.range.location + rvalueExactRange.location, length: rvalueExactRange.length - 1), rvalueLiteral)
                }
            }
        }
        return nil
    }

}
