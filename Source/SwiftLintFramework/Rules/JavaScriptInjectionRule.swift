//
//  JavaScriptInjectionRule.swift
//  SwiftLintFramework
//
//  Created by Vladimír Nevyhoštěný on 31/10/2017.
//  Copyright © 2017 Realm. All rights reserved.
//

import Foundation
import SourceKittenFramework

//==============================================================================
public struct JavaScriptInjectionRule: ASTRule, ConfigurationProviderRule
{
    public var configuration = SeverityConfiguration(.warning)
    
    //--------------------------------------------------------------------------
    public init() {}
    
    public static let description = RuleDescription(
        identifier:  "javascript_injection",
        name:        "JavaScript Injection",
        description: "JavaScript injection vulnerability. Consider the necessity of JavaScript usage.",
        kind:        .vulnerability,
        nonTriggeringExamples: [
            "config.preferences.javaScriptEnabled = false"
        ],
        triggeringExamples: [
            "config.preferences.javaScriptEnabled = ↓true"
        ]
    )
    
    
    
    //--------------------------------------------------------------------------
    public func validate(file: File, kind: SwiftDeclarationKind, dictionary: [String: SourceKitRepresentable]) -> [StyleViolation]
    {
        var ranges = [NSRange]()

        ranges.append(contentsOf: self.searchForSuspiciousAttributes(file: file, kind: kind, dictionary: dictionary))
        ranges.append(contentsOf: self.searchForUnsanitizedJavascriptExecution(file: file, kind: kind, dictionary: dictionary))
        
        return ranges.map {
            StyleViolation(ruleDescription: type(of: self).description,
                           severity:        configuration.severity,
                           location:        Location(file: file, characterOffset: $0.location),
                           endLocation:     Location(file: file, characterOffset: $0.location + $0.length)
                           )
        }
    }
    
    static let suspiciousAttributes  = ["preferences.javaScriptEnabled",
                                        "preferences.javaScriptCanOpenWindowsAutomatically"
    ]
    
    //--------------------------------------------------------------------------
    func searchForSuspiciousAttributes(file: File, kind: SwiftDeclarationKind, dictionary: [String: SourceKitRepresentable]) -> [NSRange]
    {
        var ranges = [NSRange]()
        //print(dictionary)
        for suspiciousAttribute in type(of: self).suspiciousAttributes {
            let lines = file.lines.filter {$0.content.contains(suspiciousAttribute)}
            for line in lines {
                if let rvalue = line.content.rvalue(lvalue: suspiciousAttribute), let range = line.content.range(of: rvalue)?.nsRange {
                    if rvalue.contains("true") {
                        ranges.append(line.align(NSRange(location: line.range.location + range.location, length: rvalue.count)))
                    }
                    else if rvalue.contains("false") {
                        // OK here, because the suspiciousAttribute is disabled by constant.
                    }
                    else {
                        let analyzer      = OWASPAnalyzer(lines: file.lines)
                        let assignedLines = analyzer.lines(excludeLine: line, forLvalue: rvalue)
                        
                        if assignedLines.count == 1, assignedLines [0].content.contains("false") {
                            // OK here, the suspiciousAttribute is disabled by variable.
                        }
                        else {
                            // No reliable info about the suspiciousAttribute lvalue here.
                            let regexp = regex("(?<=\\=).*$")
                            for line in assignedLines {
                                let rvalueRanges = regexp.matches(in: line.content, options: [], range: NSRange(location: 0, length: line.content.count)).map {$0.range}
                                if !rvalueRanges.isEmpty, let rvalueRange = rvalueRanges.first {
                                    let rvalue = line.content.substring(from: rvalueRange.location, length: rvalueRange.length).trimmingCharacters(in: .whitespacesAndNewlines)
                                    if rvalue != "false", let rvalueExactRange = line.content.range(of: rvalue)?.nsRange {
                                        ranges.append(line.align(NSRange(location: line.range.location + rvalueExactRange.location, length: rvalueExactRange.length)))
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
        
        return ranges
    }
    
    //--------------------------------------------------------------------------
    func searchForUnsanitizedJavascriptExecution(file: File, kind: SwiftDeclarationKind, dictionary: [String: SourceKitRepresentable]) -> [NSRange]
    {
        // Take only method calls ...
        
        guard OWASPAnalyzer.methodCallKinds.contains(kind) else {
            return []
        }
        
        var ranges          = [NSRange]()
        
        let analyzer        = OWASPAnalyzer(lines: file.lines, dictionary: dictionary)
        let bodyLines       = analyzer.lines(forDictionary: dictionary)
        
        let structure       = Structure(sourceKitResponse: dictionary)
        let methodCalls     = structure.calls(ofMethodName: "stringByEvaluatingJavaScript")
        
        for methodCall in methodCalls {
            let arguments = structure.arguments(ofFunction: methodCall)
            
            // Take the 1st parameter, `from`
            if arguments.count == 1, let javascriptArgument = arguments.last, let argOffset = javascriptArgument.bodyOffset, let argLength = javascriptArgument.bodyLength {
                let matchedLines = bodyLines.filter {$0.byteRange.location < argOffset && $0.byteRange.location + $0.byteRange.length > argOffset}
                if !matchedLines.isEmpty, let matchedLine = matchedLines.first {
                    let javascriptParamName = matchedLine.content.substring(from: argOffset - matchedLine.byteRange.location, length: argLength).paramName()
                    let assignedLines       = analyzer.lines(excludeLine: matchedLine, forLvalue: javascriptParamName)
                    
                    var isParameterModified = false
                    for line in assignedLines {
                            if analyzer.isParameterModified(javascriptParamName, onLine: line) {
                                isParameterModified = true
                                break
                            }
                    }
                    
                    if !isParameterModified, let lineRange = matchedLine.content.range(of: javascriptParamName)?.nsRange {
                        // An unmodified JavaScript in this statement may be evil!
                        ranges.append(matchedLine.align(NSRange(location: matchedLine.range.location + lineRange.location, length: javascriptParamName.count - 1)))
                    }
                }
            }
        }
        
        return ranges
    }
}

