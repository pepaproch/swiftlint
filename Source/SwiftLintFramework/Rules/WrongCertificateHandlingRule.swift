//
//  WrongCertificateHandlingRule.swift
//  SwiftLintFramework
//
//  Created by Vladimír Nevyhoštěný on 13/11/2017.
//  Copyright © 2017 Realm. All rights reserved.
//

import Foundation
import SourceKittenFramework

//==============================================================================
public struct WrongCertificateHandlingRule: ASTRule, ConfigurationProviderRule
{
    public var configuration = SeverityConfiguration(.warning)
    
    //--------------------------------------------------------------------------
    public init() {}
    
    public static let description = RuleDescription(
        identifier:   "wrong_certificate_handling",
        name:         "Certificate Handling",
        description:  "Certificate handling vulnerability.",
        kind: .vulnerability,
        nonTriggeringExamples: [
            "let trusted = err == errSecSuccess && trustResult == SecTrustResultType.unspecified"
        ],
        triggeringExamples: [
            "let disposition = URLSession.AuthChallengeDisposition.↓useCredential"
        ]
    )
    
    //--------------------------------------------------------------------------
    public func validate(file: File, kind: SwiftDeclarationKind, dictionary: [String: SourceKitRepresentable]) -> [StyleViolation]
    {
        var ranges = [NSRange]()

        // Take only method calls ...
        
        guard OWASPAnalyzer.methodCallKinds.contains(kind) else {
            return []
        }
        
        let analyzer        = OWASPAnalyzer(lines: file.lines, dictionary: dictionary)
        let bodyLines       = analyzer.lines(forDictionary: dictionary)
        
        let structure       = Structure(sourceKitResponse: dictionary)
        let methodCalls     = structure.calls(ofMethodName: "completionHandler")
        
        for methodCall in methodCalls {
            let arguments = structure.arguments(ofFunction: methodCall)
            
            // Take the 2nd parameter, `credential`
            if arguments.count == 2, let credentialArgument = arguments.last, let argOffset = credentialArgument.bodyOffset, let argLength = credentialArgument.bodyLength {
                let matchedLines = bodyLines.filter {$0.byteRange.location < argOffset && $0.byteRange.location + $0.byteRange.length > argOffset}
                if !matchedLines.isEmpty, let matchedLine = matchedLines.first {
                    let credentialParamName = matchedLine.content.substring(from: argOffset - matchedLine.byteRange.location, length: argLength).paramName()
                    
                    let assignedLines  = analyzer.lines(excludeLine: matchedLine, forLvalue: credentialParamName)
                    
                    let vulnerableRegex = regex("URLCredential\\s*\\(\\s*trust:\\s*.*\\.protectionSpace\\.serverTrust.*\\)")
                    for line in assignedLines {
                        let vulnerableRanges = vulnerableRegex.matches(in: line.content, options: [], range: NSRange(location: 0, length: line.content.count)).map {$0.range}
                        if !vulnerableRanges.isEmpty, let range = vulnerableRanges.first {
                            ranges.append(line.align(NSRange(location: line.range.location + range.location, length: range.length)))
                        }
                    }
                }
            }
        }
        
        

        return ranges.map {
            StyleViolation(ruleDescription: type(of: self).description,
                           severity:        configuration.severity,
                           location:        Location(file: file, characterOffset: $0.location),
                           endLocation:     Location(file: file, characterOffset: $0.location + $0.length)
            )
        }
    }
}

