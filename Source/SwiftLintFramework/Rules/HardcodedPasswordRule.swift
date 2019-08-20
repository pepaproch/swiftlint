//
//  HardcodedPasswordRule.swift
//  SwiftLintFramework
//
//  Created by Vladimír Nevyhoštěný on 15/11/2017.
//  Copyright © 2017 Realm. All rights reserved.
//

import Foundation
import SourceKittenFramework

//==============================================================================
public struct HardcodedPasswordRule: ASTRule, ConfigurationProviderRule
{
    public var configuration = SeverityConfiguration(.warning)
    
    //--------------------------------------------------------------------------
    public init() {}
    
    public static let description = RuleDescription(
        identifier:   "hardcoded_passwords",
        name:         "Hardcoded passwords",
        description:  "Hardcoded password vulnerability.",
        kind: .vulnerability,
        nonTriggeringExamples: [
            "let foo = Crypto(password: cryptoPassword)"
        ],
        triggeringExamples: [
            "let foo = Crypto(password: ↓\"passw0rd\")"
        ]
    )
    
    //--------------------------------------------------------------------------
    public func validate(file: File, kind: SwiftDeclarationKind, dictionary: [String: SourceKitRepresentable]) -> [StyleViolation]
    {
        var ranges = [NSRange]()
        
        let group  = DispatchGroup()
        group.enter()
        
        self.lintOnce(file: file, ruleName: type(of: self).description.identifier) { shouldProceed in
            
            guard shouldProceed else {
                group.leave()
                return
            }
            
            // Search for rvalues with quotes ...
            
            for line in file.lines {
                for pattern in OWASPAnalyzer.passphrasePatterns {
                    let matchedRanges = regex("\(pattern)\\s*[:]\\s*\"([^\"]+)\"").matches(in: line.content.lowercased(), options: [], range: NSRange(location: 0, length: line.content.count)).map {$0.range}
                    if !matchedRanges.isEmpty, let matchedRange = matchedRanges.first {
                        let matchedSubstring = line.content.substring(from: matchedRange.location, length: matchedRange.length).trimmingCharacters(in: OWASPAnalyzer.stripParamCharSet)
                        ranges.append(line.align(NSRange(location: line.range.location + matchedRange.location, length: matchedSubstring.count)))
                    }
                }
            }
            
            // Search for lvalues assigned by hardcoded rvalues ...
            
            let analyzer = OWASPAnalyzer(lines: file.lines)
            for pattern in OWASPAnalyzer.passphrasePatterns {
                
                // Search for pattern like `let password = "passw0rd"`
                
                for line in file.lines {
                    guard let paramName = line.content.paramName(labelName: pattern) else {
                        continue
                    }
                    
                    let regexp        = regex("\(paramName)\\s*=\\s*\\\".*\\\"")
                    let assignedLines = analyzer.lines(excludeLine: line, forLvalue: paramName)
                    
                    for assignedLine in assignedLines {
                        if analyzer.isComment(line: assignedLine) {
                            continue
                        }
                        
                        if assignedLine.index >= line.index {
                            break
                        }
                        
                        if let range = regexp.firstMatch(in: assignedLine.content, options: [], range: NSRange(location: 0, length: assignedLine.content.count))?.range {
                            ranges.append(assignedLine.align(NSRange(location: assignedLine.range.location + range.location, length: range.length - 1)))
                        }
                    }
                }
            }
            
            group.leave()
        }
        
        group.wait()
        
        return ranges.map {
            StyleViolation(ruleDescription: type(of: self).description,
                           severity:        self.configuration.severity,
                           location:        Location(file: file, characterOffset: $0.location),
                           endLocation:     Location(file: file, characterOffset: $0.location + $0.length)
            )
        }
    }
}

