//
//  FormatStringRule.swift
//  SwiftLintFramework
//
//  Created by Vladimír Nevyhoštěný on 22/11/2017.
//  Copyright © 2017 Realm. All rights reserved.
//

import Foundation
import SourceKittenFramework

//==============================================================================
public struct FormatStringRule: ASTRule, ConfigurationProviderRule
{
    public var configuration = SeverityConfiguration(.warning)
    
    //--------------------------------------------------------------------------
    public init() {}
    
    public static let description = RuleDescription(
        identifier:   "format_vulnerability",
        name:         "Format Vulnerability",
        description:  "Format vulnerability.",
        kind: .vulnerability,
        nonTriggeringExamples: [
            "String(format: \"Number: %d\", 1)"
        ],
        triggeringExamples: [
            "String(format: ↓stringParameter)"
        ]
    )
    static let safeExpressions        = [["format\\s*:\\s*\\\".*\\\"\\s*",                 // Matches String(format: "Number: %d", 1)
                                          "format\\s*:\\s*nil"                             // Matches format: nil
                                         ],
                                         ["NSLog\\s*\\(\\s*\\\".*\\\"\\s*,\\s*.*\\)"],     // Matches NSLog("%d", 1)
                                         ["[a-zA-Z_]*[F|f]ormat\\s*\\(\\s*\\\".*\\\"\\s*"] // Matches CFStringWithFormat("formatValue")
                                        ]
    static let vulnerableExpressions  = ["format\\s*:\\s*[a-zA-Z0-9_]*",                   // Matches String(format: parameter)
                                         "NSLog\\s*\\([^\"]*\\s*\\)",                      // Matches NSLog(message)
                                         "[a-zA-Z_]*[F|f]ormat\\s*\\([^\\\"]*\\s*\\)"      // Matches CFStringWithFormat(formatValue)
                                        ]
    
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
            
            let analyzer = OWASPAnalyzer(lines: file.lines, dictionary: dictionary)
            
            for (index, vulnerableExpression) in type(of: self).vulnerableExpressions.enumerated() {
                
                let vulnerableRegex = regex(vulnerableExpression)
                
                for line in file.lines {
                    
                    if analyzer.isComment(line: line) {
                        continue
                    }
                    
                    if let range = vulnerableRegex.firstMatch(in: line.content, options: [], range: NSRange(location: 0, length: line.content.count))?.range {
                        // Just to be sure, search for safe pattern on this line ...
                        var foundSafePattern = false
                        for safePattern in type(of: self).safeExpressions [index] {
                            if !regex(safePattern).matches(in: line.content, options: [], range: NSRange(location: 0, length: line.content.count)).isEmpty {
                                foundSafePattern = true
                                break
                            }
                        }
                        if !foundSafePattern {
                            // Mark vulnerability only when no safe expression found on this line!
                            ranges.append(line.align(NSRange(location: line.range.location + range.location, length: range.length - 1)))
                        }
                    }
                }
            }
            
            group.leave()
        }
        
        group.wait()
        
        return ranges.map {
            StyleViolation(ruleDescription: type(of: self).description,
                           severity:        configuration.severity,
                           location:        Location(file: file, characterOffset: $0.location),
                           endLocation:     Location(file: file, characterOffset: $0.location + $0.length)
            )
        }
    }
}
