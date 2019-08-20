//
//  SqlInjectionRule.swift
//  SwiftLintFramework
//
//  Created by Vladimír Nevyhoštěný on 07/11/2017.
//  Copyright © 2017 Realm. All rights reserved.
//

import Foundation
import SourceKittenFramework

private let lastName = "DOE"

//==============================================================================
public struct SqlInjectionRule: ASTRule, ConfigurationProviderRule
{
    public var configuration = SeverityConfiguration(.warning)
    
    //--------------------------------------------------------------------------
    public init() {}
    
    public static let description = RuleDescription(
        identifier:  "sql_injection",
        name:        "SQL Injection",
        description: "SQL injection vulnerability.",
        kind:        .vulnerability,
        nonTriggeringExamples: [
            "select * from USERS where FIRST_NAME || ' ' || LAST_NAME = ?"
        ],
        triggeringExamples: [
            "select * from USERS where FIRST_NAME || ' ' || LAST_NAME = \(lastName)",
            "select * from USERS where FIRST_NAME || ' ' || LAST_NAME = %@"
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
            
            // Scan for vulnerable interpolation pattern `select ... where column = \(columnValue)`
            
            let selectWhereInterpolationRegex      = regex("\\\"\\s*select\\s*.*where\\s*.*\\\\\\(.*\\)\\s*")
            let vulnerableWhereInterpolationRegex  = regex("where\\s*.*\\\\\\(.*\\)")
            let vulnerableParamInterpolationRegex  = regex("\\\\\\(.*\\)")
            
            let sqlInterpolationLines              = file.lines.filter {!selectWhereInterpolationRegex.matches(in: $0.content.lowercased(), options: [], range: NSRange(location: 0, length: $0.content.count)).isEmpty}
            for line in sqlInterpolationLines {
                let whereRanges = vulnerableWhereInterpolationRegex.matches(in: line.content.lowercased(), options: [], range: NSRange(location: 0, length: line.content.count)).map {$0.range}
                
                guard !whereRanges.isEmpty, let whereRange = whereRanges.first else {
                    continue
                }
                
                let whereSubstring = line.content.substring(from: whereRange.location)
                let paramRanges    = vulnerableParamInterpolationRegex.matches(in: whereSubstring, options: [], range: NSRange(location: 0, length: whereSubstring.count)).map {$0.range}
                
                for paramRange in paramRanges {
                    ranges.append(line.align(NSRange(location: line.range.location + whereRange.location + paramRange.location, length: paramRange.length)))
                }
            }
            
            // Scan for vulnerable format pattern `select ... where column = %@`
            
            let selectWhereFormatRegex      = regex("\\\"\\s*select\\s*.*where\\s*.*\\s*\\%\\@")
            let vulnerableWhereFormatRegex  = regex("where\\s*.*\\s*\\%\\@")
            let vulnerableParamFormatRegex  = regex("\\%\\@")
            
            let sqlFormatLines              = file.lines.filter {!selectWhereFormatRegex.matches(in: $0.content.lowercased(), options: [], range: NSRange(location: 0, length: $0.content.count)).isEmpty}
            for line in sqlFormatLines {
                let whereRanges = vulnerableWhereFormatRegex.matches(in: line.content.lowercased(), options: [], range: NSRange(location: 0, length: line.content.count)).map {$0.range}
                
                guard !whereRanges.isEmpty, let whereRange = whereRanges.first else {
                    continue
                }
                
                let whereSubstring = line.content.substring(from: whereRange.location)
                let paramRanges    = vulnerableParamFormatRegex.matches(in: whereSubstring, options: [], range: NSRange(location: 0, length: whereSubstring.count)).map {$0.range}
                
                for paramRange in paramRanges {
                    ranges.append(line.align(NSRange(location: line.range.location + whereRange.location + paramRange.location, length: paramRange.length - 1)))
                }
            }
            
            // Search for vulnerable NSPredicate pattern like `NSPredicate(format: "name like %@", name)`
            
            let vulnerablePredicateLikeRegex = regex("nspredicate\\s*\\(.*like\\s*%@\\s*.*\\)")
            let predicateLikeLines           = file.lines.filter {!vulnerablePredicateLikeRegex.matches(in: $0.content.lowercased(), options: [], range: NSRange(location: 0, length: $0.content.count)).isEmpty}
            for line in predicateLikeLines {
                guard let startRange = vulnerablePredicateLikeRegex.firstMatch(in: line.content.lowercased(), options: [], range: NSRange(location: 0, length: line.content.count)) else {
                    continue
                }
                ranges.append(line.align(NSRange(location: line.range.location + startRange.range.location, length: startRange.range.length - 1)))
            }
            
            // Search for vulnerable NSPredicate pattern like `NSPredicate(format: "name = %@", name)`
            
            let vulnerablePredicateEqRegex = regex("nspredicate\\s*\\(.*=\\s*%@")
            let predicateEqLines           = file.lines.filter {!vulnerablePredicateEqRegex.matches(in: $0.content.lowercased(), options: [], range: NSRange(location: 0, length: $0.content.count)).isEmpty}
            for line in predicateEqLines {
                guard let startRange = vulnerablePredicateEqRegex.firstMatch(in: line.content.lowercased(), options: [], range: NSRange(location: 0, length: line.content.count)) else {
                    continue
                }
                ranges.append(line.align(NSRange(location: line.range.location + startRange.range.location, length: line.content.count - startRange.range.length - 1)))
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
