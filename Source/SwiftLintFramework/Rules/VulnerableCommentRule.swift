//
//  VulnerableCommentRule.swift
//  SwiftLintFramework
//
//  Created by Vladimír Nevyhoštěný on 15/11/2017.
//  Copyright © 2017 Realm. All rights reserved.
//

import Foundation
import SourceKittenFramework

//==============================================================================
public struct VulnerableCommentRule: ASTRule, ConfigurationProviderRule
{
    public var configuration = SeverityConfiguration(.warning)
    
    //--------------------------------------------------------------------------
    public init() {}
    
    public static let description = RuleDescription(
        identifier:   "vulnerable_comment",
        name:         "Vulnerable Comment",
        description:  "Comments vulnerability.",
        kind: .vulnerability,
        nonTriggeringExamples: [
            "// Some comment."
        ],
        triggeringExamples: [
            "// login = \"John Doe\", password = ↓\"passw0rd\""
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
            
            let analyzer        = OWASPAnalyzer(lines: file.lines, dictionary: dictionary)
            let comments        = analyzer.comments
            
            for comment in comments {
                let commentText = comment.content.lowercased()
                for pattern in OWASPAnalyzer.passphrasePatterns {
                    ranges.append(contentsOf: regex("\(pattern)").matches(in: commentText, options: [], range: NSRange(location: 0, length: commentText.count)).map {comment.align(NSRange(location: comment.range.location + $0.range.location, length: $0.range.length - 1))})
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

