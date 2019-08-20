//
//  EmptyCatchRule.swift
//  SwiftLintFramework
//
//  Created by Vladimír Nevyhoštěný on 29/11/2017.
//  Copyright © 2017 Realm. All rights reserved.
//

import Foundation
import SourceKittenFramework

//==============================================================================
public struct EmptyCatchRule: ASTRule, ConfigurationProviderRule
{
    public var configuration = SeverityConfiguration(.warning)
    
    //--------------------------------------------------------------------------
    public init() {}
    
    public static let description = RuleDescription(
        identifier:   "empty_catch",
        name:         "Empty Catch",
        description:  "Empty catch block.",
        kind: .vulnerability,
        nonTriggeringExamples: [
            "catch let error {\n\tprint(\"Error: \\(error)\")\n}"
        ],
        triggeringExamples: [
            "↓catch let error {\n}"
        ]
    )
    
    //--------------------------------------------------------------------------
    public func validate(file: File, kind: SwiftDeclarationKind, dictionary: [String: SourceKitRepresentable]) -> [StyleViolation]
    {
        var ranges = [NSRange]()
        
        let analyzer = OWASPAnalyzer(lines: file.lines)
        let group    = DispatchGroup()
        group.enter()
        
        self.lintOnce(file: file, ruleName: type(of: self).description.identifier) { shouldProceed in
            
            guard shouldProceed else {
                group.leave()
                return
            }
            
            let contents       = file.contents
            var startIndex     = 0
            
            while true {
                guard let catchRange = regex("catch\\s*.*\\s*\\{").firstMatch(in: contents, options: [], range: NSRange(location: startIndex, length: contents.count - startIndex))?.range,
                      let braceRange = contents.range(of: "}", options: [], range: Range(NSRange(location: catchRange.location, length: contents.count - catchRange.location - 1), in: contents))?.nsRange
                else {
                    break
                }
                
                let range = NSRange(location: catchRange.location, length: braceRange.location - catchRange.location + braceRange.length)
                
                // Skip commented blocks of code ...
                
                guard let firstLine  = analyzer.lineAt(location: range.location) else {
                    startIndex = range.location + range.length
                    continue
                }
                
                if analyzer.isComment(line: firstLine) {
                    startIndex = firstLine.range.location + firstLine.range.length
                    continue
                }
                
                guard let lastLine   = analyzer.lineAt(location: range.location + range.length) else {
                    startIndex = range.location + range.length
                    continue
                }
                
                // Extract commented lines content from block ...
                
                var uncommentedCatchBlock = String()
                for line in file.lines [(firstLine.index - 1)..<lastLine.index] {
                    if !analyzer.isComment(line: line) {
                        uncommentedCatchBlock += line.content.trimmingCharacters(in: .whitespacesAndNewlines)
                    }
                }
                
                // Do we have an empty catch block like `catch {}` now?
                
                if uncommentedCatchBlock.contains("{}") {
                    ranges.append(NSRange(location: range.location, length: range.length - 1))
                }
                
                startIndex = range.location + range.length
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

