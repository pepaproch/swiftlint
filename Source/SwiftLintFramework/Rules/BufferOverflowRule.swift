//
//  BufferOverflowRule.swift
//  SwiftLintFramework
//
//  Created by Vladimír Nevyhoštěný on 06/11/2017.
//  Copyright © 2017 Realm. All rights reserved.
//

import Foundation
import SourceKittenFramework

//==============================================================================
public struct BufferOverflowRule: ASTRule, ConfigurationProviderRule
{
    public var configuration = SeverityConfiguration(.warning)
    
    //--------------------------------------------------------------------------
    public init() {}
    
    public static let description = RuleDescription(
        identifier:  "buffer_overflow",
        name:        "Buffer Overflow",
        description: "Buffer overflow vulnerability.",
        kind:        .vulnerability,
        nonTriggeringExamples: [
            ".allocate(bytes: MemoryLayout"
        ],
        triggeringExamples: [
            ".allocate(bytes: ↓100"
        ]
    )
    
    static let vulnerablePatterns  = [".allocate(bytes:",
                                      ".allocate(capacity:",
                                     ]
    static let safeMemoryAllocator = "MemoryLayout"
    
    //--------------------------------------------------------------------------
    public func validate(file: File, kind: SwiftDeclarationKind, dictionary: [String: SourceKitRepresentable]) -> [StyleViolation]
    {
        var ranges   = [NSRange]()
        
        guard OWASPAnalyzer.methodCallKinds.contains(kind) else {
            return []
        }
        
        let analyzer = OWASPAnalyzer(lines: file.lines, dictionary: dictionary)
        
        for pattern in type(of: self).vulnerablePatterns {
            
            let lines = analyzer.lines(matching: pattern.regexp)
            guard !lines.isEmpty else {
                continue
            }
            
            let paramLabel   = pattern.substringBetween("(",":")
            
            for matchedLine in lines {
                // Search for param name by param label
                guard let paramName = matchedLine.content.paramName(labelName: paramLabel), !paramName.contains(type(of: self).safeMemoryAllocator) else {
                    continue
                }
                
                // We need to look for parameter assigment.
                
                let assignedLines            = analyzer.lines(forDictionary: dictionary).matching(lvalue: paramName)
                var foundSafeMemoryAllocator = false
                
                // Look, if the safe memory allocator is defined before memory allocation call.
                
                for line in assignedLines {
                    if analyzer.isComment(line: line) {
                        continue
                    }
                    
                    if line.index >= matchedLine.index {
                        break
                    }
                    
                    if line.content.contains(type(of: self).safeMemoryAllocator) {
                        foundSafeMemoryAllocator = true
                        break
                    }
                }
                
                if !foundSafeMemoryAllocator, let (range, _) = OWASPAnalyzer.rvalue(withParameter: pattern, inLine: matchedLine) {
                    ranges.append(matchedLine.align(range))
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
