//
//  PathTraversalRule.swift
//  SwiftLintFramework
//
//  Created by Vladimír Nevyhoštěný on 11/10/2017.
//  Copyright © 2017 Realm. All rights reserved.
//

import SourceKittenFramework

//==============================================================================
public struct PathTraversalRule: ASTRule, ConfigurationProviderRule
{
    public var configuration = SeverityConfiguration(.warning)
    
    //--------------------------------------------------------------------------
    public init() {}
    
    public static let description = RuleDescription(
        identifier:  "path_traversal",
        name:        "Path Traversal",
        description: "Possible path traversal vulnerability. Check file path sanitation.",
        kind:        .vulnerability,
        nonTriggeringExamples: [
            "let path = \"\\(pathEntry)\""
        ],
        triggeringExamples: [
            "let path = \"↓../\\(pathEntry)\"",
            "let path = \"↓../\" + \"\\(pathEntry)\""
        ]
    )
    
    static let vulnerablePatterns = [
        "URL(fileURLWithPath:",
        "contents(atPath:",
        "contentsOfDirectory(atPath:",
        "createFile(atPath:",
        "init?(forReadingAtPath:",
        "init(forReadingFrom:",
        "init(forWritingTo:",
        "init?(forUpdatingAtPath:",
        "init(forUpdating:"
    ]
    
    //--------------------------------------------------------------------------
    public func validate(file: File, kind: SwiftDeclarationKind, dictionary: [String: SourceKitRepresentable]) -> [StyleViolation]
    {
        guard SwiftDeclarationKind.functionKinds.contains(kind),
            let bodyOffset            = dictionary.bodyOffset,
            let bodyLength            = dictionary.bodyLength,
            case let contentsNSString = file.contents.bridge(),
            let startLine             = contentsNSString.lineAndCharacter(forByteOffset: bodyOffset)?.line,
            let endLine               = contentsNSString.lineAndCharacter(forByteOffset: bodyOffset + bodyLength)?.line
            else {
                return []
        }
        
        let analyzer      = OWASPAnalyzer(lines: contentsNSString.lines().filter {$0.index >= startLine && $0.index <= endLine})
        var ranges        = [NSRange]()
        
        for pattern in type(of: self).vulnerablePatterns {
            let lines = analyzer.lines(matching: pattern.regexp)
            guard !lines.isEmpty else {
                continue
            }
            
            let paramLabel   = pattern.substringBetween("(",":")
            
            for line in lines {
                
                // Search for parameters, but exclude method calls as parameters ...
                
                guard let paramName = line.content.paramName(labelName: paramLabel),
                regex("\(paramName)\\s*\\(").matches(in: line.content, options: [], range: NSRange(location: 0, length: line.content.count)).count == 0 else {
                    continue
                }
                
                // Check if paramater is modified ...
                
                var isParameterModified = false
                if let linesBefore = analyzer.lines(before: line)?.filter({$0.content.contains(paramName)}), !linesBefore.isEmpty {
                    for lineBefore in linesBefore {
                        if analyzer.isParameterModified(paramName, onLine: lineBefore) {
                            isParameterModified = true
                            break
                        }
                    }
                }
                
                if !isParameterModified, let lineRange = line.content.range(of: paramName)?.nsRange {
                    // An unmodified parameter in this statement should be sanitized.
                    ranges.append(line.align(NSRange(location: line.range.location + lineRange.location, length: paramName.count - 1)))
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
