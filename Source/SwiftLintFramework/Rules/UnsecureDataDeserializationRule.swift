//
//  UnsecureDataDeserializationRule.swift
//  swiftlint
//
//  Created by Vladimír Nevyhoštěný on 13/10/2017.
//  Copyright © 2017 Realm. All rights reserved.
//

import Foundation
import SourceKittenFramework

//==============================================================================
public struct UnsecureDataDeserializationRule: ASTRule, ConfigurationProviderRule
{
    public var configuration = SeverityConfiguration(.warning)
    
    //--------------------------------------------------------------------------
    public init() {}
    
    public static let description = RuleDescription(
        identifier: "unsecure_data_serialization",
        name: "Unsecure Data Serialization",
        description: "Unsecure data serialization vulnerability. Use NSSecureCoding",
        kind: .vulnerability,
        nonTriggeringExamples: [
            "class Foo: NSSecureCoding"
        ],
        triggeringExamples: [
            "class Foo: ↓NSCoding"
        ]
    )
    
    static let affectedTypeKinds: Set<SwiftDeclarationKind> = [.class, .extensionClass, .protocol, .extensionProtocol]
    static let searchPattern                                = "NSCoding"
    
    //--------------------------------------------------------------------------
    public func validate(file: File, kind: SwiftDeclarationKind, dictionary: [String: SourceKitRepresentable]) -> [StyleViolation]
    {
        guard type(of: self).affectedTypeKinds.contains(kind) else {
            return []
        }
        
        var ranges         = [NSRange]()
        
        let matchedTypes   = dictionary.inheritedTypes.filter {$0.contains(type(of: self).searchPattern)}
        let analyzer       = OWASPAnalyzer(lines: file.lines)
        let matchedLines   = analyzer.lines(forDictionary: dictionary).filter {$0.content.contains(type(of: self).searchPattern)}
        
        guard matchedTypes.count == matchedLines.count else {
            return []
        }
        
        for line in matchedLines {
            let matchedRange = (line.content.range(of: type(of: self).searchPattern)?.nsRange)!
            ranges.append(line.align(NSRange(location: line.range.location + matchedRange.location, length: type(of: self).searchPattern.count)))
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

