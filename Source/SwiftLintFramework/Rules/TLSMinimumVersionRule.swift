//
//  TLSMinimumVersionRule.swift
//  SwiftLintFramework
//
//  Created by Vladimír Nevyhoštěný on 12/11/2017.
//  Copyright © 2017 Realm. All rights reserved.
//

import Foundation
import SourceKittenFramework

//==============================================================================
public struct TLSMinimumVersionRule: ASTRule, ConfigurationProviderRule
{
    public var configuration = SeverityConfiguration(.warning)
    
    //--------------------------------------------------------------------------
    public init() {}
    
    public static let description = RuleDescription(
        identifier:   "tls_minimal_version",
        name:         "TLS Vesion",
        description:  "TLS minimal version vulnerability.",
        kind: .vulnerability,
        nonTriggeringExamples: [
            "configuration.tlsMinimumSupportedProtocol = .tlsProtocol11"
        ],
        triggeringExamples: [
            "configuration.tlsMinimumSupportedProtocol = ↓.sslProtocolAll"
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
            
            
            let analyzer     = OWASPAnalyzer(lines: file.lines, dictionary: dictionary)
            let matchedLines = file.lines.filter {$0.content.contains(".tlsMinimumSupportedProtocol")}
            
            for line in matchedLines {
                guard !analyzer.isComment(line: line), let (range, rvalue) = OWASPAnalyzer.rvalue(withLvalue: "tlsMinimumSupportedProtocol", inLine: line) else {
                    continue
                }
                if rvalue.contains("tlsProtocol11") || rvalue.contains("tlsProtocol12") || rvalue.contains("tlsProtocol13") {
                    // OK. TLS version is secure enough.
                }
                else {
                    ranges.append(line.align(range))
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

