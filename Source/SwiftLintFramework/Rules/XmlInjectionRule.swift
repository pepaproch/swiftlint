//
//  XmlInjectionRule.swift
//  SwiftLintFramework
//
//  Created by Vladimír Nevyhoštěný on 02/11/2017.
//  Copyright © 2017 Realm. All rights reserved.
//

import Foundation
import SourceKittenFramework

//==============================================================================
public struct XmlInjectionRule: ASTRule, ConfigurationProviderRule
{
    public var configuration = SeverityConfiguration(.warning)
    
    //--------------------------------------------------------------------------
    public init() {}
    
    public static let description = RuleDescription(
        identifier:   "xml_injection",
        name:         "XML Injection",
        description:  "XML injection vulnerability.",
        kind: .vulnerability,
        nonTriggeringExamples: [
            "parser.externalEntityResolvingPolicy = .never"
        ],
        triggeringExamples: [
            "parser.externalEntityResolvingPolicy = ↓.always"
        ]
    )
    
    //--------------------------------------------------------------------------
    public func validate(file: File, kind: SwiftDeclarationKind, dictionary: [String: SourceKitRepresentable]) -> [StyleViolation]
    {
        var ranges = [NSRange]()
        
        ranges.append(contentsOf: self.validateExternalEntityResolvingPolicy(file: file, dictionary: dictionary))
        ranges.append(contentsOf: self.validateShouldResolveExternalEntities(file: file, dictionary: dictionary))
        ranges.append(contentsOf: self.validateXMLparseNoent(file: file, kind: kind, dictionary: dictionary))
        
        return ranges.map {
            StyleViolation(ruleDescription: type(of: self).description,
                           severity:        configuration.severity,
                           location:        Location(file: file, characterOffset: $0.location),
                           endLocation:     Location(file: file, characterOffset: $0.location + $0.length)
                          )
        }
    }
    
    static let resolvingPolicyAttribute  = "externalEntityResolvingPolicy"
    
    //--------------------------------------------------------------------------
    func validateExternalEntityResolvingPolicy(file: File, dictionary: [String: SourceKitRepresentable]) -> [NSRange]
    {
        var ranges = [NSRange]()
        
        let lines = file.lines.filter {$0.content.contains(type(of: self).resolvingPolicyAttribute)}
        for line in lines {
            if let rvalue = line.content.rvalue(lvalue: type(of: self).resolvingPolicyAttribute), let range = line.content.range(of: rvalue)?.nsRange {
                if rvalue.contains(".always") {
                    ranges.append(line.align(NSRange(location: line.range.location + range.location, length: rvalue.count)))
                }
                else if rvalue.contains(".never") {
                    // OK here, the suspiciousAttribute is disabled by constant.
                }
                else {
                    let analyzer      = OWASPAnalyzer(lines: file.lines)
                    let assignedLines = analyzer.lines(excludeLine: line, forLvalue: rvalue)
                    
                    if assignedLines.count == 1, assignedLines [0].content.contains(".never") {
                        // OK here, the suspiciousAttribute is disabled by variable.
                    }
                    else {
                        // No reliable info about the suspiciousAttribute lvalue here.
                        for line in assignedLines {
                            ranges.append(line.align(NSRange(location: line.range.location + range.location, length: rvalue.count)))
                        }
                    }
                }
            }
        }
        
        return ranges
    }
    
    static let shouldResolveExternalEntities  = "shouldResolveExternalEntities"
    
    //--------------------------------------------------------------------------
    func validateShouldResolveExternalEntities(file: File, dictionary: [String: SourceKitRepresentable]) -> [NSRange]
    {
        var ranges = [NSRange]()
        
        let lines = file.lines.filter {$0.content.contains(type(of: self).shouldResolveExternalEntities)}
        for line in lines {
            if let rvalue = line.content.rvalue(lvalue: type(of: self).shouldResolveExternalEntities), let range = line.content.range(of: rvalue)?.nsRange {
                if rvalue.contains("true") {
                    ranges.append(line.align(NSRange(location: line.range.location + range.location, length: rvalue.count)))
                }
                else if rvalue.contains("false") {
                    // OK here, the suspiciousAttribute is disabled by constant.
                }
                else {
                    let analyzer      = OWASPAnalyzer(lines: file.lines)
                    let assignedLines = analyzer.lines(excludeLine: line, forLvalue: rvalue)
                    
                    if assignedLines.count == 1, assignedLines [0].content.contains("false") {
                        // OK here, the suspiciousAttribute is disabled by variable.
                    }
                    else {
                        // No reliable info about the suspiciousAttribute lvalue here.
                        for line in assignedLines {
                            ranges.append(line.align(NSRange(location: line.range.location + range.location, length: rvalue.count)))
                        }
                    }
                }
            }
        }
        
        return ranges
    }
    
    
    static let xmlParseNoentAttribute                       = "XML_PARSE_NOENT"
    static let searchedMethodName                           = "xmlReadMemory"
    
    //--------------------------------------------------------------------------
    func validateXMLparseNoent(file: File, kind: SwiftDeclarationKind, dictionary: [String: SourceKitRepresentable]) -> [NSRange]
    {
        var ranges = [NSRange]()
        
        guard OWASPAnalyzer.methodCallKinds.contains(kind), dictionary.description.contains(type(of: self).searchedMethodName),
            let bodyOffset = dictionary.bodyOffset,
            let bodyLength = dictionary.bodyLength else {
                return ranges
        }
        
        let bodyLines   = file.lines.filter {$0.byteRange.location >= bodyOffset && $0.byteRange.location < bodyOffset + bodyLength}
        let structure   = Structure(sourceKitResponse: dictionary)
        let methodCalls = structure.calls(ofMethodName: type(of: self).searchedMethodName)
        
        for methodCall in methodCalls {
            let arguments = structure.arguments(ofFunction: methodCall)
            
            // We are looking exactly for the 5th function argument, "options"
            
            if arguments.count == 5, let optionsArgument = arguments.last, let argOffset = optionsArgument.bodyOffset, let argLength = optionsArgument.bodyLength {
                let matchedLines = bodyLines.filter {$0.byteRange.location < argOffset && $0.byteRange.location + $0.byteRange.length > argOffset}
                if !matchedLines.isEmpty, let matchedLine = matchedLines.first {
                    let optionsParamName = matchedLine.content.substring(from: argOffset - matchedLine.byteRange.location, length: argLength).paramName()
                    
                    // Maybe parameter itself contains vulnerable value?
                    
                    if optionsParamName.contains(type(of: self).xmlParseNoentAttribute) {
                        ranges.append(matchedLine.align(NSRange(location: matchedLine.byteRange.location + argOffset, length: type(of: self).xmlParseNoentAttribute.count - 1)))
                    }
                    else {
                        
                        // No. We need to look for parameter assigment.
                        
                        let analyzer       = OWASPAnalyzer(lines: file.lines)
                        let assignedLines  = analyzer.lines(excludeLine: matchedLine, forLvalue: optionsParamName)
                        
                        for line in assignedLines {
                            if let rvalueRange = line.content.range(of: type(of: self).xmlParseNoentAttribute)?.nsRange {
                                ranges.append(line.align(NSRange(location: line.range.location + rvalueRange.location, length: type(of: self).xmlParseNoentAttribute.count - 1)))
                            }
                        }
                    }
                }
            }
        }
        
        return ranges
    }

}
