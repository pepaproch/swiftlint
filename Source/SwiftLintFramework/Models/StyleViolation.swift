//
//  StyleViolation.swift
//  SwiftLint
//
//  Created by JP Simard on 5/16/15.
//  Copyright © 2015 Realm. All rights reserved.
//

import Foundation

public struct StyleViolation: CustomStringConvertible, Equatable {
    public let ruleDescription: RuleDescription
    public let severity: ViolationSeverity
    public let location: Location
    public let reason: String
    public let endLocation: Location?
    
    public var description: String {
        return XcodeReporter.generateForSingleViolation(self)
    }
    
    public var endLocationDescription: String {
        guard let line = self.endLocation?.line, let column = self.endLocation?.character else {
            return String()
        }
        return ":\(line):\(column)"
    }
    
    public init(ruleDescription: RuleDescription, severity: ViolationSeverity = .warning,
                location: Location, reason: String? = nil)
    {
        self.init(ruleDescription: ruleDescription, severity: severity, location: location, reason: reason, endLocation: nil)
    }

    public init(ruleDescription: RuleDescription, severity: ViolationSeverity = .warning,
                location: Location, reason: String? = nil, endLocation: Location? = nil) {
        self.ruleDescription = ruleDescription
        self.severity = severity
        self.location = location
        self.reason = reason ?? ruleDescription.description
        self.endLocation = endLocation
    }
}

// MARK: Equatable

public func == (lhs: StyleViolation, rhs: StyleViolation) -> Bool {
    return lhs.ruleDescription == rhs.ruleDescription &&
        lhs.location == rhs.location &&
        lhs.severity == rhs.severity &&
        lhs.reason == rhs.reason &&
        lhs.endLocation == rhs.endLocation
}
