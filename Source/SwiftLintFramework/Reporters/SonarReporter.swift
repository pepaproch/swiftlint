//
//  SonarReporter.swift
//  SwiftLintFramework
//
//  Created by Vladimír Nevyhoštěný on 04/11/2017.
//  Copyright © 2017 Realm. All rights reserved.
//

import Foundation

public struct SonarReporter: Reporter {
    public static let identifier = "sonar"
    public static let isRealtime = true
    
    public var description: String {
        return "Reports violations in the format SonarQube uses to parse the report output."
    }
    
    public static func generateReport(_ violations: [StyleViolation]) -> String {
        return violations.map(generateForSingleViolation).joined(separator: "\n")
    }
    
    internal static func generateForSingleViolation(_ violation: StyleViolation) -> String {
        // {full_path_to_file}{:line}{:character}{:line}{:endCharacter}: {error,warning}: {content}
        return [
            "\(violation.location)",
            "\(violation.endLocationDescription): ",
            "\(violation.severity.rawValue): ",
            "\(violation.ruleDescription.name) Violation: ",
            violation.reason,
            " (\(violation.ruleDescription.identifier))"
            ].joined()
    }
}
