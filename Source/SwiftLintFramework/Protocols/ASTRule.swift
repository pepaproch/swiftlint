//
//  ASTRule.swift
//  SwiftLint
//
//  Created by JP Simard on 5/16/15.
//  Copyright © 2015 Realm. All rights reserved.
//

import SourceKittenFramework

public protocol ASTRule: Rule {
    associatedtype KindType: RawRepresentable
    func validate(file: File, kind: KindType, dictionary: [String: SourceKitRepresentable]) -> [StyleViolation]
}

public extension ASTRule where KindType.RawValue == String {
    
    //--------------------------------------------------------------------------
    func validate(file: File) -> [StyleViolation]
    {
        return self.removeDuplicates(validate(file: file, dictionary: file.structure.dictionary))
    }

    //--------------------------------------------------------------------------
    func validate(file: File, dictionary: [String: SourceKitRepresentable]) -> [StyleViolation]
    {
        let result = dictionary.substructure.flatMap { subDict -> [StyleViolation] in
            var violations = validate(file: file, dictionary: subDict)

            if let kindString = subDict.kind,
                let kind = KindType(rawValue: kindString) {
                violations += validate(file: file, kind: kind, dictionary: subDict)
            }

            return violations
        }
        return self.removeDuplicates(result)
    }
    
    //--------------------------------------------------------------------------
    private func removeDuplicates(_ violations: [StyleViolation]) -> [StyleViolation]
    {
        var set = Set<String>()
        return violations.filter {
            let key = "\($0.location.file?.bridge().lastPathComponent ?? String()):\($0.ruleDescription.name):\($0.location.line ?? 0):\($0.location.character ?? 0)"
            
            if set.contains(key) {
                return false
            }
            
            set.insert(key)
            return true
        }
    }
}
