//
//  ASTNode+OWASP.swift
//  SwiftLintFramework
//
//  Created by Vladimír Nevyhoštěný on 16/11/2017.
//  Copyright © 2017 Realm. All rights reserved.
//

import Foundation
import SourceKittenFramework

//==============================================================================
extension ASTRule
{
    //--------------------------------------------------------------------------
    func lintOnce(file: File, ruleName: String, completion: @escaping ((_ shouldProceed: Bool) -> Void))
    {
        OWASPAnalyzer.lintSyncQueue.async {
            completion(OWASPAnalyzer.firstScanOf(fileName: file.path, forRule: ruleName))
        }
    }
}
