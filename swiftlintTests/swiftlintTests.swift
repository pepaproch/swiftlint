//
//  swiftlintTests.swift
//  swiftlintTests
//
//  Created by Vladimír Nevyhoštěný on 18/10/2017.
//  Copyright © 2017 Realm. All rights reserved.
//

import XCTest
import SourceKittenFramework

@testable import SwiftLintFramework

//==============================================================================
class swiftlintTests: XCTestCase
{
    //--------------------------------------------------------------------------
    class var bundle: Bundle {
        return Bundle(for: self.classForCoder())
    }
    
    //--------------------------------------------------------------------------
    class var projectDir: String {
        return (bundle.infoDictionary! ["csob.owasp.project-dir"] as? String)!
    }
    
    //--------------------------------------------------------------------------
    class var securityDemoBaseDir: String {
        return "\(projectDir)/../IOS_Security/Source/SecurityDemo/SecurityDemo"
    }
    
    //--------------------------------------------------------------------------
    class var securityDemoTestBaseDir: String {
        return "\(projectDir)/../IOS_Security/Source/SecurityDemo/SecurityDemoTests"
    }
    
    //--------------------------------------------------------------------------
    class func fullName(with fileName: String) -> String
    {
        return "\(securityDemoBaseDir)/\(fileName)"
    }
    
    //--------------------------------------------------------------------------
    class func fullTestName(with fileName: String) -> String
    {
        return "\(securityDemoTestBaseDir)/\(fileName)"
    }
    
    //--------------------------------------------------------------------------
    override func setUp()
    {
        super.setUp()
    }
    
    //--------------------------------------------------------------------------
    override func tearDown()
    {
        super.tearDown()
    }
    
    //--------------------------------------------------------------------------
    func match(_ violation: StyleViolation, startLine: Int, startColumn: Int, endLine: Int, endColumn: Int) -> Bool
    {
        return violation.location.line ?? 0          == startLine
               &&
               violation.location.character ?? 0     == startColumn
               &&
               violation.endLocation?.line ?? 0      == endLine
               &&
               violation.endLocation?.character ?? 0 == endColumn
    }
    
    //--------------------------------------------------------------------------
    func testPathTraversalViolation()
    {
        let sourceFileName = type(of: self).fullName(with: "PathTraversalDemoViewController.swift")
        guard let file = File(path: sourceFileName) else {
            XCTFail("File \(sourceFileName) not found!")
            return
        }
        
        let rule            = PathTraversalRule()
        let styleViolations = rule.validate(file: file)
        
        XCTAssert(styleViolations.count == 1, "Unexpected violations count!")
        XCTAssert(self.match(styleViolations [0], startLine: 102, startColumn: 40, endLine: 102, endColumn: 51))
    }
    
    //--------------------------------------------------------------------------
    func testUnsecureDataDeserializationViolation()
    {
        let sourceFileName = type(of: self).fullTestName(with: "User.swift")
        guard let file = File(path: sourceFileName) else {
            XCTFail("File \(sourceFileName) not found!")
            return
        }
        
        let rule            = UnsecureDataDeserializationRule()
        let styleViolations = rule.validate(file: file)
        
        XCTAssert(styleViolations.count == 1, "Unexpected violations count!")
        XCTAssert(self.match(styleViolations [0], startLine: 33, startColumn: 32, endLine: 33, endColumn: 39))
    }
    
    //--------------------------------------------------------------------------
    func testJavaScriptViolation()
    {
        let sourceFileName = type(of: self).fullName(with: "WebViewAddresBarDemoViewController.swift")
        guard let file = File(path: sourceFileName) else {
            XCTFail("File \(sourceFileName) not found!")
            return
        }
        
        let rule            = JavaScriptInjectionRule()
        let styleViolations = rule.validate(file: file)
        
        XCTAssert(styleViolations.count == 1, "Unexpected violations count!")
        XCTAssert(self.match(styleViolations [0], startLine: 12, startColumn: 27, endLine: 12, endColumn: 30))
    }
    
    //--------------------------------------------------------------------------
    func testXmlInjection()
    {
        let sourceFileName = type(of: self).fullName(with: "XmlInjectionDemoViewController.swift")
        guard let file = File(path: sourceFileName) else {
            XCTFail("File \(sourceFileName) not found!")
            return
        }
        
        let rule            = XmlInjectionRule()
        let styleViolations = rule.validate(file: file)
        
        XCTAssert(styleViolations.count == 5, "Unexpected violations count!")
        
        XCTAssert(self.match(styleViolations [0], startLine: 91, startColumn: 48, endLine: 91, endColumn: 54))
        XCTAssert(self.match(styleViolations [1], startLine: 175, startColumn: 48, endLine: 175, endColumn: 54))
        XCTAssert(self.match(styleViolations [2], startLine: 88, startColumn: 48, endLine: 88, endColumn: 51))
        XCTAssert(self.match(styleViolations [3], startLine: 126, startColumn: 65, endLine: 126, endColumn: 79))
        XCTAssert(self.match(styleViolations [4], startLine: 216, startColumn: 34, endLine: 216, endColumn: 48))
        
        for violation in styleViolations {
            XCTAssert(violation.ruleDescription.name == "XML Injection")
        }
    }
    
    //--------------------------------------------------------------------------
    func testXmlInjectionTest()
    {
        let sourceFileName = type(of: self).fullTestName(with: "SQLiteSwift_SQLInjectionTests.swift")
        guard let file = File(path: sourceFileName) else {
            XCTFail("File \(sourceFileName) not found!")
            return
        }
        
        let rule            = XmlInjectionRule()
        let styleViolations = rule.validate(file: file)
        
        XCTAssert(styleViolations.count == 0, "Unexpected violations count!")
    }

    //--------------------------------------------------------------------------
    func testBufferOverflow()
    {
        let sourceFileName = type(of: self).fullName(with: "BufferOverflowDemoViewController.swift")
        guard let file = File(path: sourceFileName) else {
            XCTFail("File \(sourceFileName) not found!")
            return
        }
        
        let rule            = BufferOverflowRule()
        let styleViolations = rule.validate(file: file)
        
        XCTAssert(styleViolations.count == 1, "Unexpected violations count!")
        XCTAssert(self.match(styleViolations [0], startLine: 45, startColumn: 79, endLine: 45, endColumn: 88))
    }
    
    //--------------------------------------------------------------------------
    func testSqlInjection()
    {
        let sourceFileName = type(of: self).fullName(with: "SQLInjectionDemoViewController.swift")
        guard let file = File(path: sourceFileName) else {
            XCTFail("File \(sourceFileName) not found!")
            return
        }
        
        let rule            = SqlInjectionRule()
        let styleViolations = rule.validate(file: file)
        
        XCTAssert(styleViolations.count == 3, "Unexpected violations count!")
        
        XCTAssert(self.match(styleViolations [0], startLine: 147, startColumn: 115, endLine: 147, endColumn: 140))
        XCTAssert(self.match(styleViolations [1], startLine: 190, startColumn: 123, endLine: 190, endColumn: 124))
        XCTAssert(self.match(styleViolations [2], startLine: 96, startColumn: 36, endLine: 96, endColumn: 85))
    }
    
    //--------------------------------------------------------------------------
    func testTLSMinimumVersion()
    {
        let sourceFileName = type(of: self).fullName(with: "WrongCerificateUsageDemoViewController.swift")
        guard let file = File(path: sourceFileName) else {
            XCTFail("File \(sourceFileName) not found!")
            return
        }
        
        let rule            = TLSMinimumVersionRule()
        let styleViolations = rule.validate(file: file)
        
        XCTAssert(styleViolations.count == 1, "Unexpected violations count!")
        XCTAssert(self.match(styleViolations [0], startLine: 48, startColumn: 53, endLine: 48, endColumn: 67))
    }
    
    //--------------------------------------------------------------------------
    func testCertificateUsage()
    {
        let sourceFileName = type(of: self).fullName(with: "WrongCerificateUsageDemoViewController.swift")
        guard let file = File(path: sourceFileName) else {
            XCTFail("File \(sourceFileName) not found!")
            return
        }
        
        let rule            = WrongCertificateHandlingRule()
        let styleViolations = rule.validate(file: file)
        
        XCTAssert(styleViolations.count == 1, "Unexpected violations count!")
        XCTAssert(self.match(styleViolations [0], startLine: 136, startColumn: 31, endLine: 136, endColumn: 90))
    }
    
    //--------------------------------------------------------------------------
    func testJavascriptInjection()
    {
        let sourceFileName = type(of: self).fullName(with: "XSSUIWebViewDemoViewController.swift")
        guard let file = File(path: sourceFileName) else {
            XCTFail("File \(sourceFileName) not found!")
            return
        }
        
        let rule            = JavaScriptInjectionRule()
        let styleViolations = rule.validate(file: file)
        
        XCTAssert(styleViolations.count == 1, "Unexpected violations count!")
        XCTAssert(self.match(styleViolations [0], startLine: 56, startColumn: 48, endLine: 56, endColumn: 53))
    }
    
    //--------------------------------------------------------------------------
    func testVulnerableComments()
    {
        let sourceFileName = type(of: self).fullName(with: "KeychainDemoViewController.swift")
        guard let file = File(path: sourceFileName) else {
            XCTFail("File \(sourceFileName) not found!")
            return
        }
        
        let rule            = VulnerableCommentRule()
        let styleViolations = rule.validate(file: file)
        
        XCTAssert(styleViolations.count == 1, "Unexpected violations count!")
        XCTAssert(self.match(styleViolations [0], startLine: 32, startColumn: 40, endLine: 32, endColumn: 47))
    }
    
    //--------------------------------------------------------------------------
    func testHardcodedPasswords()
    {
        let sourceFileName = type(of: self).fullName(with: "KeychainWrapper.swift")
        guard let file = File(path: sourceFileName) else {
            XCTFail("File \(sourceFileName) not found!")
            return
        }
        
        let rule            = HardcodedPasswordRule()
        let styleViolations = rule.validate(file: file)
        
        XCTAssert(styleViolations.count == 2, "Unexpected violations count!")
        XCTAssert(self.match(styleViolations [0], startLine: 17, startColumn: 44, endLine: 17, endColumn: 65))
        XCTAssert(self.match(styleViolations [1], startLine: 96, startColumn: 13, endLine: 96, endColumn: 32))
    }
    
    //--------------------------------------------------------------------------
    func testEmptyCatchBlock()
    {
        let sourceFileName = type(of: self).fullName(with: "PathTraversalDemoViewController.swift")
        guard let file = File(path: sourceFileName) else {
            XCTFail("File \(sourceFileName) not found!")
            return
        }
        
        let rule            = EmptyCatchRule()
        let styleViolations = rule.validate(file: file)
        
        XCTAssert(styleViolations.count == 1, "Unexpected violations count!")
        XCTAssert(self.match(styleViolations [0], startLine: 145, startColumn: 9, endLine: 147, endColumn: 9))
    }
}
