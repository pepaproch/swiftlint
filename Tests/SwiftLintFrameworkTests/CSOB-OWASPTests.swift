//
//  CSOB-OWASPTests.swift
//  SwiftLintFrameworkTests
//
//  Created by Vladimír Nevyhoštěný on 16/10/2017.
//  Copyright © 2017 Realm. All rights reserved.
//

import XCTest
@testable import SwiftLintFramework
@testable import SourceKittenFramework

//==============================================================================
class CSOB_OWASPTests: XCTestCase
{
    var projectDir: String?
    
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
    func structure(sourceFileName: String) -> (Structure, String)?
    {
        let filePath   = "\(type(of: self).securityDemoBaseDir)/\(sourceFileName)"
        if let file = File(path: filePath), let document = try? String(contentsOfFile: filePath) {
            return (Structure(file: file), document)
        }
        return nil
    }
    
    //--------------------------------------------------------------------------
    func syntaxMap(sourceFileName: String) -> (SyntaxMap, File)?
    {
        let filePath   = "\(type(of: self).securityDemoBaseDir)/\(sourceFileName)"
        if let source = try? String(contentsOfFile: filePath) {
            let crLfSource = source.replacingOccurrences(of: "\n", with: "\r\n")
            let foo        = String(describing: crLfSource)
            let file       = File(contents: foo)
        //if let file = File(path: filePath) {
            return (SyntaxMap(file: file), file)
        }
        return nil
    }

    
    //--------------------------------------------------------------------------
    func testStructure()
    {
        guard let structure = structure(sourceFileName: "XSSWkWebViewDemoViewController.swift") else {
            XCTFail("Error when parse source file structure!")
            return
        }
        
        let document = structure.1
        for (kind, range) in structure.0.kinds() {
            print("Kind: \(kind), range: \(range)")
            let startIndex = String.Index(encodedOffset: range.location)
            //let startIndex = document.index(document.startIndex, offsetBy: range.location)
            let endIndex   = document.index(startIndex, offsetBy: range.length)
            
            print("Content: \"\(document [startIndex..<endIndex])\"\n")
        }
    }
    
    //--------------------------------------------------------------------------
    func testSyntaxMap()
    {
        guard let syntaxMap = syntaxMap(sourceFileName: "XSSWkWebViewDemoViewController.swift") else {
            XCTFail("Error when parse source file structure!")
            return
        }
        
        let document = syntaxMap.1.contents.unicodeScalars
        for token in syntaxMap.0.tokens {
            print("Token:\n\(token.description)")
            let startIndex  = String.Index(encodedOffset: token.offset)
            //let startIndex  = document.index(document.startIndex, offsetBy: token.offset)
            let endIndex    = document.index(startIndex, offsetBy: token.length)
            let elementBody = String(document [startIndex..<endIndex])
            print("Element body: \"\(elementBody)\"\n")
            //print("Content: \(document.substring(from: token.offset, length: token.length))\n")
        }
    }
    
    struct Property {
        let name: String
        let type: String
        var swiftSourceRepresentation: String {
            return "static let \(name) = Property<\(type)>(name: \"\(name)\")"
        }
    }
    
    struct Model {
        let name: String
        let properties: [Property]
        var swiftSourceRepresentation: String {
            return "extension \(name) {\n" +
                properties.map({"  \($0.swiftSourceRepresentation)"}).joined(separator: "\n") +
            "\n}"
        }
    }
    
    //--------------------------------------------------------------------------
    func testExample()
    {
        let filePath = "\(type(of: self).securityDemoBaseDir)/XSSWkWebViewDemoViewController.swift"
        if let file = File(path: filePath) {
            let structure = Structure(file: file)
            let models = (structure.dictionary["key.substructure"] as! [SourceKitRepresentable]).map({
                $0 as! [String: SourceKitRepresentable]
            }).filter({ substructure in
                return SwiftDeclarationKind(rawValue: substructure["key.kind"] as! String) == .functionMethodInstance
            }).map { modelStructure in
                return Model(name: modelStructure["key.name"] as! String,
                             properties: (modelStructure["key.substructure"] as! [SourceKitRepresentable]).map({
                                $0 as! [String: SourceKitRepresentable]
                             }).filter({ substructure in
                                return SwiftDeclarationKind(rawValue: substructure["key.kind"] as! String) == .varInstance
                             }).map { Property(name: $0["key.name"] as! String, type: $0["key.typename"] as! String) }
                )
            }
            
            print(models.map({ $0.swiftSourceRepresentation }).joined(separator: "\n"))
        }
    }
    
    //--------------------------------------------------------------------------
    func testExample2()
    {
        let filePath = "\(type(of: self).securityDemoBaseDir)/XSSWkWebViewDemoViewController.swift"
        if let file = File(path: filePath) {
            let structure = Structure(file: file)
//            let representable = structure.dictionary["key.substructure"] as! [SourceKitRepresentable]
//            print(representable.count)
            let models = (structure.dictionary["key.name"] as! [SourceKitRepresentable]).map({
                $0 as! [String: SourceKitRepresentable]
            }).filter({ substructure in
                return SwiftDeclarationKind(rawValue: substructure["key.kind"] as! String) == .functionMethodInstance
            })
            
            print(models.map({ $0.description }).joined(separator: "\n"))
        }
    }

}
