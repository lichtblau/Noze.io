//
//  NSDataHelpers.swift
//  Noze.io
//
//  Created by Helge Heß on 5/26/16.
//  Copyright © 2016 ZeeZide GmbH. All rights reserved.
//

#if os(macOS) // TODO: port to Linux

import Freddy
import class Foundation.NSData

public extension JSON {

  
  // TODO: remove me, just for testing
  public init(data inData: NSData) throws {
    //private init<T>(buffer: UnsafeBufferPointer<UInt8>, owner: T) {
    
    let data   = inData.copy() as! NSData
    let buffer = UnsafeBufferPointer(start: UnsafePointer<UInt8>(data.bytes),
                                     count: data.length)
    
    var parser = JSONParser(buffer: buffer, owner: data)
    self = try parser.parse()
  }
  public init<T>(data inData: NSData, usingParser dummy: T) throws {
    try self.init(data: inData)
  }

}

public extension JSONParser {

  public static func createJSONFromData(_ data: NSData) throws -> JSON {
    return try JSON(data: data)
  }
}

public extension JSONParser {

    /// Creates a `JSONParser` ready to parse UTF-8 encoded `NSData`.
    ///
    /// If the data is mutable, it is copied before parsing. The data's lifetime
    /// is extended for the duration of parsing.
    init(utf8Data inData: NSData) {
        let data = inData.copy() as! NSData
        let buffer = UnsafeBufferPointer(start: UnsafePointer<UInt8>(data.bytes), count: data.length)
        self.init(buffer: buffer, owner: data)
    }

}

#endif
