// Swift implementation for Noze.io by David Lichteblau
// Copyright (c) 2017 Verto Analytics Oy
//
// Inspired by sample code by Darren Smith:
//
// Copyright (c) 2017 Darren Smith
//
// Permission is hereby granted, free of charge, to any person obtaining
// a copy of this software and associated documentation files (the
// "Software"), to deal in the Software without restriction, including
// without limitation the rights to use, copy, modify, merge, publish,
// distribute, sublicense, and/or sell copies of the Software, and to
// permit persons to whom the Software is furnished to do so, subject to
// the following conditions:

// The above copyright notice and this permission notice shall be
// included in all copies or substantial portions of the Software.

// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
// EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
// MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
// NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS
// BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN
// ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
// CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
// SOFTWARE.

import Dispatch
import Foundation
import xsys
import core

class SecureTransportContext: TLSContext {
    public var side: SSLProtocolSide

    init(side: SSLProtocolSide) throws {
        self.side = side
    }

    func makeSocket() throws -> InMemoryTLS {
        return try InMemorySecureTransport(ctx: self)
    }
}

class PortableBuffer: CipherTextBuffer {
    var bytes: [UInt8] = []
    var softCap: Int // limit in size, to be exceeded by not too much

    init(softCap: Int) {
        self.softCap = softCap
    }

    var usedSpace: Int {
        get { return bytes.count }
    }

    func write(bytes fresh: [UInt8]) {
        if bytes.count == 0 {
            bytes = fresh
        } else {
            // TODO: Is this one of the fast methods, or one of those
            // using an iterator, i.e. so slow that you can watch it
            // fill the bytes?
            bytes.append(contentsOf: fresh)
        }
    }

    func read(maxLength: Int?) -> [UInt8]? {
        var desired = bytes.count
        if let maxLength = maxLength {
            desired = min(desired, maxLength)
        }
        if desired == 0 {
            return nil
        }
        if desired == bytes.count {
            let slice = bytes
            bytes = []
            return slice
        } else {
            let slice = [UInt8](bytes[0..<desired])
            bytes = [UInt8](bytes[desired..<bytes.endIndex])
            return slice
        }
    }
}

class InMemorySecureTransport: InMemoryTLS {
    static var BIO_SOFT_CAP: Int = 4096  // TODO: Tuning?

    var ssl: SSLContext
    var _ingress: PortableBuffer
    var _egress: PortableBuffer
    var shookHands = false

    var ingress: CipherTextBuffer { get { return _ingress } }
    var egress: CipherTextBuffer { get { return _egress } }

    init(ssl: SSLContext) {
        self._ingress = PortableBuffer(
                softCap: InMemorySecureTransport.BIO_SOFT_CAP)
        self._egress = PortableBuffer(
                softCap: InMemorySecureTransport.BIO_SOFT_CAP)
        self.ssl = ssl
        let _self = UnsafeRawPointer(Unmanaged.passUnretained(self).toOpaque())
        SSLSetIOFuncs(ssl, readCiphertext0, writeCiphertext0)
        assert(SSLSetConnection(ssl, _self) == errSecSuccess)
        SSLSetProtocolVersionMin(ssl, SSLProtocol.tlsProtocol11)
        // TODO: SSLSetPeerDomainName
    }

    convenience init(ctx: SecureTransportContext) throws {
        guard let ssl = SSLCreateContext(
                      kCFAllocatorDefault, ctx.side, .streamType) else {
            throw SecureError.Unexpected("failed to create SSL instance")
        }
        self.init(ssl: ssl)
    }

    func readCiphertext(
        data: UnsafeMutableRawPointer,
        dataLength lenptr: UnsafeMutablePointer<Int>) -> OSStatus
    {
        let len = lenptr.pointee
        if let bytes = ingress.read(maxLength: len) {
            var bytes = bytes
            lenptr.initialize(to: bytes.count)
            _ = memcpy(data, &bytes, bytes.count)
            return bytes.count < len
                   ? OSStatus(errSSLWouldBlock)
                   : noErr
        } else {
           lenptr.initialize(to: 0)
           return OSStatus(errSSLWouldBlock)
        }
    }

    func writeCiphertext(
        data: UnsafeRawPointer,
        dataLength lenptr: UnsafeMutablePointer<Int>) -> OSStatus
    {
        let len = lenptr.pointee
        let bp = UnsafeBufferPointer(
                start: data.bindMemory(to: UInt8.self, capacity: len),
                count: len)
        egress.write(dispatchData: DispatchData(bytes: bp))
        return noErr
    }

    func readPlaintext(intoBuffer buffer: UnsafeMutableRawPointer, maxLength: Int)
      throws -> Int?
    {
        let ready = try shakeHands()
        if !ready {
            return nil
        }
        var n = 0
        let err = SSLRead(ssl, buffer, maxLength, &n)
        switch err {
        case errSecSuccess:
            return n
        case errSSLClosedGraceful:
            return 0
        case errSSLWouldBlock:
            return nil
        default:
            throw SecureError.SSL_ERROR_SSL("SSLRead: \(err)")
        }
    }

    func writePlaintext(fromBuffer buffer: UnsafeRawPointer, ofLength: Int)
      throws -> Int?
    {
        let ready = try shakeHands()
        if !ready {
            return nil
        }
        var n = 0
        let err = SSLWrite(ssl, buffer, ofLength, &n)
        switch err {
        case errSecSuccess:
            return n
        case errSSLClosedGraceful:
            return 0
        case errSSLWouldBlock:
            return nil
        default:
            throw SecureError.SSL_ERROR_SSL("SSLWrite: \(err)")
        }
    }

    func shutdown() throws -> Bool {
        // TODO: Documentation is very sparse on this one.
        // Is this even remotely right?
        let err = SSLClose(ssl)
        switch err {
        case errSecSuccess:
            return true
        case errSSLWouldBlock:
            return false
        default:
            throw SecureError.SSL_ERROR_SSL("SSLHandshake: \(err)")
        }
    }

    func shakeHands() throws -> Bool {
        if shookHands {
            return true
        }
        let err = SSLHandshake(ssl)
        switch err {
        case errSecSuccess:
            shookHands = true
            return true
        case errSSLWouldBlock:
            return false
        default:
            throw SecureError.SSL_ERROR_SSL("SSLHandshake: \(err)")
        }
    }
}

func readCiphertext0(
    connection: SSLConnectionRef,
    data: UnsafeMutableRawPointer,
    dataLength: UnsafeMutablePointer<Int>) -> OSStatus
 {
     return Unmanaged<InMemorySecureTransport>
         .fromOpaque(connection)
         .takeUnretainedValue()
         .readCiphertext(data: data, dataLength: dataLength)
 }

func writeCiphertext0(
    connection: SSLConnectionRef,
    data: UnsafeRawPointer,
    dataLength: UnsafeMutablePointer<Int>) -> OSStatus
{
    return Unmanaged<InMemorySecureTransport>
        .fromOpaque(connection)
        .takeUnretainedValue()
        .writeCiphertext(data: data, dataLength: dataLength)
}
