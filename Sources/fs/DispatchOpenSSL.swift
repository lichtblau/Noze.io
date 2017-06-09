// Inspired by sample code by Darren Smith:
// Copyright (c) 2017 Darren Smith
//
// Swift implementation for Noze.io by David Lichteblau
// Copyright (c) 2017 Verto Analytics Oy
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

import OpenSSL
import Dispatch
import Foundation
import xsys
import core

class OpenSSLContext: TLSContext {
    static var initialized = false

    static func ensureInitialized() {
        if !initialized {
            initialize()
            initialized = true
        }
    }

    static func initialize() {
        SSL_library_init()
        // OpenSSL_add_all_algorithms()
        SSL_load_error_strings()
        ERR_load_BIO_strings()
        ERR_load_crypto_strings()
        OPENSSL_config(nil)
        OPENSSL_add_all_algorithms_conf()
    }

    var ptr: UnsafeMutablePointer<SSL_CTX>
    var side: SSLProtocolSide

    init(ptr: UnsafeMutablePointer<SSL_CTX>, side: SSLProtocolSide) {
        self.ptr = ptr
        self.side = side
    }

    convenience init(side: SSLProtocolSide) throws {
        OpenSSLContext.ensureInitialized()
        let method: UnsafePointer<SSL_METHOD> = {
            switch side {
            case .serverSide: return SSLv23_server_method()
            case .clientSide: return SSLv23_client_method()
            }
        }()
        ERR_clear_error()
        guard let ctx = SSL_CTX_new(method) else {
            throw InMemoryOpenSSL.getError()
        }
        // Some notes on options which we're not setting:
        //
        // We could set SSL_MODE_ACCEPT_MOVING_WRITE_BUFFER, but never
        // mutate our buffer arrays from Swift, so copy-on-write should
        // not occur.
        //
        // We don't care about SSL_MODE_AUTO_RETRY, because it's for
        // blocking sockets only, and our file descriptor is
        // non-blocking.
        //
        // We don't enable SSL_MODE_ENABLE_PARTIAL_WRITE, and would have
        // to change our code to cope with it, if it were enabled.  We
        // don't need partial writes.

        // Options which we are setting:
        ///
        // The oldest version we accept is TLS 1.1.
        SSL_CTX_ctrl(ctx, SSL_CTRL_OPTIONS,
                     SSL_OP_NO_SSLv2 | SSL_OP_NO_SSLv3 | SSL_OP_NO_TLSv1,
                     nil)
        self.init(ptr: ctx, side: side)
    }

    func makeSocket() throws -> InMemoryTLS {
        return try InMemoryOpenSSL(ctx: self)
    }
}

class BioBuffer: CipherTextBuffer {
    var bio: UnsafeMutablePointer<BIO>
    var softCap: Int // limit in size, to be exceeded by not too much

    init(softCap: Int) {
        self.softCap = softCap
        self.bio = BIO_new(BIO_s_mem())
    }

    var usedSpace: Int {
        get { return BIO_ctrl(bio, BIO_CTRL_PENDING, 0, nil) }
    }

    func write(bytes: [UInt8]) {
        bytes.withUnsafeBufferPointer { bp in
            let count32 = Int32(bp.count)
            let n = BIO_write(bio, bp.baseAddress, count32)
            // BIOs in general do partial I/O, but we use a memory BIO
            // which grows to accommodate our data.  So let's assert
            // that it works as advertised.
            assertForReal(n == count32)
        }
    }

    func read(maxLength: Int?) -> [UInt8]? {
        var desired = usedSpace
        if let maxLength = maxLength {
            desired = min(desired, maxLength)
        }
        if desired == 0 {
            return nil
        }
        var bytes = byteArray(zeroFilledOfLength: desired)
        bytes.withUnsafeMutableBufferPointer { bp in
            let count32 = Int32(bp.count)
            let actual = BIO_read(bio, bp.baseAddress, count32)
            assertForReal(actual == count32)
        }
        return bytes
    }
}

class InMemoryOpenSSL: InMemoryTLS {
    static var BIO_SOFT_CAP: Int = 4096  // TODO: Tuning?

    var ssl: UnsafeMutablePointer<SSL>
    var _ingress: BioBuffer
    var _egress: BioBuffer

    var ingress: CipherTextBuffer { get { return _ingress } }
    var egress: CipherTextBuffer { get { return _egress } }

    init(ssl: UnsafeMutablePointer<SSL>) {
        self._ingress = BioBuffer(softCap: InMemoryOpenSSL.BIO_SOFT_CAP)
        self._egress = BioBuffer(softCap: InMemoryOpenSSL.BIO_SOFT_CAP)
        self.ssl = ssl
        SSL_set_bio(ssl, self._ingress.bio, self._egress.bio)
    }

    convenience init(ctx: OpenSSLContext) throws {
        ERR_clear_error()
        guard let ssl = SSL_new(ctx.ptr) else {
            throw InMemoryOpenSSL.getError()
        }
        // "When beginning a new handshake, the SSL engine must know
        // whether it must call the connect (client) or accept (server)
        // routines. Even though it may be clear from the method chosen,
        // whether client or server mode was requested, the handshake
        // routines must be explicitly set."
        switch ctx.side {
        case .serverSide: SSL_set_accept_state(ssl)
        case .clientSide: SSL_set_connect_state(ssl)
        }
        self.init(ssl: ssl)
    }

    // SSL_free -- includes bios

    /// decrypt data into the buffer, up to the given length,
    ///   - returning the bytes actually read (always > 0)
    ///   - Or 0 on close notify alert
    ///   - Or nil if IO is required.
    ///   - throws on errors other than pending IO and closure
    ///
    /// TODO: take a buffer pointer instead of two arguments?
    func readPlaintext(intoBuffer buffer: UnsafeMutableRawPointer, maxLength: Int)
      throws -> Int?
    {
        ERR_clear_error()
        let n = SSL_read(ssl, buffer, Int32(maxLength))
        if n <= 0 {
            let err = SSL_get_error(ssl, n)
            switch err {
            case SSL_ERROR_WANT_READ, SSL_ERROR_WANT_WRITE:
                return nil
            case SSL_ERROR_ZERO_RETURN:
                return 0
            case SSL_ERROR_SSL:
                throw InMemoryOpenSSL.getError()
            case _:
                throw SecureError.Unexpected("SSL_read \(err)")
            }
        }
        return Int(n)
    }

    /// encrypt data into the buffer, up to the given length,
    ///   - returning the bytes actually written (always > 0)
    ///   - Or 0 on close notify alert
    ///   - Or nil if IO is required.
    ///   - throws on errors other than pending IO and closure
    ///
    /// OpenSSL doesn't do partial writes unless we enable that
    /// behaviour explicitly.  But let's still return an Int? here
    /// for symmetry with the read method.
    ///
    /// TODO: take a buffer pointer instead of two arguments?
    func writePlaintext(fromBuffer buffer: UnsafeRawPointer, ofLength: Int)
      throws -> Int?
    {
        ERR_clear_error()
        let n = SSL_write(ssl, buffer, Int32(ofLength))
        if n <= 0 {
            let err = SSL_get_error(ssl, n)
            switch err {
            case SSL_ERROR_WANT_READ, SSL_ERROR_WANT_WRITE:
                return nil
            case SSL_ERROR_ZERO_RETURN:
                return 0
            case SSL_ERROR_SSL:
                throw InMemoryOpenSSL.getError()
            case _:
                throw SecureError.Unexpected("SSL_write \(err)")
            }
        }
        assertForReal(n == Int32(ofLength))
        return Int(n)
    }

    func shutdown() throws -> Bool {
        ERR_clear_error()
        let n = SSL_shutdown(ssl)
        if n >= 0 {
            return n > 0
        }
        let err = SSL_get_error(ssl, n)
        switch err {
        case SSL_ERROR_SSL:
            throw InMemoryOpenSSL.getError()
        case _:
            throw SecureError.Unexpected("SSL_shutdown \(err)")
        }
    }

    /// To be called after SSL_ERROR_SSL.
    static func getError() -> Error {
        let code = ERR_get_error()
        let hopefullyEnough = 256
        var a = byteArray(zeroFilledOfLength: hopefullyEnough)
        a.withUnsafeMutableBufferPointer { bp in
            bp.baseAddress!.withMemoryRebound(
              to: Int8.self, capacity: bp.count) {
                ptr in ERR_error_string_n(code, ptr, bp.count)
            }
        }
        return SecureError.SSL_ERROR_SSL(
          String(data: Data(a), encoding: .utf8)!)
    }
}
