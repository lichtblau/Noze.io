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

public protocol DispatchIOnesque: class {
    var fileDescriptor: Int32 { get }
    func setLimit(lowWater: Int)
    func close(flags: Dispatch.DispatchIO.CloseFlags)
    func read(offset: off_t,
              length: Int,
              queue: DispatchQueue,
              ioHandler: @escaping (Bool, DispatchData?, Int32) -> Void)
    func write(offset: off_t,
               data: Dispatch.DispatchData,
               queue: DispatchQueue,
               ioHandler: @escaping (Bool, DispatchData?, Int32) -> Void)
}

extension DispatchIO: DispatchIOnesque { }
extension DispatchTLS: DispatchIOnesque { }

/// SSL libraries like to do read and write calls similar to
/// non-blocking POSIX calls, which is a slight mismatch for the
/// event-driven APIs we use with libdispatch: The former want partial
/// reads which return pending data synchronously.  The latter only give
/// us the pending data in an asynchronous callback.
///
/// So we paper over this difference using an explicit memory buffer
/// that is under our control, making SSL read and write from/to memory
/// while using libdispatch to push data into this buffer and pausing
/// the dispatch source when the buffer is full.  The details differ
/// slightly between OpenSSL (to avoid implementing our own BIO for
/// callbacks, we use a memory BIO) and Secure Transport (here we keep
/// the memory buffer on the Swift side to implement IO callbacks).
///
/// Key to the buffering strategy is that data accepted in each
/// direction must be throttled to the speed at which the other
/// direction is sending it, otherwise we would buffer data arbitrary.

public enum SecureError : Swift.Error {
    // Documentation says: "A failure in the SSL library occurred,
    // usually a protocol error.  The OpenSSL error queue contains more
    // information on the error."  -- We take one error out of the queue
    // and use it as the description.
    case SSL_ERROR_SSL(String)
    // Some generic OpenSSL error we were not quite prepared for.
    case Unexpected(String)
    // Unclean shutdown of the underlying socket.  This is not a close
    // notify alert.  Same as SocketError in terms of security
    // implications, but separate for debugging.
    case UncleanClose
    // Something went wrong with the underlying DispatchIO
    case SocketError(Int32)
}

// With Secure Transport, we get this enum for free.  It's good design,
// so let's imitate it on OpenSSL.
#if os(Linux)
enum SSLProtocolSide {
    case serverSide
    case clientSide
}
#endif

/// Terminological confusion ahead:
///
/// |------------------+---------------+------------------|
/// |                  | context class | per socket class |
/// |------------------+---------------+------------------|
/// | Noze             | TLSContext    | InMemoryTLS      |
/// | OpenSSL          | SSLContext    | SSL              |
/// | Secure Transport | ?             | SSLContext       |
/// |------------------+---------------+------------------|

/// Shared context and factory for TLS sockets and holds state that is
/// shared among them, namely general configuration (which we set) and
/// session resumption information (hich the underlying library
/// maintains for us in its context object).
protocol TLSContext: class {
    func makeSocket() throws -> InMemoryTLS
}

/// SSL from memory, to memory.
///
/// Abstracts over the SSL instance of the underlying SSL library, but
/// buffers ciphertext in memory through the CipherTextBuffer instances.
///
/// Whoever uses this class gets to push ciphertext into the ingress
/// buffer (from whatever source, presumably a socket, they got it).
/// And they are responsible for pulling fresh ciphertext out of the
/// egress buffer and writing it somewhere (presumably the same socket).
///
/// For plaintext, we do not manage the buffers and instead expect the
/// caller to provide a suitable buffer.
///
/// See DispatchTLS to see which read and write is to be triggered when.
protocol InMemoryTLS: class {
    var ingress: CipherTextBuffer { get }
    var egress: CipherTextBuffer { get }
    func shutdown() throws -> Bool
    func readPlaintext(intoBuffer buffer: UnsafeMutableRawPointer, maxLength: Int)
        throws -> Int?
    func writePlaintext(fromBuffer: UnsafeRawPointer, ofLength: Int)
        throws -> Int?
}

extension InMemoryTLS {
    func readPlaintext(intoArray bytes: inout [UInt8]) throws -> Int? {
        return try bytes.withUnsafeMutableBufferPointer {
            bp in try readPlaintext(
                 intoBuffer: UnsafeMutableRawPointer(bp.baseAddress!),
                 maxLength: bp.count)
        }
    }

    func writePlaintext(fromArray bytes: [UInt8]) throws -> Int? {
        return try bytes.withUnsafeBufferPointer {
            bp in try writePlaintext(
                 fromBuffer: UnsafeRawPointer(bp.baseAddress!),
                 ofLength: bp.count)
        }
    }
}

// An in-memory buffer which grows without bounds.
// On OpenSSL, this can implemented using the built-in memory BIO.
// With Secure Transport, a pure Swift version can be used.
protocol CipherTextBuffer: class {
    var usedSpace: Int { get }
    var availableSpace: Int { get }
    var softCap: Int { get }
    func write(bytes: [UInt8])
    func write(dispatchData: DispatchData)
    func read() -> [UInt8]?
    func read(maxLength: Int?) -> [UInt8]?
    func readDispatchData() -> DispatchData?
}

extension CipherTextBuffer {
    // The buffer is fundamentally of variable size, but we have a
    // notion of it being full (or indeed, over-full) when it reaches
    // our soft size cap.  The soft limit works by inserting a given
    // batch of data only when there is some head room left -- but we
    // don't slice the data to be inserted to fit exactly.  This way we
    // can exceed the cap, but will never exceed it by more than one
    // buffer size.  Which is admittedly a bit vague, given that buffers
    // come from the user, but presumably users who are concerned about
    // memory use won't be inserting huge buffers.
    var availableSpace: Int {
        get { return max(0, softCap - usedSpace) }
    }

    func read() -> [UInt8]? {
        return read(maxLength: nil)
    }

    func write(dispatchData: DispatchData) {
        write(bytes: arrayFromDispatchData(dispatchData))
    }

    func readDispatchData() -> DispatchData? {
        return read().map(dispatchDataFromArray)
    }
}

#if os(Linux)
typealias DefaultTLSContext = OpenSSLContext
#else
typealias DefaultTLSContext = SecureTransportContext
#endif

/// Like assert, but without the scary behaviour where release builds
/// ruthlessly optimize everything away.  Let's still use an autoclosure
/// though, so that we could inline and ifdef away the body based on an
/// explicit flag if we wanted to.
func assertForReal(_ condition: @autoclosure () -> Bool,
                   file: String = #file,
                   line: Int = #line)
{
    if !condition() {
        print("assertion failed at \(file):\(line)")
        // How does one trap without assert?  I suppose this ought to work:
        _ = (nil as Bool?)!
    }
}
