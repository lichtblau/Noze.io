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

import Dispatch
import Foundation
import xsys
import core

public typealias IOHandler = (Bool, DispatchData?, Int32) -> Void

// List of byte array types in Swift to choose from (no claim regarding
// exhaustiveness of the list):
//
//   - NSData
//   - NSMutableData
//   - DispatchData
//   - [UInt8]
//   - ArraySlice<UInt8>
//   - Data
//   - MutableRandomAccessSlice<Data> (?!)
//   - MutableRangeReplaceableRandomAccessSlice<Data> (?!)
//
// Honorable mention:
//   - Unsafe*BufferPointer
//
// The revolution has takenplace, and finally Data.subscript(bounds:
// Range<Data.Index>) returns a Data instead of a Mutable*Scariness<Data>.
// Maybe that's the future then, performance traps notwithstanding.
//
// But we can keep using arrays.  Arrays are nice -- and some places
// could even switch to the underrated ArraySlice<UInt8> for more
// generality.

// Should we then repeatedly shuffle those bytes around?  Of course.
func arrayFromDispatchData(_ data: DispatchData) -> [UInt8] {
    let n = data.count
    var a = byteArray(zeroFilledOfLength: n)
    a.withUnsafeMutableBufferPointer { ptr in
        data.copyBytes(to: ptr.baseAddress!, count: n)
    }
    return a
}

func dispatchDataFromArray(_ bytes: [UInt8]) -> DispatchData {
    return bytes.withUnsafeBufferPointer {
        bp in DispatchData(bytes: bp)
    }
}

func dispatchDataFromArray(_ bytes: [UInt8], to: Int) -> DispatchData {
    return bytes.withUnsafeBufferPointer {
        bp in DispatchData(bytes: UnsafeBufferPointer(
                             start: bp.baseAddress,
                             count: to))
    }
}

/// TODO: Can this be the best way of making an array?  Though at least
/// these look like they are not performance trap constructors with
/// hidden iteration disasters, unlike init(repeating:count:).
func byteArray(zeroFilledOfLength length: Int) -> [UInt8] {
    return [UInt8](Data(count: length))
}

/// Represents a single read() or write() request for a DispatchIO by
/// combining the data and handler to call when we're done.
///
/// We don't coalesce successive operations, so each one has a nice,
/// fixed-size buffer.
///
/// OpenSSL has a totally silly assertion about "moving" buffers.  Note
/// that if we ever plan on mutating the bytes array here through Swift,
/// and with an extra reference triggering copy-on-write behaviour, we'd
/// have to enable the funny flag disabling the silly assertion.  Maybe
/// we should do that either way, because who are they to tell us what
/// to do with our buffer?
///
/// The callback has a done flag, but we never emit it with a false
/// value.  We're doing partial reads, and then consider the job done.
/// Is that correct?
class PendingIoOperation {
    var bytes: [UInt8]
    var onProgress: IOHandler
    var queue: DispatchQueue

    var count: Int {
        get { return bytes.count }
    }

    init(bytes: [UInt8],
         onProgress: @escaping IOHandler,
         queue: DispatchQueue) {
        self.bytes = bytes
        self.onProgress = onProgress
        self.queue = queue
    }

    convenience init(data: DispatchData,
                     onProgress: @escaping IOHandler,
                     queue: DispatchQueue) {
        self.init(bytes: arrayFromDispatchData(data),
                  onProgress: onProgress,
                  queue: queue)
    }

    convenience init(zeroFilledOfLength length: Int,
                     onProgress: @escaping IOHandler,
                     queue: DispatchQueue) {
        self.init(bytes: byteArray(zeroFilledOfLength: length),
                  onProgress: onProgress,
                  queue: queue)
    }

    func dispatchData(to: Int? = nil) -> DispatchData {
        if let to = to {
            return dispatchDataFromArray(bytes, to: to)
        } else {
            return dispatchDataFromArray(bytes)
        }
    }

    func failed(withError error: Int32, pending buffer: DispatchData? = nil) {
        queue.async {
            self.onProgress(true, buffer, error)
        }
    }
}

class PendingRead: PendingIoOperation {
    func done(readingTo to: Int? = nil) {
        let data = self.dispatchData(to: to)
        queue.async {
            self.onProgress(true, data, 0)
        }
    }

    func eof() {
        queue.async {
            self.onProgress(true, nil, 0)
        }
    }
}

class PendingWrite: PendingIoOperation {
    func done(pendingWriteOf buffer: DispatchData?) {
        queue.async {
            self.onProgress(buffer == nil, buffer, 0)
        }
    }

    func eof() {
        let unwritten = dispatchDataFromArray(bytes)
        queue.async {
            self.onProgress(true, unwritten, 0)
        }
    }
}

// FSM for closing the sending direction of the SSL connection,
// i.e. whether we want to send, or have sucessfully sent, a close
// notify alert.  Here we do not track whether we have received such an
// alert from the other side -- those are merely relayed to the caller,
// who can decide when to call close on DispatchSSL.  There is one
// interaction between the two types though: If the force flag to
// ShutdownRequested is true, then we might call SSL_shutdown (c.f. its
// documentation) twice to put things to an end.
enum ShutdownRequest {
    case Open
    case ShutdownRequested(Bool) // should we close both?
    case ShutdownSent
    case Closed
}

/// DispatchTLS: looks a bit like DispatchIO but uses SSL.
///
/// To access the encrypted socket, we wrap a real DispatchIO.  Not sure
/// this is optimal -- would we be better served using two dispatch
/// sources directly?
public class DispatchTLS {
    static var _client: DefaultTLSContext! = nil
    static var _server: DefaultTLSContext! = nil
    static var initialized = false

    static var client: DefaultTLSContext {
        get {
            ensureInitialized()
            return _client!
        }
    }

    static var server: DefaultTLSContext {
        get {
            ensureInitialized()
            return _server!
        }
    }

    static func ensureInitialized() {
        if !initialized {
            do {
                try initialize()
                initialized = true
            } catch {
                // TODO?
                assertForReal(false)
            }
        }
    }

    static func initialize() throws {
        _client = try DefaultTLSContext(side: .clientSide)
        _server = try DefaultTLSContext(side: .serverSide)
    }

    public var fileDescriptor: Int32
    var ssl: InMemoryTLS
    var queue: DispatchQueue
    var cleanupHandler: (_ error: Int32) -> Void
    var io: DispatchIO!
    var isReadingCiphertext: Bool = false
    var isWritingCiphertext: Bool = false
    var pendingReads: [PendingRead] = []
    var pendingWrites: [PendingWrite] = []
    var shutdownRequest: ShutdownRequest = .Open
    var error: Error? = nil

    public init(fileDescriptor: Int32,
                queue: DispatchQueue,
                cleanupHandler: @escaping (_ error: Int32) -> Void)
        throws
    {
        self.fileDescriptor = fileDescriptor
        self.queue = queue
        self.cleanupHandler = cleanupHandler
        self.ssl = try DispatchTLS.client.makeSocket() // TODO: server
        self.io = DispatchIO(type: DispatchIO.StreamType.stream,
                             fileDescriptor: fileDescriptor,
                             queue: queue) {
            errno in self.onSocketClose(errno)
        }
        self.io.setLimit(lowWater: 1)
        queue.async {
            self.tryReadingCiphertext()
        }
    }

    func onSocketClose(_ errno: Int32) {
        switch shutdownRequest {
        case .Closed:
            // that's cool then
            break
        default:
            self.error = SecureError.SocketError(errno)
            step()
        }
    }

    func tryReadingCiphertext() {
        let maxLength = self.ssl.ingress.availableSpace
        if !isReadingCiphertext && maxLength > 0 {
            isReadingCiphertext = true
            io.read(offset: 0, length: maxLength, queue: queue) {
                (done, data, errno) in
                if errno != 0 {
                    self.error = SecureError.SocketError(errno)
                }
                if done {
                    self.isReadingCiphertext = false
                }
                if let data = data {
                    // TODO Noze has very fancy EOF detection here; how
                    // does it work?
                    if data.count == 0 {
                        // This means EOF, but in correct SSL shutdown
                        // for both directions we wouldn't have gotten
                        // here.  So something would have gone wrong,
                        // and we will get that error or cleanup handler
                        // elsewhere.  Let's simply prevent further
                        // attempts to read from the socket:
                        self.isReadingCiphertext = true
                    }
                    self.ssl.ingress.write(dispatchData: data)
                }
                self.step()
            }
        }
    }

    func tryWritingCiphertext() {
        if !isWritingCiphertext {
            if let data = ssl.egress.readDispatchData() {
                isWritingCiphertext = true
                io.write(offset: 0, data: data, queue: queue) {
                    (done, pendingData, errno) in
                    if errno != 0 {
                        self.error = SecureError.SocketError(errno)
                    }
                    if done {
                        self.isWritingCiphertext = false
                    }
                    self.step()
                }
            }
        }
    }

    // TODO: suboptimal
    func step() {
        switch shutdownRequest {
        case .Closed:
            return
        case .Open, .ShutdownRequested, .ShutdownSent:
            break
        }
        if self.error == nil {
            do {
                try step0()
            } catch {
                self.error = error
            }
        }
        if let error = self.error {
            print("ERROR: \(error)")
            // Unfortunately we only get to return an errno, not throw
            // an Error.  (Even if the error has an errno from the
            // underlying socket, I suspect we probably don't want to
            // pass it up, because all underlying socket errors are the
            // same to us, right?)
            if let op = pendingReads.first {
                op.failed(withError: EIO)
                pendingReads.removeFirst()
            } else if let op = pendingWrites.first {
                op.failed(withError: EIO)
                pendingWrites.removeFirst()
            }
        }
    }

    func step0() throws {
        var progress: Bool
        repeat {
            progress = false
            switch shutdownRequest {
            case .ShutdownSent, .Closed:
                break
            case .ShutdownRequested:
                // 0. shutdown
                try stepShutdown()
            case .Open:
                // 1. SSL_read -- only as much as the caller has asked for,
                // and leaving the read pending if it requires I/O
                if try stepRead() { progress = true }
                // 2. SSL_write -- write cleartext only if the ciphertext
                // output buffer isn't full.  Again leaving the write
                // pending if it needs to be retried for I/O reasons
                if try stepWrite() { progress = true }
            }
            // 3. We might try to read ciphertext -- this function will
            // take care of checking the buffer for space and if
            // available, an asynchronous read callback will call us
            // again
            tryReadingCiphertext()
            // 4. We might need to write ciphertext -- this function
            // will do so if no other write is pending
            tryWritingCiphertext()
            // Consider more requests from the caller which are pending
            // if we managed to fulfil one of them just now.
        } while progress
    }

    func stepShutdown() throws {
        switch shutdownRequest {
        case .ShutdownRequested(let force):
            var done = try ssl.shutdown()
            if !done && force {
                done = try ssl.shutdown()
            }
            if done {
                shutdownRequest = .Closed
                self.io.close()
                self.cleanupHandler(0)
            } else if force {
                shutdownRequest = .Closed
                self.io.close(flags: DispatchIO.CloseFlags.stop)
                self.cleanupHandler(EIO)
            } else {
                shutdownRequest = .ShutdownSent
            }
        default:
            break
        }
    }

    func stepRead() throws -> Bool {
        if let op = pendingReads.first {
            if let n = try ssl.readPlaintext(intoArray: &op.bytes) {
                if n == 0 {
                    op.eof()
                    noteCloseNotify()
                } else {
                    op.done(readingTo: n)
                    pendingReads.removeFirst()
                    return pendingReads.count > 0
                }
            }
        }
        return false
    }

    func stepWrite() throws -> Bool {
        if let op = pendingWrites.first {
            if ssl.egress.availableSpace > 0 {
                // we're willing to overflow the available space, but
                // for at most one chunk of bytes at any time
                if let n = try ssl.writePlaintext(fromArray: op.bytes) {
                    if n == 0 {
                        op.eof()
                        noteCloseNotify() // hmm
                    } else {
                        // We don't enable partial writes in OpenSSL
                        // yet, so they should be impossible.  But I
                        // prefer having the assertion here where we
                        // could generalize the code, instad of in the
                        // socket class which isn't responsible for
                        // buffer management.
                        assertForReal(n == op.count)
                        op.done(pendingWriteOf: nil)
                        pendingWrites.removeFirst()
                        return pendingWrites.count > 0
                    }
                }
            }
        }
        return false
    }

    func noteCloseNotify() {
        switch shutdownRequest {
        case .Open, .ShutdownRequested(_):
            // The receiving direction has shut down.  But
            // the user needs to close() us in order perform
            // the shutdown in the other direction.
            break
        case .ShutdownSent, .Closed:
            // This was it.
            shutdownRequest = .Closed
            self.io.close(flags: DispatchIO.CloseFlags.stop)
            self.cleanupHandler(0)
        }
    }

    public func setLimit(lowWater: Int) {
        // ignored -- we only need this declaration to fit our
        // triangular SSL peg into the square DispatchIO protocol to the
        // precise extent required by GCDCChannelBase.
    }

    public func close(flags: Dispatch.DispatchIO.CloseFlags) {
        queue.async {
            switch self.shutdownRequest {
            case .Open, .ShutdownRequested(_):
                self.shutdownRequest = .ShutdownRequested(
                  flags.contains(DispatchIO.CloseFlags.stop))
                self.step()
            case .ShutdownSent:
                break
            case .Closed:
                break
            }
        }
    }

    public func read(offset: off_t,
                     length: Int,
                     queue: DispatchQueue,
                     ioHandler: @escaping IOHandler) {
        self.queue.async {
            self.pendingReads.append(PendingRead(
                                       zeroFilledOfLength: length,
                                       onProgress: ioHandler,
                                       queue: queue))
            self.step()
        }
    }

    public func write(offset: off_t,
                      data: Dispatch.DispatchData,
                      queue: DispatchQueue,
                      ioHandler: @escaping IOHandler) {
        let bytes = arrayFromDispatchData(data)
        self.queue.async {
            self.pendingWrites.append(PendingWrite(
                                        bytes: bytes,
                                        onProgress: ioHandler,
                                        queue: queue))
            self.step()
        }
    }
}
