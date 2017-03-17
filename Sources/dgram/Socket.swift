//
//  Socket.swift
//  Noze.io
//
//  Created by Helge Heß on 4/17/16.
//  Copyright © 2016 ZeeZide GmbH. All rights reserved.
//

import Dispatch
import xsys
import core
import events
import fs
import net

public typealias Datagram = (data: [UInt8], peer: SocketAddress)

public typealias MessageCB = (Datagram) -> Void
public typealias SocketEventCB = ( Socket ) -> Void

/// TODO: doc
open class Socket : ErrorEmitter, LameLogObjectType {
  public let log          : Logger
  public var fd           : FileDescriptor?     = nil // fd can be invalid too
  public var address      : sockaddr_any?       = nil
  public var receiveSource: DispatchSourceProtocol? = nil
  public var sendSource   : DispatchSourceProtocol? = nil
  public let Q            : DispatchQueue
  public var didRetainQ   : Bool = false // #linux-public
  public var sendBuffer   : [Datagram] = []

  public init(queue          : DispatchQueue = core.Q,
              enableLogger   : Bool = false)
  {
    self.Q   = queue
    self.log = Logger(enabled: enableLogger)

    super.init()

    log.onAfterEnter  = { [unowned self] log in self.logState() }
    log.onBeforeLeave = { [unowned self] log in self.logState() }
  }
  deinit {
    self._primaryClose()

    if self.didRetainQ {
      core.module.release()
      self.didRetainQ = false
    }
  }


  // MARK: - Binding

  @discardableResult
  open func bind(_ port      : Int? = nil,
                 exclusive   : Bool = false,
                 onListening : SocketEventCB? = nil) -> Self
  {
    if let cb = onListening { _ = self.onListening(handler: cb) }

    // TODO: How to decide between IPv4 and IPv6? Node says it's using v6 when
    //       available.
    let address = xsys_sockaddr_in(port: port)

    return self.bind(address, exclusive: exclusive)
  }

  @discardableResult
  public func bind(_ address: sockaddr_any,
                   exclusive: Bool = false) -> Self {
    switch address {
      case .AF_INET (let addr): return bind(addr, exclusive: exclusive)
      case .AF_INET6(let addr): return bind(addr, exclusive: exclusive)
      case .AF_LOCAL(let addr): return bind(addr, exclusive: exclusive)
    }
  }

  @discardableResult
  public func bind<AT: SocketAddress>(_ address: AT,
                                      exclusive: Bool = false) -> Self
  {
    // Note: Everything here runs synchronously, which I guess is fine in this
    //       specific case?
    // TBD:  We could dispatch it, but is it worth? Maybe. More stuff could be
    //       going on (connections to watchdogs etc).
    let log = self.log
    log.enter(); defer { log.leave() }
    log.debug("   address: \(address)")


    // setup socket if necessary

    if fd == nil {
      let rc = _setupSocket(domain: AT.domain)
      guard rc == 0 else { return caught(error: xsys.errno) } // TODO: better err
    }
    assert(fd?.isValid ?? false)


    // set SO_REUSEADDR
    if !exclusive {
      let rc = _makeNonExclusive(fd: fd!)
      guard rc == 0 else { return caught(error: xsys.errno) } // TODO: better err
    }

    // bind socket

    let brc = _bind(address: address)
    guard brc == 0 else { return caught(error: xsys.errno) } // TODO: better err


    // determine the address we bound to

    let boundAddress : AT? = getasockname(fd: fd!.fd, xsys.getsockname)
    self.address = sockaddr_any(boundAddress)
    assert(self.address != nil)


    // setup GCD source

    let receiveSource = DispatchSource.makeReadSource(fileDescriptor: fd!.fd,
                                                      queue: self.Q)
    self.receiveSource = receiveSource
    if !self.didRetainQ { core.module.retain() }


    // setup GCD callback
    // Note: This creates a retain-cycle, which is kinda the right thing to do
    //       (Socket object should not go away until the dispatch source is
    //        active? Or should it go away an drop the source properly)
    //       In other words: the server only goes away if it is closed.
    receiveSource.setEventHandler {
      self._onMessage(address: boundAddress)
    }
    receiveSource.resume()

    let sendSource = DispatchSource.makeWriteSource(fileDescriptor: fd!.fd,
                                                    queue: self.Q)
    self.sendSource = sendSource
    sendSource.setEventHandler {
      self._send()
    }

    // make non-blocking
    fd!.isNonBlocking = true


    // finish up

    nextTick {
      self.listeningListeners.emit(self)
    }
    return self
  }

  // MARK: - Accepting

  public func _onMessage<AT: SocketAddress>(address localAddress: AT?) {
    // #linux-public
    // This is cheating a little, we pass in the localAddress to capture the
    // generic socket type (which matches the one returned by accept().
    log.enter(); defer { log.leave() }

    let (err, buf, peer) = recvfrom(self.fd!, likeAddress: localAddress)
    if let err = err {
        self.caught(error: err)
    } else {
        self.messageListeners.emit((buf!, peer!))
    }
  }

  // MARK: - Binding

  public func _bind<AT: SocketAddress>(address a: AT) -> Int32 { // #linux-public
    var address = a
    return withUnsafePointer(to: &address) { ptr -> Int32 in
      return ptr.withMemoryRebound(to: xsys_sockaddr.self, capacity: 1) {
        bptr in
        return xsys.bind(fd!.fd, bptr, socklen_t(address.len))
      }
    }
  }


  // MARK: - sending

  // TODO: node's completion callback -- not sure how important it is for
  // a transport without delivery guarantee, but would be nice to have
  public func send(_ data: [UInt8], to peer: SocketAddress) {
      if sendBuffer.count == 0 {
          sendSource!.resume()
      }
      sendBuffer.append((data, peer))
  }

  func _send() {
      let (data, peer) = sendBuffer.removeFirst() // TODO: performance?
      if let err = sendto(self.fd!, data: data, to: peer) {
          self.caught(error: err)
      }
      if sendBuffer.count == 0 {
          sendSource!.suspend()
      }
  }

  // MARK: - Reuse server socket

  public func _makeNonExclusive(fd lfd: FileDescriptor) -> Int32 { // #linux-public
    var buf    = Int32(1)
    let buflen = socklen_t(MemoryLayout<Int32>.stride)
    let rc     = xsys.setsockopt(lfd.fd, xsys.SOL_SOCKET, xsys.SO_REUSEADDR,
                                 &buf, buflen)
    return rc
  }

  // MARK: - Closing the socket

  open func close() {
    _close()
  }

  public func _primaryClose() { // #linux-public
    if receiveSource != nil {
      receiveSource!.cancel()
      receiveSource = nil
    }

    if let fd = self.fd {
      fd.close()
      self.fd = nil
    }
    self.address = nil
  }

  public func _close() { // #linux-public
    log.enter(); defer { log.leave() }

    _primaryClose()

    // notify close listeners
    nextTick {
      self.closeListeners.emit(self)
      self.listeningListeners.removeAllListeners()

      if self.didRetainQ {
          core.module.release()
          self.didRetainQ = false
      }
    }
  }


  // MARK: - Create socket

  public func _setupSocket(domain d: Int32, type: Int32 = xsys.SOCK_DGRAM)
               -> Int32 // #linux-public
  {
    assert(fd == nil)

    let sockfd = xsys.socket(d, type, 0)
    log.debug("setup socket: \(sockfd)")
    guard sockfd != -1 else {
      log.debug("  failed: \(xsys.errno)")
      return xsys.errno
    }

    fd = FileDescriptor(sockfd)
    log.debug("  FD: \(fd)")
    return 0
  }


  // MARK: - Events

  public var closeListeners      = EventOnceListenerSet<Socket>()
  public var listeningListeners  = EventListenerSet<Socket>()
  public var messageListeners    = EventListenerSet<Datagram>()

  @discardableResult
  public func onClose  (handler cb: @escaping SocketEventCB) -> Self {
    closeListeners.add(handler: cb);                  return self
  }
  @discardableResult
  public func onceClose(handler cb: @escaping SocketEventCB) -> Self {
    closeListeners.add(handler: cb, once: true);      return self
  }

  @discardableResult
  public func onListening(handler cb: @escaping SocketEventCB) -> Self
  {
    listeningListeners.add(handler: cb);              return self
  }
  @discardableResult
  public func onceListening(handler cb: @escaping SocketEventCB) -> Self
  {
    listeningListeners.add(handler: cb, once: true);  return self
  }

  @discardableResult
  public func onMessage(handler cb: @escaping MessageCB) -> Self {
    messageListeners.add(handler: cb);                return self
  }
  @discardableResult
  public func onceMessage(handler cb: @escaping MessageCB) -> Self {
    messageListeners.add(handler: cb, once: true);    return self
  }

  // MARK: - ErrorEmitter

  public func caught(error e: Error) { // #linux-public
    log.enter(); defer { log.leave() }
    self.errorListeners.emit(e)
  }

  public func caught(error e: Int32, close: Bool = true) -> Self {
    // #linux-public
    caught(error: POSIXErrorCode(rawValue: e)!)
    if close { _close() }
    return self
  }


  // MARK: - Logging

  open var logStateInfo : String {
    var s = ""
    if let address = address { s += " \(address)" }
    if let fd      = fd      { s += " fd=\(fd.fd)" }
    return s
  }

  open func logState() {
    guard log.enabled else { return }
    log.debug("[\(logStateInfo)]")
  }

}
