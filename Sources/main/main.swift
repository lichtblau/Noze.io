import Foundation
import core
import net

class Flupp {
    func writeRequest(to sock: Socket) {
        sock.write("GET / HTTP/1.0\r\n")
        sock.write("Content-Length: 0\r\n")
        sock.write("Host: zeezide.com\r\n")
        sock.write("\r\n")
        // old comment says:
        //   end() would immediately close socket
        // see mutterings about that below
    }

    func testSocketBasicHTTPWriteRightAway() {
        let sock = Socket(tls: true)
          .connect(port: 443,
                   host: "www.google.fi") { sock in
              print("connected... somewhere... maybe...")
              self.writeRequest(to: sock)
          }

        sock.onError { error in
            print("error on connect: \(error)")
        }

        sock.onReadable {
            while let bucket = sock.read() {
                print("bucket: \(String(data: Data(bucket), encoding: .utf8)!)")
            }
        }

        sock.onEnd {
            // This will never happen, because SSL tells Noze that the
            // read direction has been shut down, and then we'd have to
            // shut down the write direction if and when we feel like it
            // (or indeed earlier, just after writing the request!), but
            // none of that seems to be happening.  I don't even know
            // what the methods and events for shutdown of the two
            // directions are in Noze.  Something needs figuring out here.
            //
            // In real Node, I assume:
            //   - allowHalfOpen needs to be set to true
            //   - .end() is write shutdown
            //   - then the 'end' is read shutdown
            // But there's a comment in the socket saying that end() in
            // nose is close, not shutdown.  I guess that would be the
            // problem then.
            print("SOCKET ENDED")
        }
    }
}

func main() {
    Flupp().testSocketBasicHTTPWriteRightAway()
    core.module.run()
}

main()
