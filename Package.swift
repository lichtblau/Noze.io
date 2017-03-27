import PackageDescription

let package = Package(
  name:         "NozeIO",
  targets:      [
    Target(name: "Freddy"),
    Target(name: "CryptoSwift"),
    Target(name: "base64"),
    Target(name: "mustache"),
    
    Target(name: "xsys"),
    Target(name: "core",
           dependencies: [
	     .Target(name: "xsys")
	   ]),
    Target(name: "leftpad",
           dependencies: [
	     .Target(name: "core")
	   ]),
    Target(name: "events",
           dependencies: [
	     .Target(name: "core")
	   ]),
    Target(name: "streams",
           dependencies: [
	     .Target(name: "core"),
	     .Target(name: "events")
	   ]),
    Target(name: "json",
           dependencies: [
	     .Target(name: "core"),
	     .Target(name: "streams"),
	     .Target(name: "Freddy"),
             .Target(name: "fs")
	   ]),
    Target(name: "fs",
           dependencies: [
	     .Target(name: "core"),
	     .Target(name: "xsys"),
	     .Target(name: "events"),
	     .Target(name: "streams")
	   ]),
    Target(name: "crypto",
           dependencies: [
             .Target(name: "core"),
             .Target(name: "xsys"),
             .Target(name: "events"),
             .Target(name: "streams"),
             .Target(name: "CryptoSwift")
           ]),
    Target(name: "dns",
           dependencies: [
	     .Target(name: "core"),
	     .Target(name: "xsys")
	   ]),
    Target(name: "net",
           dependencies: [
	     .Target(name: "core"),
	     .Target(name: "xsys"),
	     .Target(name: "events"),
	     .Target(name: "streams"),
	     .Target(name: "fs"),
             .Target(name: "dns")
	   ]),
    Target(name: "dgram",
           dependencies: [
	     .Target(name: "net"),
	   ]),
    Target(name: "process",
           dependencies: [
	     .Target(name: "core"),
	     .Target(name: "xsys"),
	     .Target(name: "streams"),
	     .Target(name: "fs")
	   ]),
    Target(name: "console",
           dependencies: [
	     .Target(name: "core"),
	     .Target(name: "xsys"),
	     .Target(name: "events"),
	     .Target(name: "streams"),
	     .Target(name: "process")
	   ]),
    Target(name: "child_process",
           dependencies: [
	     .Target(name: "core"),
	     .Target(name: "xsys"),
	     .Target(name: "streams"),
	     .Target(name: "process"),
	     .Target(name: "fs")
	   ]),
    Target(name: "redis",
           dependencies: [
	     .Target(name: "core"),
	     .Target(name: "xsys"),
	     .Target(name: "events"),
	     .Target(name: "streams"),
	     .Target(name: "net"),
	     .Target(name: "console")
	   ]),
    Target(name: "cows",
           dependencies: [
	     .Target(name: "core"),
	     .Target(name: "xsys")
	   ])
  ],
  dependencies: []
)
