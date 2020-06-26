# certifiable

[![Clojars Project](https://img.shields.io/clojars/v/com.bhauman/certifiable.svg)](https://clojars.org/com.bhauman/certifiable)

A helper tool that simplifies the creation of development time SSL
certificates for use with Java Webservers like Jetty.

Sometimes you just want a simple way to generate a Java Keystore file
that you can supply to a Java server so that you can enable HTTPS
development on your local machine.

Certifiable creates a secure root certificate on your machine that you
can trust because the root keys get deleted. It then creates a single
end user certificate and keys in the form of a Java Keystore.

This is more secure than the various tools that rely on you
trusting a single root certificate while retaining the roots keys to
allow the creation of more local certificates. While this is
convenient it certainly isn't safe.

Certifiable only relies the Java `keytool` command. Assuming that if
Java is installed then `keytool` will be available as well.

[Leiningen](https://leiningen.org) dependency information:

```clj
[com.bhauman/certifiable "0.0.5"]
```

[clj/deps.edn](https://clojure.org/guides/deps_and_cli) information:

```clj
{:deps {com.bhauman/certifiable {:mvn/version "0.0.5"}}}
```

This tool was built based on this [excellent shell script](https://gist.github.com/granella/01ba0944865d99227cf080e97f4b3cb6).

## Quick Docs

```shell
Generates a local developement Java keystore that can be used
to support SSL/HTTPS connections in a Java Server like Jetty.

Usage: clj -m certifiable.main [options] [command] [hostnames and ips]

Available Commands: (if no command is supplied "create" is the default)
 create [hosts and ips]  : takes a list of hostnames and ips and creates a keystore
                           if no hostnames or ips supplied defaults to
                           localhost www.locahost 127.0.0.1
 list                    : lists the current keystores
 info [name/list idx]    : displays info on the given store name or list index
 reset                   : deletes all keystores and removes the trust for them
 remove [name/list idx]  : deletes the given keystore and removes trust for it
 help                    : prints out these instructions


Options:
  -o, --output FILE  The path and filename of the jks output file
  -h, --help
  -v                 verbose - outputs more info about keytool calls
```

## Quick Start Command Line Usage

Make sure you have the [Clojure tools installed](https://clojure.org/guides/getting_started#_installation_on_mac_via_code_brew_code)

Then to generate a certificate execute the following:

```sh
$ clj -Sdeps '{:deps {com.bhauman/certifiable {:mvn/version "0.0.5"}}}' -m certifiable.main

[Certifiable] Generating root and ca keypairs
[Certifiable] Generating root certificate: ~/_certifiable_certs/localhost-1d070e4/dev-root-trust-this.pem
[Certifiable] Generating ca certificate signed by root
[Certifiable] Importing root and ca chain into ca.jks keystore
[Certifiable] Deleted trusted root certificate keys: ~/_certifiable_certs/localhost-1d070e4/dev-root.jks
[Certifiable] Generate private keys for server
[Certifiable] Generate a certificate for server signed by ca
[Certifiable] Importing complete chain into keystore at: ~/_certifiable_certs/localhost-1d070e4/dev-server.jks
[Certifiable] Deleted intermediate certificate authority keys: ~/_certifiable_certs/localhost-1d070e4/intermediate-certificate-authority.jks
[Certifiable] Generated Java Keystore file: ~/_certifiable_certs/localhost-1d070e4/dev-server.jks
[Certifiable] Attempting to add root certificate to MacOS login keychain.
[Certifiable] Cert "Certifiable dev root (localhost-1d070e4)" successfully added to MacOS login keychain!
[Certifiable] Attempting to add root certificate to Firefox nss trust store.
[Certifiable] Cert "Certifiable dev root (localhost-1d070e4) 756891964" successfully added to Firefox trust store!
--------------------------- Setup Instructions ---------------------------
Local dev Java keystore generated at: ~/_certifiable_certs/localhost-1d070e4/dev-server.jks
The keystore type is: "JKS"
The keystore password is: "password"
The root certificate is: ~/_certifiable_certs/localhost-1d070e4/dev-root-trust-this.pem
For System: root certificate is trusted
For Firefox: root certificate is trusted
Example SSL Configuration for ring.jetty.adapter/run-jetty:
{:ssl? true,
 :ssl-port 9533,
 :keystore
 "~/_certifiable_certs/localhost-1d070e4/dev-server.jks",
 :key-password "password"}
```

The file
`~/_certifiable_certs/localhost-1d070e4/dev-root-trust-this.pem` needs
to be trusted by your operating system and Firefox directly in order
to avoid the not trusted browser warnings.

On MacOS the above command will ask to have the generated certificate
imported into your keychain as a trusted certificate.

This command will also create a default Java Keystore for `localhost`,
`www.localhost` and `127.0.0.1` at
`~/_certifiable_certs/localhost-1d070e4/dev-server.jks` that you
can supply to a Clojure webserver like `ring.jetty.adapter` like so:

```clj
(require '[ring.adapter.jetty :refer [run-jetty]]

(run-jetty (fn [req] {:status 200 :content-type "text/plain" :body "Hi"}))
  {:join? false
   :port 9500
   :ssl? true
   :ssl-port 9533
   :keystore "[home-dir]/_certifiable_certs/localhost-1d070e4/dev-server.jks"
   :key-password "password"})
```

The password for the keystore is always `password`.

If everything worked properly and you have trusted the root
certificate then visiting `https://localhost:9533`,
`https://www.localhost:9533` and `https://127.0.0.1:9533` should all
work.

### Specify custom local domain

If you want your HTTPS server to be available on particular local
domain (I.E. `example.test`) first make sure you have the domain added it to your
`/etc/hosts` file. After you have done that you can call:

```sh
$ clj -Sdeps '{:deps {com.bhauman/certifiable {:mvn/version "0.0.5"}}}' -m certifiable.main create example.test localhost 127.0.0.2
```

That command will generate a new local development certifiable with a
custom the Subject Alternative Name section that includes both
`example.test`, `localhost` and `127.0.0.2`.

### Listing and getting info on available keystores

The `list` command will list available keystores

```sh
$ clj -Sdeps '{:deps {com.bhauman/certifiable {:mvn/version "0.0.5"}}}' -m certifiable.main list
Keystores found in directory:  /Users/bhauman/_certifiable_certs
1. localhost-1d070e4  [localhost, www.localhost, 127.0.0.1]
2. localhost-8464661  [localhost, 127.0.0.1]
3. test.localhost-8496962  [test.localhost, 127.0.0.1]
```

You can get more info on a specific cert with the `info` command which
takes and index from the list command or the name of the keystore as an arg.

```sh
$ clj -Sdeps '{:deps {com.bhauman/certifiable {:mvn/version "0.0.5"}}}' -m certifiable.main info 1
{:created #inst "2020-06-26T17:13:54.285-00:00",
 :domains ["localhost" "www.localhost"],
 :stable-name "localhost-1d070e4",
 :ips ["127.0.0.1"],
 :password "password",
 :root-pem-path
 "/Users/bhauman/_certifiable_certs/localhost-1d070e4/dev-root-trust-this.pem",
 :server-keystore-path
 "/Users/bhauman/_certifiable_certs/localhost-1d070e4/dev-server.jks"}
 ```

And with a keystore name:

```sh
$ clj -m certifiable.main info test.localhost-8496962
{:created #inst "2020-06-26T17:22:07.307-00:00",
 :domains ("test.localhost"),
 :stable-name "test.localhost-8496962",
 :ips ["127.0.0.1"],
 :password "password",
 :root-pem-path
 "/Users/bhauman/_certifiable_certs/test.localhost-8496962/dev-root-trust-this.pem",
 :server-keystore-path
 "/Users/bhauman/_certifiable_certs/test.localhost-8496962/dev-server.jks"}
```

### Output Java KeyStore file to a specific location

If you would like to output `.jks` file to a certain path you can
supply a `-o` or `--output` option like so:

```sh
$ clj -Sdeps '{:deps {com.bhauman/certifiable {:mvn/version "0.0.5"}}}' -m certifiable.main -o dev-example.jks create
```

### Debugging

If a command isn't executing correctly you can use the `-v` option to
print out all the calls to `keytool`.

### Reseting

If you get to a point where things aren't working you can use the
`reset` command and it will clear out the root and ca certificates
and allow you to start from scratch.

```sh
$ clj -Sdeps '{:deps {com.bhauman/certifiable {:mvn/version "0.0.5"}}}' -m certifiable.main reset
```

### Help 

Using the `help` command or `-h` option with display all possible CLI options.

## License

Copyright © 2018 Bruce Hauman

Distributed under the Eclipse Public License either version 1.0 or (at
your option) any later version.
