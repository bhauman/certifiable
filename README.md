# certifiable

A helper tool that simplifies the creation of development time SSL
certificates for use with Java Webservers like Jetty.

Sometimes you just want a simple way to generate a Java Keystore file
that you can supply to a Java server so that you can enable HTTPS
development on your local machine.

Certifiable creates and reuses a single root certificate and chains
the certificates for each server off of it. This provides the benefit
of only having to trust the root certificate once.

Certifiable only relies the Java `keytool` command. Assuming that if
Java is installed then `keytool` will be available as well.

[Leiningen](https://leiningen.org) dependency information:

```clj
[com.bhauman/certifiable "0.0.1"]
```

[clj/deps.edn](https://clojure.org/guides/deps_and_cli) information:

```clj
{:deps {com.bhauman/certifiable "0.0.1}}
```

## Quick Start Command Line Usage

Make sure you have the [Clojure tools installed](https://clojure.org/guides/getting_started#_installation_on_mac_via_code_brew_code)

Then to generate a certificate execute the following:

```sh
$ clj -Sdeps '{:deps {com.bhauman/certifiable "0.0.1}}' -m certifiable.main
```

If this is the first time its been run, this command will create a
directory in your home directory `~/.certifiable_dev_certs` and
populate it with a root certificate and a ca (certificate authority)
certificate.

The file `~/.certifiable_dev_certs/dev-root-import-this.pem` needs to
be trusted by your operating system and Firefox directly in order to
avoid the not trusted browser warnings.

On MacOS the above command will ask to have the generated certificate
imported into your keychain as a trusted certificate.

The command will output a `dev-localhost.jks` file that you can supply
to a Clojure webserver like `ring.jetty.adapter` like so:

```clj
(require '[ring.adapter.jetty :refer [run-jetty]]

(run-jetty (fn [req] {:status 200 :content-type "text/plain" :body "Hi"}))
  {:join? false
   :port 9500
   :ssl? true
   :ssl-port 9533
   :keystore "dev-localhost.jks"
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
$ clj -Sdeps '{:deps {com.bhauman/certifiable "0.0.1}}' -m certifiable.main -d "example.test,localhost"
```

That command will generate a new local development certifiable with a
custom the Subject Alternative Name section that includes both
`example.test` and `localhost`.

You can also supply a comma separated list of custom IP addresses with the `-i` or `--ips` option.

### Output file

The default output `.jks` file is `dev-localhost.jks` if you want to
override that then you can supply a `-o` or `--output` option like so:

```sh
$ clj -Sdeps '{:deps {com.bhauman/certifiable "0.0.1}}' -m certifiable.main -d "example.test,localhost" -o "dev-example.jks"
```

### Debugging

If a command isn't executing correctly you can use the `-v` option to
print out all the calls to `keytool`.

### Reseting

If you get to a point where things aren't working you can use the
`--reset` option and it will clear out the root and ca certificates
and allow you to start from scratch.

```sh
$ clj -Sdeps '{:deps {com.bhauman/certifiable "0.0.1}}' -m certifiable.main --reset
```

### Help 

Using the `-h` option with display all possible CLI options.

## License

Copyright © 2018 Bruce Hauman

Distributed under the Eclipse Public License either version 1.0 or (at
your option) any later version.
