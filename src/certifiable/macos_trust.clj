(ns certifiable.macos-trust
  (:require
   [clojure.java.io :as io]
   [clojure.java.shell :refer [sh]]
   [certifiable.util :as util]
   [certifiable.log :as log]))

;; add the cert to the keychain
;; security add-trusted-cert -d -r trustRoot -k ~/Library/Keychains/login.keychain-db root.pem

(def security-command?
  (memoize
   (fn []
     (and (= :macos (util/os?))
          (util/command-exists? "security")))))

(defn macos-login-keychain-dir []
  (let [path (io/file (System/getProperty "user.home") "Library" "Keychains")
        new-login-chain (io/file path "login.keychain-db")
        old-login-chain (io/file path "login.keychain")]
    (cond
      (.exists new-login-chain) new-login-chain
      (.exists old-login-chain) new-login-chain
      :else nil)))

(defn security-command [& args]
  (when (security-command?)
    (apply sh "security" args)))

(defn has-cert? [pem-path]
  (when-let [keychain (macos-login-keychain-dir)]
    (zero? (:exit (security-command "verify-cert" "-k" (str keychain) "-c" (str pem-path))))))

(defn add-cert [pem-path]
  (when-let [keychain (macos-login-keychain-dir)]
    (zero? (:exit (security-command
                   "add-trusted-cert" #_"-d" "-r" "trustRoot" "-k"
                   (str keychain)
                   (str pem-path))))))

(defn remove-cert [pem-path]
  (when-let [keychain (macos-login-keychain-dir)]
    ;; have to call delete first to set some deletion flag
    ;; even though the command fails
    (security-command "delete-certificate" "-Z"
                      (clojure.string/upper-case
                       (util/cert-sha-1-fingerprint (util/certificate pem-path)))
                      (str keychain))
    ;; then when we removetrust the certificate leaves the store
    (zero? (:exit (security-command "remove-trusted-cert" (str pem-path))))))

(defn add-trusted-cert! [root-pem-file]
  (when (= :macos (util/os?))
    (when-let [keychain (macos-login-keychain-dir)]
      (sh "security" "add-trusted-cert" #_"-d" "-r" "trustRoot" "-k"
          (str keychain)
          (str root-pem-file)))))

(defn install-trust! [pem-path]
  (when (= :macos (util/os?))
    (log/info "Attempting to add root certificate to MacOS login keychain.")
    (if-not (security-command?)
      (log/info "\"security\" command is not available so this certificate will not be installed to MacOS login keychain.")
      (let [dname (pr-str (subs (.getName (.getIssuerDN (util/certificate pem-path))) 3))]
        (if (has-cert? pem-path)
          (do (log/info "Cert" dname "already present in MacOS login keychain.")
              true)
          (if (add-cert pem-path)
            (do (log/info "Cert" dname "successfully added to MacOS login keychain!")
                true)
            ;; TODO add output from certutil to inform why it failed?
            (do
              (log/info "FAILED adding" dname "to MacOS login keychain!")
              (log/info "Add the certifcate manually"))))))))

#_ (def pem-path (io/file (System/getProperty "user.home") "_certifiable_certs/localhost-1d070e4/dev-root-trust-this.pem"))

#_ (has-cert? pem-path)
#_ (add-cert pem-path)
#_ (remove-cert pem-path)
