(ns certifiable.util
  (:require [clojure.java.shell :refer [sh]]
            [clojure.java.io :as io])
  (:import [java.security.cert X509Certificate CertificateFactory]
           [java.security MessageDigest]
           [java.nio.charset StandardCharsets]))

(defn certificate [pem-path]
  (let [is (io/input-stream (io/file pem-path))]
    (.generateCertificate (CertificateFactory/getInstance "X.509") is)))

(defn bytes->hex-str [byt-array]
  (let [sb (StringBuilder.)]
    (doseq [e byt-array]
      (.append sb (format "%02x" e)))
    (str sb)))

(defn cert-sha-1-fingerprint [cert]
  (->> (.getEncoded cert)
       (.digest (MessageDigest/getInstance  "SHA-1"))
       bytes->hex-str))

(defn command-exists? [path]
  (boolean
   (try
     (sh (str path))
     (catch Throwable e))))

(defn os? []
  (let [os-name
        (-> (System/getProperty "os.name" "generic")
            (.toLowerCase java.util.Locale/ENGLISH))
        has? #(>= (.indexOf %1 %2) 0)]
    (cond
      (or (has? os-name "mac")
          (has? os-name "darwin")) :macos
      (has? os-name "win") :windows
      (has? os-name "nux") :linux
      :else :other)))


