(ns certifiable.sha
  (:require [clojure.string :as string])
  (:import [java.security MessageDigest]
           [java.nio.charset StandardCharsets]))

;; taken from https://github.com/tebeka/clj-digest/blob/master/src/digest.clj
(defn- signature
  [^MessageDigest algorithm]
  (let [size (* 2 (.getDigestLength algorithm))
        sig (.toString (BigInteger. 1 (.digest algorithm)) 16)
        padding (string/join (repeat (- size (count sig)) "0"))]
    (str padding sig)))

(defn sha-signature [s]
  (let [md (MessageDigest/getInstance "SHA-256")]
    (.reset md)
    (.update md (.getBytes s StandardCharsets/UTF_8))
    (signature md)))

(defn sha-signature-short [s]
  (subs (sha-signature s) 0 7))


#_(sha-digest-short "abasdf")


