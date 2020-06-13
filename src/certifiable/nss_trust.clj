(ns certifiable.nss-trust
  (:require [clojure.java.io :as io]
            [certifiable.util :as util]
            [clojure.java.shell :as shell :refer [sh]]))

;; currently this only works on OSX

(defmulti firefox-profile-dir identity)

(defmethod firefox-profile-dir :default [_]
  nil)

(defmethod firefox-profile-dir :macos [_]
  (io/file (System/getProperty "user.home") "Library/Application Support/Firefox/Profiles"))

(defn firefox-profiles []
  (when-let [dir (firefox-profile-dir (util/os?))]
    (and (.exists dir)
         (map io/file
              (filter
               #(.isDirectory %)
               (.listFiles dir))))))

(defn prefix-profile-path [profile-path]
  (cond
    (.exists (io/file profile-path "cert9.db")) (str "sql:" profile-path)
    (.exists (io/file profile-path "cert8.db")) (str "dbm:" profile-path)
    :else nil))

(defn certutil-path []
  (cond
    (util/command-exists? "certutil") "certutil"
    (util/command-exists? "/usr/local/opt/nss/bin/certutil") "/usr/local/opt/nss/bin/certutil"
    :else (and (util/command-exists? "brew")
               (when-let [nss-path (:out (sh "brew" "--prefix" "nss"))]
                 (let [certutil-path (io/file nss-path "bin" "certutil")]
                   (when (util/command-exists? (str certutil-path))
                     (str certutil-path)))))))

(def ^:dynamic *certutil-path* (certutil-path))

(defn certutil-installed? [] *certutil-path*)

(defn ca-uniq-name [pem-path]
  (let [cert (util/certificate pem-path)
        dname (subs (.getName (.getIssuerDN cert)) 3)]
    (str dname " " (.getSerialNumber cert))))

(defn certutil-cmd [& args]
  (when (certutil-installed?)
    (apply sh *certutil-path* args)))

(defn cert-valid-cmd [prefixed-profile-path uniq-name]
  (certutil-cmd "-V" "-d" prefixed-profile-path "-u" "L" "-n" uniq-name))

;; certutil -A -d "sql:/Users/bhauman/Library/Application Support/Firefox/Profiles/n94d69rw.default-1530010864728" -t C,, -n "Testing certifiable" -i ~/_certifiable_certs/localhost-1d070e4/dev-root-trust-this.pem
(defn cert-add-cmd [prefixed-profile-path uniq-name pem-path]
  (certutil-cmd "-A" "-d" prefixed-profile-path "-t" "C,," "-n" uniq-name "-i" (str pem-path)))

(defn cert-delete-cmd [prefixed-profile-path uniq-name]
  (certutil-cmd "-D" "-d" prefixed-profile-path "-n" uniq-name))

(defn has-cert? [pem-path]
  (let [uniq-name (ca-uniq-name pem-path)]
    (->> (keep prefix-profile-path (firefox-profiles))
         (map #(cert-valid-cmd % uniq-name))
         (map :exit)
         (some zero?))))

(defn add-cert [pem-path]
  (let [uniq-name (ca-uniq-name pem-path)]
    (->> (keep prefix-profile-path (firefox-profiles))
         (mapv #(cert-add-cmd % uniq-name pem-path))
         not-empty)))

(defn remove-cert [pem-path]
  (let [uniq-name (ca-uniq-name pem-path)]
    (->> (keep prefix-profile-path (firefox-profiles))
         (mapv #(cert-delete-cmd % uniq-name)))))

(defn install-trust! [pem-path]
  (when (= :macos (util/os?))
    (util/log "Attempting to add root certificate to Firefox nss trust store.")
    (if-not *certutil-path*
      (do
        (util/log "Warning \"certutil\" command is not available so this certificate will not be installed for Firefox")
        (util/log "Please install \"certutil\" with \"brew install nss\""))
      (let [uniq-name (pr-str (ca-uniq-name pem-path))]
        (if (has-cert? pem-path)
          (util/log "Cert" uniq-name "already present in Firefox trust store.")
          (if (add-cert pem-path)
            (util/log "Cert" uniq-name "successfully added to Firefox trust store!")
            ;; TODO add output from certutil to inform why it failed?
            (do
              (util/log "FAILED adding" uniq-name "to Firefox trust store!")
              (util/log "Add the certifcate manually"))))))))

#_(def pem-path (io/file (System/getProperty "user.home") "_certifiable_certs/localhost-1d070e4/dev-root-trust-this.pem"))

#_(install-trust! pem-path)

#_(has-cert? pem-path)

#_(add-cert pem-path)

#_(remove-cert pem-path)
