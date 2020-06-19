(ns certifiable.main
  (:require
   [clojure.java.shell :refer [sh]]
   [clojure.java.io :as io]
   [clojure.string :as string]
   [clojure.tools.cli :refer [parse-opts]]
   [certifiable.sha :refer [sha-signature-short]]
   [certifiable.util :as util]
   [certifiable.log :as log]
   [certifiable.keytool :refer [keytool keytool?]]
   [certifiable.macos-trust :as macos-trust]
   [certifiable.nss-trust :as nss-trust]
   [clojure.pprint])
  (:gen-class))

(def ^:dynamic *ca-dir* (io/file (System/getProperty "user.home") "_certifiable_certs"))

(def ^:dynamic *password* "password")

(def ^:dynamic *root-keystore-name* "dev-root.jks")
(def ^:dynamic *root-pem-name* "dev-root-trust-this.pem")

(def ^:dynamic *ca-keystore-name* "intermediate-certificate-authority.jks")
(def ^:dynamic *ca-pem-name* "intermediate-certificate-authority.pem")

(def ^:dynamic *server-keystore-name* "dev-server.jks")
(def ^:dynamic *server-pem-name* "dev-server.pem")

(def ^:dynamic *info-name* "info.edn")

(defn dname [{:keys [stable-name]}]
  (format "cn=Certifiable dev root (%s)" stable-name))

(defn file-paths [{:keys [stable-name]}]
  {:root-keystore-path (io/file *ca-dir* stable-name *root-keystore-name*)
   :ca-keystore-path (io/file *ca-dir* stable-name *ca-keystore-name*)
   :root-pem-path (io/file *ca-dir* stable-name *root-pem-name*)
   :ca-pem-path (io/file *ca-dir* stable-name *ca-pem-name*)
   :server-keystore-path (io/file *ca-dir* stable-name *server-keystore-name*)
   :server-pem-path (io/file *ca-dir* stable-name *server-pem-name*)})

(defn gen-key-pair [args-map]
  (let [base-args (merge {:validity 10000
                          :keyalg :RSA
                          :keysize 2048
                          :keypass *password*
                          :storepass *password*}
                         args-map)]
    (assert (:alias base-args))
    (assert (:dname base-args))
    (assert (:keystore base-args))
    (keytool :genkeypair base-args)))

(defn delete-directory [f]
  (doseq [f (reverse (file-seq f))]
    (when (.exists f)
      (.delete f))))

(defn clean! []
  (delete-directory (io/file *ca-dir*)))

(defn gen-third-party-ca [opts]
  (let [{:keys [root-keystore-path
                ca-keystore-path 
                root-pem-path 
                ca-pem-path]} (file-paths opts)]
    (try
      (io/make-parents root-keystore-path)
      ;; gen keypairs
      (log/info "Generating root and ca keypairs")
      ;; keytool -genkeypair -alias root -dname "cn=Local Network - Development" -validity 10000 -keyalg RSA -keysize 2048 -ext bc:c -keystore root.jks -keypass password -storepass password
      (gen-key-pair {:alias :root
                     :dname (dname opts)
                     :ext "bc:c"
                     :keystore root-keystore-path})
      ;; keytool -genkeypair -alias ca -dname "cn=Local Network - Development" -validity 10000 -keyalg RSA -keysize 2048 -ext bc:c -keystore ca.jks -keypass password -storepass password
      (gen-key-pair {:alias :ca
                     :dname (dname opts)
                     :ext "bc:c"
                     :keypass *password*
                     :keystore ca-keystore-path})
      
      (log/info (str "Generating root certificate: " root-pem-path))
      ;; generate root certificate
      ;; keytool -exportcert -rfc -keystore root.jks -alias root -storepass password > root.pem
      (->>
       (keytool :exportcert [:rfc
                             :keystore root-keystore-path
                             :alias :root
                             :storepass *password*])
       :out
       (spit root-pem-path))
      
      ;; generate a certificate for ca signed by root (root -> ca)
      ;; keytool -keystore ca.jks -storepass password -certreq -alias ca \
      ;; | keytool -keystore root.jks -storepass password -gencert -alias root -ext bc=0 -ext san=dns:ca -rfc > ca.pem
      (log/info "Generating ca certificate signed by root")
      (->> (keytool :certreq
                    {:keystore ca-keystore-path
                     :storepass *password*
                     :alias :ca})
           :out
           (keytool :gencert
                    [:keystore root-keystore-path
                     :storepass *password*
                     :alias :root
                     :rfc
                     :ext "bc=0"
                     :ext "san=dns:ca"])
           :out
           (spit ca-pem-path))
      
    ;; import ca cert chain into ca.jks

      (log/info "Importing root and ca chain into ca.jks keystore")
      ;; keytool -keystore ca.jks -storepass password -importcert -trustcacerts -noprompt -alias root -file root.pem
      (keytool :importcert [:keystore ca-keystore-path
                            :storepass *password*
                            :trustcacerts
                            :noprompt
                            :alias :root
                            :file root-pem-path])
      
      ;; keytool -keystore ca.jks -storepass password -importcert -alias ca -file ca.pem
      (keytool :importcert {:keystore ca-keystore-path
                            :storepass *password*
                            :alias :ca
                            :file ca-pem-path})
      (finally
        (.delete root-keystore-path)
        (log/info (str "Deleted trusted root certificate keys: " root-keystore-path))))))


(defn domains-and-ips->san [{:keys [domains ips]}]
  ;; "san=dns:localhost,dns:www.localhost,dns:martian.test,ip:127.0.0.1"
  (string/join ","
               (concat (map #(str "dns:" %) domains)
                       (map #(str "ip:" %) ips))))

(defn generate-jks-for-domain [{:keys [keystore-path domains ips] :as opts}]
  (let [{:keys [ca-keystore-path 
                server-keystore-path
                root-pem-path 
                ca-pem-path
                server-pem-path]} (file-paths opts)]
    (try
      (assert (.exists root-pem-path))
      (assert (.exists ca-keystore-path))
      (assert (.exists ca-pem-path))
      ;; generate private keys (for server)
      
      ;; keytool -genkeypair -alias server -dname cn=server -validity 10000 -keyalg RSA -keysize 2048 -keystore my-keystore.jks -keypass password -storepass password
      (log/info "Generate private keys for server")
      (gen-key-pair {:alias :server
                     :dname "cn=CertifiableLeafCert" 
                     :keystore server-keystore-path})
      
      ;; generate a certificate for server signed by ca (root -> ca -> server)
      
      ;; keytool -keystore my-keystore.jks -storepass password -certreq -alias server \
      ;; | keytool -keystore ca.jks -storepass password -gencert -alias ca -ext ku:c=dig,keyEnc -ext "san=dns:localhost,ip:127.0.0.1" -ext eku=sa,ca -rfc > server.pem
      (log/info "Generate a certificate for server signed by ca")
      (->> (keytool :certreq {:keystore server-keystore-path
                              :storepass *password*
                              :alias :server})
           :out
           (keytool :gencert
                    [:alias :ca
                     :keystore ca-keystore-path
                     :storepass *password*
                     :rfc
                     :ext "ku:c=dig,keyEnc"
                     :ext (str "san=" (domains-and-ips->san opts))
                     :ext "eku=sa,ca"])
           :out
           (spit server-pem-path))
      
      ;; import server cert chain into my-keystore.jks
      (log/info (str "Importing complete chain into keystore at: " server-keystore-path))
      ;; keytool -keystore my-keystore.jks -storepass password -importcert -trustcacerts -noprompt -alias root -file root.pem
      
      (keytool :importcert [:keystore server-keystore-path
                            :storepass *password*
                            :trustcacerts
                            :noprompt
                            :alias :root
                            :file root-pem-path])

    ;; keytool -keystore my-keystore.jks -storepass password -importcert -alias ca -file ca.pem
      (keytool :importcert {:keystore server-keystore-path
                            :storepass *password*
                            :alias :ca
                            :file ca-pem-path})
    
      ;; keytool -keystore my-keystore.jks -storepass password -importcert -alias server -file server.pem
      (keytool :importcert {:keystore server-keystore-path
                            :storepass *password*
                            :alias :server
                            :file server-pem-path})

      (finally
        (.delete ca-keystore-path)
        (.delete ca-pem-path)
        (.delete server-pem-path)
        (log/info (str "Deleted intermediate certificate authority keys: " ca-keystore-path))))
    (log/info (str  "Generated Java Keystore file: " server-keystore-path))))


(defn stable-name [{:keys [keystore-path domains ips] :as opts}]
  (let [domains-ips (concat (sort domains)
                            (sort ips))
        n (first domains-ips)
        sig (sha-signature-short (string/join  "," domains-ips))]
    (str n "-" sig)))

(defn dev-cert-exists? [opts]
  (let [{:keys [root-pem-path server-keystore-path]} (file-paths opts)]
    (and (.exists root-pem-path)
         (.exists server-keystore-path))))


(defn meta-data [{:keys [domains ips stable-name]}]
  {:created (java.util.Date.)
   :domains domains
   :name stable-name
   :ips ips})

(defn info-file [opts]
  (io/file *ca-dir* (:stable-name opts) *info-name*))

(defn emit-meta-data [opts]
  (spit (info-file opts)
        (with-out-str (clojure.pprint/pprint (meta-data opts)))))

(defn emit-keystore [{:keys [keystore-path stable-name]}]
  (when keystore-path
    (log/info "Outputing Java Keystore to:" (str keystore-path))
    (io/copy
     (io/file *ca-dir* stable-name *server-keystore-name*)
     (io/file keystore-path))))

#_(clean!)
#_(create-dev-certificate-jks {})

(defn install-to-trust-stores! [pem-path]
  (macos-trust/install-trust! pem-path)
  (nss-trust/install-trust! pem-path))

#_(defn final-instructions [])

(defn create-dev-certificate-jks [{:keys [keystore-path domains ips] :as opts}]
  (let [opts (merge {:domains ["localhost" "www.localhost"]
                     :ips ["127.0.0.1"]}
                    opts)
        stable-name' (stable-name opts)
        opts (assoc opts :stable-name stable-name')]
    (if-not (keytool?)
      (do
        (log/info "ERROR: Can not find keytool Java command.")
        (println "Please check your Java installation and ensure that keytool is on your path."))
      (do
        (if-not (dev-cert-exists? opts)
          (do (gen-third-party-ca opts)
              (generate-jks-for-domain opts)
              (emit-meta-data opts)
              (install-to-trust-stores! (io/file *ca-dir* stable-name' *root-pem-name*)))
          (do
            (log/info (str "Root certificate and keystore already exists for " (:stable-name opts)))
            (install-to-trust-stores! (io/file *ca-dir* stable-name' *root-pem-name*))))
        ;; TODO print import instructions
        (emit-keystore opts)
        ))))

(def cli-options
  [["-d" "--domains DOMAINS" "A comma seperated list of domains to be included in certificate"
    :default ["localhost" "www.localhost"]
    :default-desc "localhost,www.localhost"
    :parse-fn #(mapv string/trim (string/split % #","))]
   ["-i" "--ips IPS" "A comma seperated list of IP addresses to be included in certificate"
    :default ["127.0.0.1"]
    :default-desc "127.0.0.1"
    :parse-fn #(mapv string/trim (string/split % #","))
    :validate [#(every?
                 (partial re-matches #"\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}")
                 %)
               "Must be a comma seperated list of IP address"]]
   ["-o" "--output FILE" "The path and filename of the jks output file"
    :id :keystore-path]
   [nil "--reset" "Start from scratch, deletes root and certificate authority certs"]
   ["-h" "--help"]
   ["-v" nil "verbose - outputs more info about keytool calls"
    :id :verbosity
    :default false]])

(defn usage [options-summary]
  (->> ["Generates a local developement Java keystore that can be used
to support SSL/HTTPS connections in a Java Server like Jetty."
        ""
        "Usage: clj -m certifiable.main [options]"
        ""
        "Options:"
        options-summary]
       (string/join \newline)))

(defn -main [& args]
  (try
    (let [options (parse-opts args cli-options)
          err? (or (:errors options)
                   (not-empty (:arguments options)))]
      (binding [log/*log-level* (if (:verbosity (:options options))
                                  :all
                                  :info)
                *out* *err*]
        
        (log/debug (str "Args:\n"
                        (with-out-str (clojure.pprint/pprint (:options options)))))
        (doseq [err (:errors options)]
          (println err))
        (doseq [arg (:arguments options)]
          (println "Unknown option:" arg))
        (cond
          (or err?
              (-> options :options :help))
          (println (usage (:summary options)))

          (-> options :options :reset)
          (do (clean!)
              (log/info "Resetting: Deleting all certificates!"))
          :else
          (do
            (create-dev-certificate-jks (:options options))))))
    (finally
      (shutdown-agents))))

;; keytool -importkeystore -srckeystore /Users/bhauman/.certifiable_dev_certs/certificate-authority.jks -destkeystore /Users/bhauman/.certifiable_dev_certs/certificate-authority.jks -deststoretype pkcs12

;; keytool -importkeystore -srckeystore localhost.p12 -srcstoretype  pkcs12 -destkeystore dev-localhost.jks -deststoretype jks

;; converting from a 
;; keytool -importkeystore -srckeystore localhost.p12 -srcstoretype  pkcs12 -destkeystore dev-localhost.jks -deststoretype jks
