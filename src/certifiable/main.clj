(ns certifiable.main
  (:require
   [clojure.java.shell :refer [sh]]
   [clojure.java.io :as io]
   [clojure.string :as string]
   [clojure.tools.cli :refer [parse-opts]]
   [clojure.pprint])
  (:gen-class))

(def ^:dynamic *ca-dir* (io/file (System/getProperty "user.home") ".certifiable_dev_certs"))

(def ^:dynamic *password* "password")

(def ^:dynamic *dname* "cn=Certifiable development root")

(def ^:dynamic *root-keystore-name* "dev-root.jks")
(def ^:dynamic *root-pem-name* "dev-root-import-this.pem")

(def ^:dynamic *ca-keystore-name* "certificate-authority.jks")
(def ^:dynamic *ca-pem-name* "certificate-authority.pem")

(def ^:dynamic *debug* false)

(defn log [s]
  (println (str "[Certifiable] " s)))

(defn debug-log [s]
  (when *debug*
    (println (str "[Certifiable:Debug] " s))))

(defn root-files []
  {:root-keystore-path (io/file *ca-dir* *root-keystore-name*)
   :ca-keystore-path (io/file *ca-dir* *ca-keystore-name*)
   :root-pem-path (io/file *ca-dir* *root-pem-name*)
   :ca-pem-path (io/file *ca-dir* *ca-pem-name*)})

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

(defn keytool? []
  (try
    (-> (sh "keytool" "-gencert" "-help") :exit (= 0))
    (catch java.io.IOException e
      false)))

(def keytool-keys #{:rfc :noprompt :keystore :ext :keypass :dname :file :storepass
                    :alias :trustcacerts :keyalg :keysize :validity})

(defn process-args [args]
  (keep (fn [x] (if (keytool-keys x)
                  (str "-" (name x))
                  (when x
                    (try
                      (name x)
                      (catch Throwable e
                        (str x))))))
        (if (map? args)
          (apply concat args)
          args)))

#_(process-args [:validity 10000
                 :keyalg :RSA
                 :keysize 2048
                 :keypass *password*
                 :storepass *password*])

(defn keytool
  ([cmd args]
   (keytool cmd args nil))
  ([cmd args in]
   (let [args (cond-> (process-args args)
                in (concat [:in in]))
         command-str (string/join
                      " "
                      (concat ["keytool" (str "-" (name cmd))]
                              args))
         _ (debug-log command-str)
         res (apply sh "keytool" (str "-" (name cmd))
                    args)]
     (when-not (zero? (:exit res))
       (throw (ex-info "Failed keytool command" (assoc res
                                                       :command command-str
                                                       :args args
                                                       :piped-input in))))
     res)))

;; add the cert to the keychain
;; security add-trusted-cert -d -r trustRoot -k ~/Library/Keychains/login.keychain-db root.pem

(defn macos-login-keychain-dir []
  (let [path (io/file (System/getProperty "user.home") "Library" "Keychains")
        new-login-chain (io/file path "login.keychain-db")
        old-login-chain (io/file path "login.keychain")]
    (cond
      (.exists new-login-chain) new-login-chain
      (.exists old-login-chain) new-login-chain
      :else nil)))

(defn add-trusted-cert! [root-pem-file]
  (when (= :macos (os?))
    (when-let [keychain (macos-login-keychain-dir)]
      (sh "security" "add-trusted-cert" #_"-d" "-r" "trustRoot" "-k"
          (str keychain)
          (str root-pem-file)))))

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

(defn root-ca? []
  (every? #(.exists %) (vals (root-files))))

(defn gen-third-party-ca []
  (let [{:keys [root-keystore-path
                ca-keystore-path 
                root-pem-path 
                ca-pem-path]} (root-files)]
    (io/make-parents root-keystore-path)
    ;; gen keypairs
    (log "Generating root and ca keypairs")
    ;; keytool -genkeypair -alias root -dname "cn=Local Network - Development" -validity 10000 -keyalg RSA -keysize 2048 -ext bc:c -keystore root.jks -keypass password -storepass password
    (gen-key-pair {:alias :root
                   :dname *dname*
                   :ext "bc:c"
                   :keystore root-keystore-path})
    ;; keytool -genkeypair -alias ca -dname "cn=Local Network - Development" -validity 10000 -keyalg RSA -keysize 2048 -ext bc:c -keystore ca.jks -keypass password -storepass password
    (gen-key-pair {:alias :ca
                   :dname *dname*
                   :ext "bc:c"
                   :keypass *password*
                   :keystore ca-keystore-path})

    (log "Generating root certificate")
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
    (log "Generating ca certificate signed by root")
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

    (log "Importing root and ca chain into ca.jks keystore")
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

    (add-trusted-cert! root-pem-path)))


(defn domains-and-ips->san [{:keys [domains ips]}]
  ;; "san=dns:localhost,dns:www.localhost,dns:martian.test,ip:127.0.0.1"
  (string/join ","
               (concat (map #(str "dns:" %) domains)
                       (map #(str "ip:" %) ips))))

(defn generate-jks-for-domain [{:keys [keystore-path domains ips] :as opts}]
  (let [{:keys [root-keystore-path
                ca-keystore-path 
                root-pem-path 
                ca-pem-path]} (root-files)
        server-keystore-path (io/file keystore-path)
        keystore-name (.getName server-keystore-path)
        ;; TODO This will likely get overwritten but it's only used as a temporary file
        server-pem-path (io/file *ca-dir* (str keystore-name ".pem"))]
    (io/make-parents root-keystore-path)
    (io/make-parents server-keystore-path)
    (when (.exists server-keystore-path)
      (log (str "Deleting previous keystore " server-keystore-path))
      (.delete server-keystore-path))
    (when (.exists server-pem-path)
      (log (str "Deleting previous pem " server-pem-path))
      (.delete server-pem-path))
    ;; generate private keys (for server)

    ;; keytool -genkeypair -alias server -dname cn=server -validity 10000 -keyalg RSA -keysize 2048 -keystore my-keystore.jks -keypass password -storepass password
    (log "Generate private keys for server")
    (gen-key-pair {:alias :server
                   :dname "cn=CertifiableLeafCert" 
                   :keystore server-keystore-path})

    ;; generate a certificate for server signed by ca (root -> ca -> server)

  ;; keytool -keystore my-keystore.jks -storepass password -certreq -alias server \
  ;; | keytool -keystore ca.jks -storepass password -gencert -alias ca -ext ku:c=dig,keyEnc -ext "san=dns:localhost,ip:127.0.0.1" -ext eku=sa,ca -rfc > server.pem
    (log "Generate a certificate for server signed by ca")
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
    (log (str "Importing complete chain into keystore at: " server-keystore-path))
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
    (log (str  "Generated Java Keystore file: " server-keystore-path))))

(defn create-dev-certificate-jks [{:keys [keystore-path domains ips] :as opts}]
  (let [opts (merge {:keystore-path "dev-localhost.jks"
                     :domains ["localhost" "www.localhost"]
                     :ips ["127.0.0.1"]}
                    opts)]
    (if-not (keytool?)
      (do
        (log "ERROR: Can not find keytool Java command.")
        (println "Please check your Java installation and ensure that keytool is on your path."))
      (do
        (if-not (root-ca?)
          (do
            (log "Root certificate does not exist! generating ...")
            (clean!)
            (gen-third-party-ca)
            (println "When a new root certificate is generated it needs to be imported
so that your browsers trust it."))
          (log "Root certificate exists. Using previously generated root."))
        (generate-jks-for-domain opts)))))

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
    :id :keystore-path
    :default "dev-localhost.jks"]
   [nil "--reset" "Start from scratch, deletes root and certificate authority certs"]
   ["-h" "--help"]
   ["-v" nil "verbose - outputs more info about keytool calls"
    :id :verbosity
    :default false]])

#_(parse-opts ["-i" "127.0.0.1,..." "ggez"
               "-d" "localhost,www.localhost"
               "-n" "fastly"] cli-options)

#_(parse-opts ["-h"] cli-options)

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
  (let [options (parse-opts args cli-options)
        err? (or (:errors options)
                 (not-empty (:arguments options)))]
    (binding [*debug* (:verbosity (:options options))
              *out* *err*]
      (debug-log (str "Args:\n"
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
            (log "Resetting: Deleting root and ca certificates!"))
        :else
        (do
          (create-dev-certificate-jks (:options options))
          (shutdown-agents))))))

#_(create-dev-certificate-jks {})

#_(clean!)

#_(gen-third-party-ca)







