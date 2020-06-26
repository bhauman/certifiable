(ns certifiable.main
  (:require
   [clojure.java.shell :refer [sh]]
   [clojure.java.io :as io]
   [clojure.string :as string]
   [clojure.tools.cli :refer [parse-opts]]
   [clojure.edn :as edn]
   [certifiable.sha :refer [sha-signature-short]]
   [certifiable.util :as util]
   [certifiable.log :as log]
   [certifiable.keytool :refer [keytool keytool-cmd]]
   [certifiable.macos-trust :as macos-trust]
   [certifiable.nss-trust :as nss-trust]
   [clojure.pprint])
  (:import [java.net
            URL
            InetAddress])
  (:gen-class))

;; this isn't hidden so that users easily add trust manually and dont' have
;; to navigate hidden files from inside a gui file system explorer
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
        (when (.exists root-keystore-path)
          (.delete root-keystore-path)
          (log/info (str "Deleted trusted root certificate keys: " root-keystore-path)))))))


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
      (assert (or (not-empty domains)
                  (not-empty ips))
              "Must supply hostnames or ips")
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
        (when (.exists ca-keystore-path)
          (.delete ca-keystore-path))
        (when (.exists ca-pem-path)
          (.delete ca-pem-path))
        (when (.exists server-pem-path)
          (.delete server-pem-path))
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
   :stable-name stable-name
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
  {:system-trust-installed
   (when (= :macos (util/os?))
     (macos-trust/install-trust! pem-path))
   :firefox-trust-installed
   (nss-trust/install-trust! pem-path)})

(defn remove-trust [pem-path]
  (when (and (= :macos (util/os?))
             (macos-trust/has-cert? pem-path))
    (log/info "Removing trust from MacOS keychain for " (str pem-path))
    (macos-trust/remove-cert pem-path))
  (if (nss-trust/has-cert? pem-path)
    (log/info "Removing trust from Firefox NSS trust store for" (str pem-path))
    (nss-trust/remove-cert pem-path)))

(defn remove-cert [{:keys [stable-name root-pem-path] :as cert-info}]
  (remove-trust root-pem-path)
  (when stable-name
    (delete-directory (io/file *ca-dir* stable-name))))

(declare list-keystores)

(defn remove-all []
  (try
    (doseq [cert-info (list-keystores *ca-dir*)]
      (log/info "Removing:" (:stable-name cert-info))
      (remove-cert cert-info))
    (finally
      (delete-directory *ca-dir*))))

(defn final-instructions [{:keys [keystore-path] :as opts} trust-installed]
  (let [{:keys [server-keystore-path
                root-pem-path]} (file-paths opts)
        path (or keystore-path (str server-keystore-path))
        {:keys [system-trust-installed
                firefox-trust-installed]} trust-installed]
    (str
     "--------------------------- Setup Instructions ---------------------------\n"
     "Local dev Java keystore generated at: " path "\n"
     "The keystore type is: \"JKS\"\n"
     "The keystore password is: \"" *password* "\"\n"
     "The root certificate is: " root-pem-path "\n"
     "For System: root certificate " (if system-trust-installed
                                       "is trusted"
                                       "needs to have trust set up") "\n"
     "For Firefox: root certificate " (if firefox-trust-installed
                                        "is trusted"
                                        "needs to have trust set up") "\n"
     "Example SSL Configuration for ring.jetty.adapter/run-jetty:\n"
     (with-out-str (clojure.pprint/pprint
                    {:ssl? true
                     :ssl-port 9533
                     :keystore path
                     :key-password *password*})))))

(declare keystore-info)

(defn create-dev-certificate-jks [{:keys [keystore-path domains ips print-instructions?] :as opts}]
  (let [opts (merge {:domains ["localhost" "www.localhost"]
                     :ips ["127.0.0.1"]}
                    opts)
        stable-name' (stable-name opts)
        opts (assoc opts :stable-name stable-name')]
    (if-not (keytool-cmd)
      (do
        (log/info "ERROR: Can not find keytool Java command.")
        (println "Please check your Java installation and ensure that keytool is on your path."))
      (do
        (if-not (dev-cert-exists? opts)
          (do (gen-third-party-ca opts)
              (generate-jks-for-domain opts)
              (emit-meta-data opts)
              (let [trust-info (install-to-trust-stores! (io/file *ca-dir* stable-name' *root-pem-name*))]
                (when print-instructions?
                  (println (final-instructions opts trust-info)))
                (emit-keystore opts)
                (keystore-info opts)))
          (do
            (log/info (str "Root certificate and keystore already exists for " (:stable-name opts)))
            (let [trust-info (install-to-trust-stores! (io/file *ca-dir* stable-name' *root-pem-name*))]
              (when print-instructions?
                (println (final-instructions opts trust-info)))
              (emit-keystore opts)
              (keystore-info opts))))
        ))))

(def cli-options
  [["-o" "--output FILE" "The path and filename of the jks output file"
    :id :keystore-path]
   ["-h" "--help"]
   ["-v" nil "verbose - outputs more info about keytool calls"
    :id :verbosity
    :default false]])

(defn usage [options-summary]
  (->> ["Generates a local developement Java keystore that can be used
to support SSL/HTTPS connections in a Java Server like Jetty."
        ""
        "Usage: clj -m certifiable.main [options] [command] [command args]"
        ""
        "Available Commands: (if no command is supplied \"create\" is the default)"

" create [hosts and ips]  : takes a list of hostnames and ips and creates a keystore
                           if no hostnames or ips supplied defaults to 
                           localhost www.locahost 127.0.0.1"
        " list                    : lists the current keystores"
        " info [name/list idx]    : displays info on the given store name or list index"
        " reset                   : deletes all keystores and removes the trust for them"
        " remove [name/list idx]  : deletes the given keystore and removes trust for it"
        " help                    : prints out these instructions"
        ""
        ""
        "Options:"
        options-summary]
       (string/join \newline)))

(defn list-dirs [dir]
  (let [dir (io/file dir)]
    (when (.isDirectory dir)
      (filter
       #(.isDirectory %)
       (seq (.listFiles dir))))))

(defn keystore-info [{:keys [stable-name] :as opts}]
  (let [info-file (info-file opts)
        data (if (.exists info-file)
               (try
                 (edn/read-string (slurp info-file))
                 (catch Throwable t)))
        {:keys [root-pem-path server-keystore-path]} (file-paths opts)]
    (assoc data
           :password *password*
           :root-pem-path (str root-pem-path)
           :server-keystore-path (str server-keystore-path))))

(defn list-keystores [ca-dir]
  (mapv keystore-info (map #(hash-map :stable-name %)
                           (sort (map #(.getName %)
                                      (list-dirs *ca-dir*))))))

#_(list-keystores *ca-dir*)

(defn list-command [ca-dir]
  (let [keystores (list-keystores ca-dir)]
    (if (empty? keystores)
      (println "No installed keystores found")
      (println "Keystores found in directory: " (str ca-dir)))
    (doall
     (map-indexed
      #(println (format "%d. %s  [%s]"
                        (inc %1) (:stable-name %2)
                        (string/join ", " (concat (sort (:domains %2))
                                                  (sort (:ips %2)))) ))
      (list-keystores ca-dir)))))

(defn ip-address? [x]
  (let [[host ip]
        (try
          (string/split (str (InetAddress/getByName x))
                        #"/")
          (catch Throwable t))]
    (when (and (string/blank? host)
               ip
               (not (string/blank? ip)))
      ip)))

(defn hostname? [x]
  (and
   (re-matches #"[a-zA-Z\d].*" x)
   (= x (.getHost (URL. (str "http://" x))))
   x))

(defn parse-domain-ip-arguments [args]
  (not-empty
   (reduce 
    (fn [accum x]
      (if-let [ip (ip-address? x)]
        (update accum :ips conj ip)
        (if (hostname? x)
          (update accum :domains conj x)
          (update accum ::not-hostname-or-ip-error conj x))))
    {}
    args)))

(defn find-cert-info [name-or-idx]
  (let [keystores (list-keystores *ca-dir*)]
    (or (first (filter #(= (:stable-name %) name-or-idx) keystores))
        (when-let [idx (try (Integer/parseInt name-or-idx)
                            (catch Throwable t))]
          (try (nth (list-keystores *ca-dir*) (dec idx))
               (catch Throwable t))))))

(defn -main [& args]
  (try
    (let [options (parse-opts args cli-options)
          err? (or (:errors options)
                   (not-empty (:arguments options)))]
      (log/debug (str "Args:\n"
                      (with-out-str (clojure.pprint/pprint (:options options)))))
      (binding [log/*log-level* (if (:verbosity (:options options))
                                  :all
                                  :info)
                *out* *err*]
        (let [cmd? (first (:arguments options))]
          (cond
            (or (-> options :options :help)
                (= cmd? "help"))
            (println (usage (:summary options)))
            (nil? cmd?)
            (create-dev-certificate-jks (assoc (:options options)
                                               :print-instructions? true))
            (= cmd? "list") (list-command *ca-dir*)
            (= cmd? "info")
            (if-let [cert-stable-name (second (:arguments options))]
              (if-let [info (find-cert-info cert-stable-name)]
                (clojure.pprint/pprint info)
                (log/info (format "Cert %s not found" cert-stable-name)))
              (log/info "You must supply a the name to get info. Try the \"list\" command"))
            (= cmd? "remove")
            (if-let [cert-stable-name (second (:arguments options))]
              (if-let [info (find-cert-info cert-stable-name)]
                (do
                  (log/info (format "Removing %s!" (:stable-name info)))
                  (remove-cert info))
                (log/info (format "Cert %s not found" cert-stable-name)))
              (log/info "You must supply a the name to get info. Try the \"list\" command"))
            (= cmd? "reset")
            (do
              (log/info "Resetting: Deleting all certificates!")
              (remove-all))
            (= cmd? "create")
            (let [domains-and-ips-opts (parse-domain-ip-arguments (filter string? (rest (:arguments options))))]
              (if-let [bad-names (::not-hostname-or-ip-error domains-and-ips-opts)]
                (do
                  (log/info "All arguments to create must be valid hostnames or ip addresses")
                  (doseq [n bad-names]
                    (log/info (str n " is not a hostname or ip address"))
                    (when (.startsWith n "*")
                      (log/info "Wildcard hostnames are not allowed"))))
                (create-dev-certificate-jks (assoc (merge (:options options) domains-and-ips-opts)
                                                   :print-instructions? true))))
            (or
             (not-empty (:errors options))
             (not-empty (:arguments options)))
            (do
              (doseq [err (:errors options)]
                (println err))
              (doseq [arg (:arguments options)]
                (println "Unknown option:" arg))
              (println (usage (:summary options))))
            :else
            (do
              (println (usage (:summary options))))))))
    (finally
      (shutdown-agents))))

;; keytool -importkeystore -srckeystore /Users/bhauman/.certifiable_dev_certs/certificate-authority.jks -destkeystore /Users/bhauman/.certifiable_dev_certs/certificate-authority.jks -deststoretype pkcs12

;; keytool -importkeystore -srckeystore localhost.p12 -srcstoretype  pkcs12 -destkeystore dev-localhost.jks -deststoretype jks

;; converting from a 
;; keytool -importkeystore -srckeystore localhost.p12 -srcstoretype  pkcs12 -destkeystore dev-localhost.jks -deststoretype jks




