(ns certifiable.keytool
  (:require [clojure.java.shell :refer [sh]]
            [clojure.java.io :as io]
            [clojure.string :as string]
            [certifiable.util :as util]
            [certifiable.log :as log]))

(def keytool-cmd (memoize
                  (fn []
                    (let [base-path (io/file (System/getProperty "java.home") "bin")
                          keytool-path (str (io/file base-path "keytool"))
                          keytool-exe-path (str (io/file base-path "keytool.exe"))
                          paths (cond-> (list keytool-path)
                                  (= (util/os?) :windows) (conj keytool-exe-path))]
                      (first (filter util/command-exists? paths))))))

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

(defn keytool
  ([cmd args]
   (keytool cmd args nil))
  ([cmd args in]
   (when (keytool-cmd)
     (let [args (cond-> (process-args args)
                  in (concat [:in in]))
           command-str (string/join
                        " "
                        (concat [(keytool-cmd) (str "-" (name cmd))]
                                args))
           _ (log/debug command-str)
           res (apply sh (keytool-cmd) (str "-" (name cmd))
                      args)]
       (when-not (zero? (:exit res))
         (throw (ex-info "Failed keytool command" (assoc res
                                                         :command command-str
                                                         :args args
                                                         :piped-input in))))
       res))))

#_(defn cert-info [pem-file]
  (:out (keytool :printcert ["-file" (str pem-file)])))
