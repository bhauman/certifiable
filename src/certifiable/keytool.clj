(ns certifiable.keytool
  (:require [clojure.java.shell :refer [sh]]
            [clojure.string :as string]
            [certifiable.log :as log]))

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
         _ (log/debug command-str)
         res (apply sh "keytool" (str "-" (name cmd))
                    args)]
     (when-not (zero? (:exit res))
       (throw (ex-info "Failed keytool command" (assoc res
                                                       :command command-str
                                                       :args args
                                                       :piped-input in))))
     res)))

#_(defn cert-info [pem-file]
  (:out (keytool :printcert ["-file" (str pem-file)])))
