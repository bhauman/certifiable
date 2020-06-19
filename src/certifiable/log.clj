(ns certifiable.log
  (:require [clojure.string :as string]))

(def log-levels {:all 0
                 :debug 1
                 :info 2
                 :warn 3
                 :error 4
                 :fatal 5
                 :off 6})

(def ^:dynamic *log-level* :info)

(def ^:dynamic *log-fn* println)

(defn level-tag [level]
  (str "[Certifiable"
       (when (#{:debug :warn :error :fatal} level)
         (str ":" (string/upper-case (name level))))
       "]"))

(defn log* [level & args]
  (when-let [v (log-levels level)]
    (when (<= (log-levels *log-level*) v)
      (apply *log-fn* (level-tag level)
             (map str args))
      nil)))

(defn info [& args]
  (apply log* :info args))

(defn debug [& args]
  (apply log* :debug args))

(defn warn [& args]
  (apply log* :warn args))

(defn error [& args]
  (apply log* :error args))

(defn fatal [& args]
  (apply log* :fatal args))


