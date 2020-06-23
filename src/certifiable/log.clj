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

(def ^:dynamic *output-fn* println)

(defn level-tag [level]
  (str "[Certifiable"
       (when (#{:debug :warn :error :fatal} level)
         (str ":" (string/upper-case (name level))))
       "]"))

(defn log* [level & args]
  (when-let [v (log-levels level)]
    (when (<= (log-levels *log-level*) v)
      (apply *output-fn* (level-tag level)
             (map str args))
      nil)))

(def ^:dynamic *log-fn* log*)

(defn info [& args]
  (apply *log-fn* :info args))

(defn debug [& args]
  (apply *log-fn* :debug args))

(defn warn [& args]
  (apply *log-fn* :warn args))

(defn error [& args]
  (apply *log-fn* :error args))

(defn fatal [& args]
  (apply *log-fn* :fatal args))


