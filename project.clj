(defproject com.bhauman/certifiable "0.0.4"
  :description "Assists in the creation of development SSL certificates and Java Keystore files"
  :url "https://github.com/bhauman/certifiable"
  :license {:name "Eclipse Public License"
            :url  "http://www.eclipse.org/legal/epl-v10.html"}
  :dependencies [[org.clojure/tools.cli "1.0.194"]]
  :profiles {:dev {:dependencies [[org.clojure/clojure "1.10.0"]]}}
  :deploy-repositories [["releases" :clojars]]
  :aliases {"update-readme-version" ["shell" "sed" "-i" "s/\\\\[certifiable \"[0-9.]*\"\\\\]/[certifiable \"${:version}\"]/" "README.md"]}
  #_:release-tasks #_[["shell" "git" "diff" "--exit-code"]
                  ["change" "version" "leiningen.release/bump-version"]
                  ["change" "version" "leiningen.release/bump-version" "release"]
                  ["changelog" "release"]
                  ["update-readme-version"]
                  ["vcs" "commit"]
                  ["vcs" "tag"]
                  ["deploy"]
                  ["vcs" "push"]])
