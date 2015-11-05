(ns clj-lti.oauth
  (:import javax.crypto.Mac
           javax.crypto.spec.SecretKeySpec
           java.net.URLDecoder
           java.net.URLEncoder)
  (:require [clojure.walk :as walk]
            [clojure.string :as string]
            [clojure.data.codec.base64 :as base64]))

(defn percent-encode 
  [s]
  (some-> s 
    (URLEncoder/encode "UTF-8")
    (.replace "+", "%20")
    (.replace "*", "%2A")
    (.replace "%7E", "~")))

(defn percent-decode
  [s]
  (some-> s 
    (URLDecoder/decode "UTF-8")))

(def join-params (partial string/join "&"))
(def sort-params (partial sort-by first))
(def percent-encode-params 
   (partial map #(map percent-encode %1)))
(def stringify-params (partial map (fn [[k v]] (str k "=" v))))
(defonce ^Class ArrayClass (.getClass (to-array [])))

(defn array?
  [x]
  (.isInstance ArrayClass x))

(defn expand-params
   "Account for the fact that multiple values may occur for a parameter, so
handle vectors of values, and turn them into repeated assignments, as they
might appear in a URL."	
   [l]
   (for [[k items] l
        v (if (or (coll? items) (array? items)) (vec items) [items])]
     [(name k) v]))


(defn encode-params
   [params]
   (-> params
      expand-params
      percent-encode-params
      sort-params
      stringify-params
      join-params))

(defn base-string [^String method url params]
   (join-params [(.toUpperCase method)
                 (percent-encode url)
                (percent-encode (encode-params params))]))

(defn sign
   [^String secret ^String base]
   (let [mac (Mac/getInstance "HmacSHA1")
         signing-key (SecretKeySpec. (.getBytes secret "UTF-8") (.getAlgorithm mac))]
      (.init mac signing-key)
      (String. ^bytes (base64/encode (.doFinal mac (.getBytes base))) "UTF-8")))
