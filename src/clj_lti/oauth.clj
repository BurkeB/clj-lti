(ns clj-lti.oauth
  (:import oauth.signpost.OAuth
           javax.crypto.Mac
           javax.crypto.spec.SecretKeySpec)
  (:require [clojure.walk :as walk]
            [clojure.string :as string]
            [clojure.data.codec.base64 :as base64]))

(declare percent-encode)

(def join-params (partial string/join "&"))
(def sort-params (partial sort-by first))
(def percent-encode-params 
   (partial map #(map percent-encode %1)))
(def stringify-params (partial map (fn [[k v]] (str k "=" v))))

(defn expand-params
   "Account for the fact that multiple values may occur for a parameter, so
handle vectors of values, and turn them into repeated assignments, as they
might appear in a URL."	
   [l]
   (for [[k items] l
        v (if (vector? items) items [items])]
     [(name k) v]))

(defn percent-encode
  "Percent-encode a given string."
  [param]
  (OAuth/percentEncode param))

(defn encode-params
   [params]
   (-> params
      expand-params
      percent-encode-params
      sort-params
      stringify-params
      join-params))

(defn base-string [method url params]
   (join-params [(.toUpperCase method)
                 (percent-encode url)
                (percent-encode (encode-params params))]))

(defn sign
   [^String secret ^String base]
   (let [mac (Mac/getInstance "HmacSHA1")
         signing-key (SecretKeySpec. (.getBytes secret "UTF-8") (.getAlgorithm mac))]
      (.init mac signing-key)
      (String. (base64/encode (.doFinal mac (.getBytes base))) "UTF-8")))
