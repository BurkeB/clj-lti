(ns clj-lti.oauth-test
  (:require [clojure.test :refer :all]
            [clj-lti.oauth :refer :all]))

(def params {"status" "Hello Ladies + Gentlemen, a signed OAuth request!"
             "include_entities" "true"
             "oauth_consumer_key" "xvz1evFS4wEEPTGEFPHBog"
             "oauth_nonce" "kYjzVBB8Y0ZFabxSWbWovY3uYSQ2pTgmZeNu2VS4cg"
             "oauth_signature_method" "HMAC-SHA1"
             "oauth_timestamp" "1318622958"
             "oauth_token" "370773112-GmHxMAgYyLbNEtIKZeRNFsMKPR9EyMZeS9weJAEb"
             "oauth_version" "1.0"})
(def method "post")
(def url "https://api.twitter.com/1/statuses/update.json")
(def param-string "include_entities=true&oauth_consumer_key=xvz1evFS4wEEPTGEFPHBog&oauth_nonce=kYjzVBB8Y0ZFabxSWbWovY3uYSQ2pTgmZeNu2VS4cg&oauth_signature_method=HMAC-SHA1&oauth_timestamp=1318622958&oauth_token=370773112-GmHxMAgYyLbNEtIKZeRNFsMKPR9EyMZeS9weJAEb&oauth_version=1.0&status=Hello%20Ladies%20%2B%20Gentlemen%2C%20a%20signed%20OAuth%20request%21")
(def base "POST&https%3A%2F%2Fapi.twitter.com%2F1%2Fstatuses%2Fupdate.json&include_entities%3Dtrue%26oauth_consumer_key%3Dxvz1evFS4wEEPTGEFPHBog%26oauth_nonce%3DkYjzVBB8Y0ZFabxSWbWovY3uYSQ2pTgmZeNu2VS4cg%26oauth_signature_method%3DHMAC-SHA1%26oauth_timestamp%3D1318622958%26oauth_token%3D370773112-GmHxMAgYyLbNEtIKZeRNFsMKPR9EyMZeS9weJAEb%26oauth_version%3D1.0%26status%3DHello%2520Ladies%2520%252B%2520Gentlemen%252C%2520a%2520signed%2520OAuth%2520request%2521")
(def signing-key "kAcSOqF21Fu85e7zjz7ZN2U4ZRhfV3WpwPAoE3Z7kBw&LswwdoUaIvS8ltyTt5jkRh4J50vUPVVHtR2YPi5kE")

(deftest percent-encode-test
  (testing "Percent encoding"
    (is (= (percent-encode "Ladies + Gentlemen") "Ladies%20%2B%20Gentlemen"))
    (is (= (percent-encode "An encoded string!") "An%20encoded%20string%21"))
    (is (= (percent-encode "Dogs, Cats & Mice") "Dogs%2C%20Cats%20%26%20Mice"))
    (is (= (percent-encode "☃") "%E2%98%83"))))

(deftest encode-params-test
  (testing "Parameter strings"
    (is (= (encode-params params) param-string))
    (is (= (encode-params (clojure.walk/keywordize-keys params)) param-string))))

(deftest base-string-test
  (testing "base-string"
    (is (= (base-string method url params) base))))

(deftest sign-test
  (testing "signing"
    (is (= (sign signing-key (base-string method url params) "HmacSHA1") "tnnArxj06cWHq44gCs1OSKk/jLY="))))
