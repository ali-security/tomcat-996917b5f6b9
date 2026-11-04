#!/usr/bin/env bash

# Licensed to the Apache Software Foundation (ASF) under one or more
# contributor license agreements.  See the NOTICE file distributed with
# this work for additional information regarding copyright ownership.
# The ASF licenses this file to You under the Apache License, Version 2.0
# (the "License"); you may not use this file except in compliance with
# the License.  You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

# Regenerates the test PKI in test/org/apache/tomcat/util/net (the committed
# certificates expired in 2021, which breaks every TLS test). Same layout as
# keystore-info.txt: CA "Apache Tomcat Test CA" (ca.jks / ca-cert.pem), RSA and
# EC "localhost" server certs (JKS + PKCS#8 PEM keys), client cert "user1",
# localhost-rsa-copy1.jks with key password "tomcatpass". Test-only files; none
# of them is part of any shipped jar.

set -euo pipefail
cd "$(dirname "$0")/../test/org/apache/tomcat/util/net"

DN='/C=US/ST=MA/L=Wakefield/O=The Apache Software Foundation/OU=Apache Tomcat PMC'
SP=changeit; KP=tomcatpass; DAYS=7300
SAN='subjectAltName=DNS:localhost,IP:127.0.0.1'
tmp=$(mktemp -d); trap 'rm -rf "$tmp"' EXIT

openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:4096 -out "$tmp/ca-key.pem"
openssl req -x509 -new -key "$tmp/ca-key.pem" -sha256 -days $DAYS \
    -subj "$DN/CN=Apache Tomcat Test CA" -out ca-cert.pem
rm -f ca.jks
keytool -importcert -noprompt -storetype JKS -alias ca -file ca-cert.pem \
    -keystore ca.jks -storepass $SP

leaf() {
    local name=$1 alg=$2 cn=$3 ext=${4:-}
    if [ "$alg" = ec ]; then
        openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:prime256v1 -out ${name}-key.pem
    else
        openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 -out ${name}-key.pem
    fi
    local extf="$tmp/$name.ext"
    printf 'basicConstraints=CA:FALSE\n' > "$extf"
    if [ -n "$ext" ]; then printf '%s\n' "$ext" >> "$extf"; fi
    openssl req -new -key ${name}-key.pem -sha256 -subj "$DN/CN=$cn" -out "$tmp/$name.csr"
    openssl x509 -req -in "$tmp/$name.csr" -CA ca-cert.pem -CAkey "$tmp/ca-key.pem" \
        -CAcreateserial -CAserial "$tmp/ca.srl" -sha256 -days $DAYS -extfile "$extf" \
        -out ${name}-cert.pem
}

jks() {
    local name=$1 alias=$2 store=$3 keypass=$4
    cat ${name}-cert.pem ca-cert.pem > "$tmp/$name-chain.pem"
    openssl pkcs12 -export -in "$tmp/$name-chain.pem" -inkey ${name}-key.pem \
        -name $alias -passout pass:$SP -out "$tmp/$name.p12"
    rm -f "$store"
    keytool -importkeystore -noprompt -srckeystore "$tmp/$name.p12" -srcstoretype PKCS12 \
        -srcstorepass $SP -srcalias $alias -destkeystore "$store" -deststoretype JKS \
        -deststorepass $SP -destkeypass $keypass -destalias $alias
}

leaf localhost-rsa rsa localhost "$SAN"
leaf localhost-ec  ec  localhost "$SAN"
leaf user1         rsa user1     ""
jks localhost-rsa tomcat localhost-rsa.jks       $SP
jks localhost-ec  tomcat localhost-ec.jks        $SP
jks user1         user1  user1.jks               $SP
jks localhost-rsa tomcat localhost-rsa-copy1.jks $KP
# user1 key/cert PEMs are not part of the committed fixture set
rm -f user1-key.pem user1-cert.pem

for f in *.jks; do
    echo "== $f"
    keytool -list -v -keystore "$f" -storepass $SP | grep -E 'Alias name|Valid from'
done
echo "makeTestCerts: regenerated test PKI (valid $DAYS days)"
