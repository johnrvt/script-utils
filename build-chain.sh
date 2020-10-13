#!/bin/bash
#
# Build a certificate chain from a single certificate.
#
# Copyright (c) 2019  Jonathan Ravat
# Licensed under the MIT license.

set -e

if [ $# != 1 ]; then
    echo "$0: missing argument: try '$0 --help'" >&2
    exit 1
fi

case "$1" in
    -h|--help)
        echo "Synopsis: $0 CERTIFICATE"
        echo "Build a certificate chain from a single certificate."
        echo
        echo "The certificate chain is written in the same path of the input certificate,"
        echo "using the same filename by removing the '.crt' or '.pem' suffix if any, and"
        echo "adding '.chained.crt' to it."
        exit 0
    ;;
esac

which openssl >/dev/null || echo "$0: missing openssl command. Please install 'openssl'." >&2
which certtool >/dev/null || echo "$0: missing certtool command. Please install 'gnutls-bin'." >&2
which openssl certtool >/dev/null || exit 1

cert="$1"
certpath=$(dirname "$cert")
tmpdir=$(mktemp -d)
certlist=("$cert")

subject_hash=$(openssl x509 -in "$cert" -noout -subject_hash)
issuer_hash=$(openssl x509 -in "$cert" -noout -issuer_hash)

while [ "$subject_hash" != "$issuer_hash" ]; do
    # Get intermediate CA
    issuer_uri=$(openssl x509 -in "$cert" -noout -text | grep -F "CA Issuers - URI:" | sed 's/^.*URI://')
    if [ -n "$issuer_uri" ]; then
        issuer_filename=$(basename "$issuer_uri")
        issuer_cert="$certpath/$issuer_filename"
        wget -nv -O "$tmpdir/$issuer_filename" "$issuer_uri"
        openssl x509 -in "$tmpdir/$issuer_filename" -out "$issuer_cert" 2>/dev/null || openssl x509 -in "$tmpdir/$issuer_filename" -inform DER -out "$issuer_cert"
    else
        local_issuer=$(ls "/etc/ssl/certs/$issuer_hash"* 2>/dev/null | tail -n 1)
        if [ -z "$local_issuer" ]; then
            echo "$0: fatal: Issuer '$(openssl x509 -in "$cert" -noout -issuer)' not found locally" >&2
            exit 1
        fi
        path_issuer=$(readlink -f "$local_issuer")
        issuer_cert="$certpath/$(basename "$path_issuer")"
        openssl x509 -in "$local_issuer" -out "$issuer_cert" 2>/dev/null || openssl x509 -in "$local_issuer" -inform DER -out "$issuer_cert"
    fi

    # Check issuer with subject
    issuer_subject_hash=$(openssl x509 -in "$issuer_cert" -noout -subject_hash)
    if [ "$issuer_hash" != "$issuer_subject_hash" ]; then
        issuer_subject=$(openssl x509 -in "$issuer_cert" -noout -subject)
        issuer_expected=$(openssl x509 -in "$cert" -noout -issuer)
        echo "$0: fatal: Subject of '$issuer_cert' is not the issuer expected: has '$issuer_subject' but expect '$issuer_expected'" >&2
        exit 1
    fi

    certlist[${#certlist[@]}]="$issuer_cert"
    cert="$issuer_cert"
    subject_hash=$(openssl x509 -in "$cert" -noout -subject_hash)
    issuer_hash=$(openssl x509 -in "$cert" -noout -issuer_hash)
done

# Check for auto-signed certificate
if [ ${#certlist[@]} == 1 ]; then
    echo "$0: $1: nothing to do: auto-signed certificate" >&2
    exit 2
fi

# Verify chain
verify_opts=(-trusted "${certlist[-1]}")
for (( i=1; i < ${#certlist[@]} - 1; i++ )); do
    verify_opts[${#verify_opts[@]}]=-untrusted
    verify_opts[${#verify_opts[@]}]="${certlist[$i]}"
done
echo -n "Verify chain: "
openssl verify "${verify_opts[@]}" "$1"

# Generate certificate chain and bundle (issuers certificates)
base_cert=$(echo "$1" | sed -E 's/\.(crt|pem)$//')
chaincert="$base_cert.chained.crt"
bundlecert="$base_cert.bundle.crt"
> "$chaincert"
> "$bundlecert"
for f in "${certlist[@]}"; do
    openssl x509 -in "$f" >> "$chaincert"
    [ "$f" != "$1" ] && openssl x509 -in "$f" >> "$bundlecert"
done

# Check certificate chain
certtool --verify-chain --verify-profile=high --infile="$chaincert"

