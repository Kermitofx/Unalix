#!/bin/bash

if echo "$1" | grep -Eq '(https:\/\/|http:\/\/)([a-zA-Z0-9-]*\.)?(tweakers\.net).*'; then
	UseTweakersRegex='true'
fi
