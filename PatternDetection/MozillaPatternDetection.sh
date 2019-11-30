#!/bin/bash

if echo "$1" | grep -Eq 'https?:\/\/([a-zA-Z0-9-]*\.)?(mozilla\.org).*'; then
	UseMozillaRegex='true'
fi
