#!/bin/bash

if echo "$1" | grep -Eq '(https:\/\/|http:\/\/)([a-zA-Z0-9-]*\.)?(cnet\.com).*'; then
	UseCnetRegex='true'
fi
