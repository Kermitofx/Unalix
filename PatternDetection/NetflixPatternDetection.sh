#!/bin/bash

if echo "$1" | grep -Eq '(https:\/\/|http:\/\/)([a-zA-Z0-9-]*\.)?(netflix)(\.[a-zA-Z]{2,}).*'; then
	UseNetflixRegex='true'
fi
