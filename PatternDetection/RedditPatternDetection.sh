#!/bin/bash

if echo "$1" | grep -Eq '(https:\/\/|http:\/\/)([a-zA-Z0-9-]*\.)?(reddit)(\.[a-zA-Z]{2,}).*'; then
	UseRedditRegex='true'
fi
