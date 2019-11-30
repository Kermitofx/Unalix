#!/bin/bash

if echo "$1" | grep -Eq '(https:\/\/|http:\/\/)([a-zA-Z0-9\.]*)?(doubleclick)(\.[a-zA-Z]{2,}).*'; then
	UseDoubleclickRegex='true'
fi
