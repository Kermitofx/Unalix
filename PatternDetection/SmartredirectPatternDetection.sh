#!/bin/bash

if echo "$1" | grep -Eq 'https?:\/\/([a-zA-Z0-9-]*\.)?(smartredirect\.de).*'; then
	UseSmartredirectRegex='true'
fi
