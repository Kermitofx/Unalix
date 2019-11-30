#!/bin/bash

if echo "$1" | grep -Eq 'https?:\/\/([a-zA-Z0-9-]*\.)?(vitamix\.com).*'; then
	UseVitamixRegex='true'
fi
