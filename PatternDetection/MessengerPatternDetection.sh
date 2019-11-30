#!/bin/bash

if echo "$1" | grep -Eq 'https?:\/\/([a-zA-Z0-9-]*\.)?(messenger\.com).*'; then
	UseMessengerRegex='true'
fi
