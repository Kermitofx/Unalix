#!/bin/bash

if echo "$1" | grep -Eq '(https:\/\/|http:\/\/)([a-zA-Z0-9-]*\.)?(amazon-adsystem)(\.[a-zA-Z]{2,}).*'; then
	UseAmazonAdsRegex='true'
fi
