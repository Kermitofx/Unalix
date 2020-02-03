#!/bin/bash

# The network requests function. This will be used to get the direct link of shortened URLs
MakeNetworkRequest(){

	# If curl cannot access the link for any reason, the value of the "$URL" variable will be considered the "final URL"
	echo "$URL" > "$TrashURLFilename"
	# Make request
	timeout -s '9' "$ConnectionTimeout" curl -LNkB --raw --head --ignore-content-length --no-progress-meter --no-sessionid --ssl-no-revoke --no-keepalive $NetworkProtocol $Socks5 $CACertOptions $DoHOptions -H 'Accept:' --request 'GET' --user-agent "$UserAgent" --url "$URL" | grep -E '^(L|l)(O|o)(C|c)(A|a)(T|t)(I|i)(O|o)(N|n):\s*' | ParseText >> "$TrashURLFilename"
	# If the URL does not have a valid protocol, set it to http
	sed -ri 's/^(https?(:\/\/|%3A%2F%2F|%3a%2f%2f))?/http:\/\//g' "$TrashURLFilename"
	# Set received data
	URL=$(ParseText < "$TrashURLFilename" | tail -1)

}

# Delete placeholder files (from git), creat all needed directories and set all environment variables
SetupUnalix(){

	rm -f "$HOME/Unalix/Administrators/placeholder" "$HOME/Unalix/Reports/placeholder"
	[ -d "$HOME/Unalix/Rules" ] || { mkdir -m '700' -p "$HOME/Unalix/Rules"; }
	[ -d "$HOME/Unalix/TempFiles" ] || { mkdir -m '700' -p "$HOME/Unalix/TempFiles"; }
	[ -d "$HOME/Unalix/PatternDetection" ] || { mkdir -m '700' -p "$HOME/Unalix/PatternDetection"; }
	[ -d "$HOME/Unalix/Reports" ] || { mkdir -m '700' -p "$HOME/Unalix/Reports"; }
	
	# Import all variables from "$HOME/Unalix/Settings/Settings.txt"
	source "$HOME/Unalix/Settings/Settings.txt" || { echo -e '\033[0;31mAn error occurred while trying to import the settings file!\033[0m'; exit; }

	# Check if "$BotToken" is a valid value
	[[ "$BotToken" =~ [0-9]+:[A-Za-z0-9_-]+ ]] || { echo -e '\033[0;31m"$BotToken" contains a invalid value. Unalix cannot be started!\033[0m'; exit; }
	
	# Check if "$DoH" is a valid value'
	if [[ "$DoH" =~ https://[a-zA-Z0-9._-]{1,}\.[a-zA-Z0-9._-]{2,}(:443)?(/[a-zA-Z0-9._-]*)? ]]; then
		# If Tor traffic is enabled, disable DNS-over-HTTPS
		if [ "$TorTraffic" = 'true' ]; then
			unset 'DoHOptions' 
		else
			DoHOptions="--doh-url $DoH"
		fi
	else
		unset 'DoHOptions'
	fi
	
	# Check if "$TorTraffic" is set to "true"
	[ "$TorTraffic" = 'true' ] && Socks5='--socks5 127.0.0.1:9050' || { unset 'UseSocks5'; }

	# Check if "$DisableIPv4" is set to "true"
	if [ "$DisableIPv4" = 'true' ]; then
		NetworkProtocol='--ipv6'
	# Check if "$DisableIPv6" is set to "true"
	elif [ "$DisableIPv6" = 'true' ]; then
		NetworkProtocol='--ipv4'
	else
		unset 'NetworkProtocol'
	fi

	# Check if "$ConnectionTimeout" is a valid value
	[[ "$ConnectionTimeout" =~ [0-9]+ ]] || { ConnectionTimeout='25'; }

	# Check if "$SimultaneouslyOperations" is a valid value
	[ "$SimultaneouslyOperations" = 'true' ] && Simultaneously='true' || { unset 'Simultaneously'; }

	# Check if "$CurlCustomCertificates" and "$CurlCustomCertificatesPath" are valid values
	if [ "$CurlCustomCertificates" = 'true' ]; then
		if [ -z "$CurlCustomCertificatesPath" ]; then
			echo -e '\033[0;31mNo path was specified for the CA certificate store!\033[0m'; exit '1'
		else
			CACertOptions="--cacert $CurlCustomCertificatesPath"
		fi
	else
		unset 'CACertOptions'
	fi

	# Check if the package "idn" is installed
	if [[ "$(idn 'i❤️.ws')" != 'xn--i-7iq.ws' ]]; then
		echo -e '\033[0;31mThe "idn" package is not installed, inaccessible or has limitations!\033[0m'
	fi
	
	# Check if the package "idn2" is installed
	if [[ "$(idn2 'президент.рф')" != 'xn--d1abbgf6aiiy.xn--p1ai' ]]; then
		echo -e '\033[0;31mThe "idn2" package is not installed, inaccessible or has limitations!\033[0m'
	fi
	
	# Check if the package "bash" is installed
	if [[ -z "$(bash --version)" ]]; then
		echo -e '\033[0;31mThe "bash" package is not installed, inaccessible or has limitations!\033[0m'; exit '1'
	fi

	# Check if the package "curl" is installed
	if [[ -z "$(curl --version)" ]]; then
		echo -e '\033[0;31mThe "curl" package is not installed, inaccessible or has limitations!\033[0m'; exit '1'
	fi
	
	# Check if the package "jq" is installed
	if [[ -z "$(jq --version)" ]]; then
		echo -e '\033[0;31mThe "jq" package is not installed, inaccessible or has limitations!\033[0m'; exit '1'
	fi
	
	# Check if the package "vim" is installed
	if [[ -z "$(vim --version)" ]]; then
		echo -e '\033[0;31mThe "vim" package is not installed, inaccessible or has limitations!\033[0m'; exit '1'
	fi
	
	# Check if the package "xmlstarlet" is installed
	if [[ "$(echo '&amp;' | xmlstarlet -q 'unesc')" != '&' ]]; then
		echo -e '\033[0;31mThe "xmlstarlet" package is not installed, inaccessible or has limitations!\033[0m'; exit '1'
	fi
	
	# Set default permissions
	chmod -R '700' "$HOME/Unalix"
	
	return '0'

}

# Remove trackings parameters using regex patterns stored in the "$EndRegex" file
RemoveTrackingParameters(){

	# Parse "redirection" rules
	for RegexRules in $(grep -E '^Redirection\=' "$EndRegex" | sed -r '/^#.*|^$/d; s/^Redirection\=//g')
	do
		URL=$(echo "$URL" | sed -r "s/$RegexRules.*/\1/g")
	done

	# The "redirect" URL needs to be decoded, since it may contain encoded characters
	URL=$(DecodeText "$URL")

	# Remove specific fields
	for RegexRules in $(sed -r '/^Redirection\=/d; /^#.*|^$/d' < "$EndRegex")
	do
		URL=$(echo "$URL"| sed -r "s/\b$RegexRules//g")
	done

	# Parse "special" rules
	for SpecialRegexRules in $(sed -r '/^#.*|^$/d' < "$SpecialEndRegex")
	do
		URL=$(echo "$URL" | sed -r "$SpecialRegexRules")
	done

}

# This is used to decide which regex patterns will be (or not) used to remove tracking fields from links sent by users
DetectPatterns(){
	
	# Import all variables from scripts in "Unalix/PatternDetection"
	for Patterns in $(find "$HOME/Unalix/PatternDetection" -maxdepth '1' -type 'f' -regex '^.*PatternDetection\.sh$')
	do
		source "$Patterns" "$URL"
	done

	# Import all regex patterns that will be used
	[ "$UseMozawsRegex" = 'true' ] && cat "$HOME/Unalix/Rules/Common/MozawsRules.txt" > "$EndRegex" && unset 'UseMozawsRegex'
	[ "$UseDoubleclickRegex" = 'true' ] && cat "$HOME/Unalix/Rules/Common/DoubleclickRules.txt" >> "$EndRegex" && unset 'UseDoubleclickRegex'
	[ "$UseTechcrunchRegex" = 'true' ] && cat "$HOME/Unalix/Rules/Common/TechcrunchRules.txt" >> "$EndRegex" && unset 'UseTechcrunchRegex'
	[ "$UseFacebookRegex" = 'true' ] && cat "$HOME/Unalix/Rules/Common/FacebookRules.txt" >> "$EndRegex" && unset 'UseFacebookRegex'
	[ "$UseNetflixRegex" = 'true' ] && cat "$HOME/Unalix/Rules/Common/NetflixRules.txt" >> "$EndRegex" && unset 'UseNetflixRegex'
	[ "$UseCnetRegex" = 'true' ] && cat "$HOME/Unalix/Rules/Common/CnetRules.txt" >> "$EndRegex" && unset 'UseCnetRegex'
	[ "$UseAliExpressRegex" = 'true' ] && cat "$HOME/Unalix/Rules/Common/AliExpressRules.txt" >> "$EndRegex" && unset 'UseAliExpressRegex'
	[ "$UseCurseforgeRegex" = 'true' ] && cat "$HOME/Unalix/Rules/Common/CurseforgeRules.txt" >> "$EndRegex" && unset 'UseCurseforgeRegex'
	[ "$UseSpiegelRegex" = 'true' ] && cat "$HOME/Unalix/Rules/Common/SpiegelRules.txt" >> "$EndRegex" && unset 'UseSpiegelRegex'
	[ "$UseYoukuRegex" = 'true' ] && cat "$HOME/Unalix/Rules/Common/YoukuRules.txt" >> "$EndRegex" && unset 'UseYoukuRegex'
	[ "$UseTwitterRegex" = 'true' ] && cat "$HOME/Unalix/Rules/Common/TwitterRules.txt" >> "$EndRegex" && unset 'UseTwitterRegex'
	[ "$UsePrvnizpravyRegex" = 'true' ] && cat "$HOME/Unalix/Rules/Common/PrvnizpravyRules.txt" >> "$EndRegex" && unset 'UsePrvnizpravyRegex'
	[ "$UseBingRegex" = 'true' ] && cat "$HOME/Unalix/Rules/Common/BingRules.txt" >> "$EndRegex" && unset 'UseBingRegex'
	[ "$UseEbayRegex" = 'true' ] && cat "$HOME/Unalix/Rules/Common/EbayRules.txt" >> "$EndRegex" && unset 'UseEbayRegex'
	[ "$UseOzonRegex" = 'true' ] && cat "$HOME/Unalix/Rules/Common/OzonRules.txt" >> "$EndRegex" && unset 'UseOzonRegex'
	[ "$UseLinkedInRegex" = 'true' ] && cat "$HOME/Unalix/Rules/Common/LinkedInRules.txt" >> "$EndRegex" && unset 'UseLinkedInRegex'
	[ "$UseFacebookRegex" = 'true' ] && cat "$HOME/Unalix/Rules/Common/FacebookRules.txt" >> "$EndRegex" && unset 'UseFacebookRegex'
	[ "$UseYouTubeRegex" = 'true' ] && cat "$HOME/Unalix/Rules/Common/YouTubeRules.txt" >> "$EndRegex" && unset 'UseYouTubeRegex'
	[ "$UseDailycodingproblemRegex" = 'true' ] && cat "$HOME/Unalix/Rules/Common/DailycodingproblemRules.txt" >> "$EndRegex" && unset 'UseDailycodingproblemRegex'
	[ "$UseVivaldiRegex" = 'true' ] && cat "$HOME/Unalix/Rules/Common/VivaldiRules.txt" >> "$EndRegex" && unset 'UseVivaldiRegex'
	[ "$UseReaddcRegex" = 'true' ] && cat "$HOME/Unalix/Rules/Common/ReaddcRules.txt" >> "$EndRegex" && unset 'UseReaddcRegex'
	[ "$UseTchiboRegex" = 'true' ] && cat "$HOME/Unalix/Rules/Common/TchiboRules.txt" >> "$EndRegex" && unset 'UseTchiboRegex'
	[ "$UseVKRegex" = 'true' ] && cat "$HOME/Unalix/Rules/Common/VKRules.txt" >> "$EndRegex" && unset 'UseVKRegex'
	[ "$UseSiteRegex" = 'true' ] && cat "$HOME/Unalix/Rules/Common/Site.txt" >> "$EndRegex" && unset 'UseSiteRegex'
	[ "$UseWalmartRegex" = 'true' ] && cat "$HOME/Unalix/Rules/Common/WalmartRules.txt" >> "$EndRegex" && unset 'UseWalmartRegex'
	[ "$UseNormlRegex" = 'true' ] && cat "$HOME/Unalix/Rules/Common/NormlRules.txt" >> "$EndRegex" && unset 'UseNormlRegex'
	[ "$UseSteampoweredRegex" = 'true' ] && cat "$HOME/Unalix/Rules/Common/SteampoweredRules.txt" >> "$EndRegex" && unset 'UseSteampoweredRegex'
	[ "$UseSite2Regex" = 'true' ] && cat "$HOME/Unalix/Rules/Common/Site2Rules.txt" >> "$EndRegex" && unset 'UseSite2Regex'
	[ "$UseGoogleAdsRegex" = 'true' ] && cat "$HOME/Unalix/Rules/Common/GoogleAdsRules.txt" >> "$EndRegex" && unset 'UseGoogleAdsRegex'
	[ "$UseWootRegex" = 'true' ] && cat "$HOME/Unalix/Rules/Common/WootRules.txt" >> "$EndRegex" && unset 'UseWootRegex'
	[ "$Use9GAGRegex" = 'true' ] && cat "$HOME/Unalix/Rules/Common/9GAGRules.txt" >> "$EndRegex" && unset 'Use9GAGRegex'
	[ "$UseImdbRegex" = 'true' ] && cat "$HOME/Unalix/Rules/Common/ImdbRules.txt" >> "$EndRegex" && unset 'UseImdbRegex'
	[ "$UseMozawsRegex" = 'true' ] && cat "$HOME/Unalix/Rules/Common/MozawsRules.txt" >> "$EndRegex" && unset 'UseMozawsRegex'
	[ "$UseGitHubRegex" = 'true' ] && cat "$HOME/Unalix/Rules/Common/GitHubRules.txt" >> "$EndRegex" && unset 'UseGitHubRegex'
	[ "$UseSteamcommunityRegex" = 'true' ] && cat "$HOME/Unalix/Rules/Common/SteamcommunityRules.txt" >> "$EndRegex" && unset 'UseSteamcommunityRegex'
	[ "$UseShutterstockRegex" = 'true' ] && cat "$HOME/Unalix/Rules/Common/ShutterstockRules.txt" >> "$EndRegex" && unset 'UseShutterstockRegex'
	[ "$UseNetParadeRegex" = 'true' ] && cat "$HOME/Unalix/Rules/Common/NetParadeRules.txt" >> "$EndRegex" && unset 'UseNetParadeRegex'
	[ "$UseGovdeliveryRegex" = 'true' ] && cat "$HOME/Unalix/Rules/Common/GovdeliveryRules.txt" >> "$EndRegex" && unset 'UseGovdeliveryRegex'
	[ "$UseMessengerRegex" = 'true' ] && cat "$HOME/Unalix/Rules/Common/MessengerRules.txt" >> "$EndRegex" && unset 'UseMessengerRegex'
	[ "$UseGoogleRegex" = 'true' ] && cat "$HOME/Unalix/Rules/Common/GoogleRules.txt" >> "$EndRegex" && unset 'UseGoogleRegex'
	[ "$UseSmartredirectRegex" = 'true' ] && cat "$HOME/Unalix/Rules/Common/SmartredirectRules.txt" >> "$EndRegex" && unset 'UseSmartredirectRegex'
	[ "$UseVitamixRegex" = 'true' ] && cat "$HOME/Unalix/Rules/Common/VitamixRules.txt" >> "$EndRegex" && unset 'UseVitamixRegex'
	[ "$UseIndeedRegex" = 'true' ] && cat "$HOME/Unalix/Rules/Common/IndeedRules.txt" >> "$EndRegex" && unset 'UseIndeedRegex'
	[ "$UseMozillaZineRegex" = 'true' ] && cat "$HOME/Unalix/Rules/Common/MozillaZineRules.txt" >> "$EndRegex" && unset 'UseMozillaZineRegex'
	[ "$UseGiphyRegex" = 'true' ] && cat "$HOME/Unalix/Rules/Common/GiphyRules.txt" >> "$EndRegex" && unset 'UseGiphyRegex'
	[ "$UseGenericRegex" = 'true' ] && cat "$HOME/Unalix/Rules/Common/GlobalRules.txt" >> "$EndRegex" && unset 'UseGenericRegex'
	[ "$UseTwitchRegex" = 'true' ] && cat "$HOME/Unalix/Rules/Common/TwitchRules.txt" >> "$EndRegex" && unset 'UseTwitchRegex'
	[ "$UseLinksynergyRegex" = 'true' ] && cat "$HOME/Unalix/Rules/Common/LinksynergyRules.txt" >> "$EndRegex" && unset 'UseLinksynergyRegex'
	[ "$UseAmazonRegex" = 'true' ] && cat "$HOME/Unalix/Rules/Common/AmazonRules.txt" >> "$EndRegex" && unset 'UseAmazonRegex'
	[ "$UseTweakersRegex" = 'true' ] && cat "$HOME/Unalix/Rules/Common/TweakersRules.txt" >> "$EndRegex" && unset 'UseTweakersRegex'
	[ "$UseAmazonAdsRegex" = 'true' ] && cat "$HOME/Unalix/Rules/Common/AmazonAdsRules.txt" >> "$EndRegex" && unset 'UseAmazonAdsRegex'
	[ "$UseSite3Regex" = 'true' ] && cat "$HOME/Unalix/Rules/Common/Site3Rules.txt" >> "$EndRegex" && unset 'UseSite3Regex'
	[ "$UseRedditRegex" = 'true' ] && cat "$HOME/Unalix/Rules/Common/RedditRules.txt" >> "$EndRegex" && unset 'UseRedditRegex'
	[ "$UseDeviantartRegex" = 'true' ] && cat "$HOME/Unalix/Rules/Common/DeviantartRules.txt" >> "$EndRegex" && unset 'UseDeviantartRegex'
	[ "$UseMozillaRegex" = 'true' ] && cat "$HOME/Unalix/Rules/Common/MozillaRules.txt" >> "$EndRegex" && unset 'UseMozillaRegex'
	[ "$UseDisqusRegex" = 'true' ] && cat "$HOME/Unalix/Rules/Common/DisqusRules.txt" >> "$EndRegex" && unset 'UseDisqusRegex'
	[ "$UseHhdotruRegex" = 'true' ] && cat "$HOME/Unalix/Rules/Common/HhdotruRules.txt" >> "$EndRegex" && unset 'UseHhdotruRegex'
	[ "$UseNytimesRegex" = 'true' ] && cat "$HOME/Unalix/Rules/Common/NytimesRules.txt" >> "$EndRegex" && unset 'UseNytimesRegex'
	[ "$UseNypostRegex" = 'true' ] && cat "$HOME/Unalix/Rules/Common/NypostRules.txt" >> "$EndRegex" && unset 'UseNypostRegex'
	[ "$UseGateRegex" = 'true' ] && cat "$HOME/Unalix/Rules/Common/GateRules.txt" >> "$EndRegex" && unset 'UseGateRegex'
	[ "$UseTelefonicaVivoRegex" = 'true' ] && cat "$HOME/Unalix/Rules/Common/TelefonicaVivoRules.txt" >> "$EndRegex" && unset 'UseTelefonicaVivoRegex'
	[ "$UseBloggerRegex" = 'true' ] && cat "$HOME/Unalix/Rules/Common/BloggerRules.txt" >> "$EndRegex" && unset 'UseBloggerRegex'
	[ "$UseKabumRegex" = 'true' ] && cat "$HOME/Unalix/Rules/Common/KabumRules.txt" >> "$EndRegex" && unset 'UseKabumRegex'
	[ "$UseOuoIoRegex" = 'true' ] && cat "$HOME/Unalix/Rules/Common/OuoIoRules.txt" >> "$EndRegex" && unset 'UseOuoIoRegex'
	[ "$UseMercadoLibreRegex" = 'true' ] && cat "$HOME/Unalix/Rules/Common/MercadoLibreRules.txt" >> "$EndRegex" && unset 'UseMercadoLibreRegex'
	[ "$UseGoogleAMPRegex" = 'true' ] && cat "$HOME/Unalix/Rules/Special/GoogleAMPRules.txt" > "$SpecialEndRegex" && unset 'UseGoogleAMPRegex'
	[ "$UseMobileFieldsRegex" = 'true' ] && cat "$HOME/Unalix/Rules/Special/MobileFieldsRules.txt" >> "$SpecialEndRegex" && unset 'UseMobileFieldsRegex'

}

# Set filename variables
SetFilenameVariables(){

	if [ "$1" = '--ip-query' ]; then
		rm -f "$DNSAnswerFilename" "$IPAddressFilename"
		DNSAnswerFilename="$HOME/Unalix/TempFiles/Resolved-$(tr -dc '[:alnum:]' < '/dev/urandom' | head -c 10).txt"
		IPAddressFilename="$HOME/Unalix/TempFiles/IPAddress-$(tr -dc '[:alnum:]' < '/dev/urandom' | head -c 10).txt"
	elif [ "$1" = '--simultaneously' ]; then
		SimultaneouslyEndResult="$SimultaneouslyRequestsDirectory/EndResult-$(tr -dc '[:alnum:]' < '/dev/urandom' | head -c 10).txt"
		SpecialEndRegex="$SimultaneouslyRequestsDirectory/SpecialRegex-$(tr -dc '[:alnum:]' < '/dev/urandom' | head -c 10).txt"
		EndRegex="$SimultaneouslyRequestsDirectory/EndRegex-$(tr -dc '[:alnum:]' < '/dev/urandom' | head -c 10).txt"
		TrashURLFilename="$SimultaneouslyRequestsDirectory/TrashURL-$(tr -dc '[:alnum:]' < '/dev/urandom' | head -c 10).txt"
		RequestRunning="$SimultaneouslyRequestsDirectory/RequestRunning-$(tr -dc '[:alnum:]' < '/dev/urandom' | head -c 10).txt"
	else
		rm -f "$OriginalLinksFilename" "$EndResults" "$CleanedURLs" "$SpecialEndRegex" "$EndRegex" "$TrashURLFilename" "$LinksFilename" "$GetFromURLsFilename"
		OriginalLinksFilename="$HOME/Unalix/TempFiles/OriginalLinks-$(tr -dc '[:alnum:]' < '/dev/urandom' | head -c 10).txt"
		EndResults="$HOME/Unalix/TempFiles/EndResults-$(tr -dc '[:alnum:]' < '/dev/urandom' | head -c 10).txt"
		CleanedURLs="$HOME/Unalix/TempFiles/CleanedURLs-$(tr -dc '[:alnum:]' < '/dev/urandom' | head -c 10).txt"
		SpecialEndRegex="$HOME/Unalix/TempFiles/SpecialRegex-$(tr -dc '[:alnum:]' < '/dev/urandom' | head -c 10).txt"
		EndRegex="$HOME/Unalix/TempFiles/EndRegex-$(tr -dc '[:alnum:]' < '/dev/urandom' | head -c 10).txt"
		TrashURLFilename="$HOME/Unalix/TempFiles/TrashURL-$(tr -dc '[:alnum:]' < '/dev/urandom' | head -c 10).txt"
		LinksFilename="$HOME/Unalix/TempFiles/Links-$(tr -dc '[:alnum:]' < '/dev/urandom' | head -c 10).txt"
		GetFromURLsFilename="$HOME/Unalix/TempFiles/GetFromURLs-$(tr -dc '[:alnum:]' < '/dev/urandom' | head -c 10).txt"
	fi

}

# This is the main function. It calls all other functions related to removal of tracking fields
ParseTrackingParameters(){

	URL=$(DecodeText "$URL")

	DetectPatterns; RemoveTrackingParameters; SolveURLIssues

	MakeNetworkRequest

	URL=$(DecodeText "$URL")

	DetectPatterns; RemoveTrackingParameters; SolveURLIssues

}

# Get end results and check if it's valid
GetEndResults(){

	if [ "$BatchMode" != 'true' ]; then
		[[ "$URL" =~ ^https?://[a-zA-Z0-9._-]{1,}\.[a-zA-Z0-9._-]{2,}(:[0-9]{1,5})?(/|%2F|\?|#)?.*$ ]] && MakeURLCompatible && ChatAction --stop-broadcast && sendMessage --reply_to_message_id "$message_message_id" --chat_id "$message_chat_id" --text "\`$URL\`" --parse_mode 'markdown' --disable_web_page_preview 'true' || { ChatAction --stop-broadcast; sendMessage --reply_to_message_id "$message_message_id" --chat_id "$message_chat_id" --text "The \`ParseTrackingParameters\` function has returned an invalid result." --parse_mode 'markdown'; }; cleanup
	else
		if [ "$Simultaneously" != 'true' ]; then
			[[ "$URL" =~ ^https?://[a-zA-Z0-9._-]{1,}\.[a-zA-Z0-9._-]{2,}(:[0-9]{1,5})?(/|%2F|\?|#)?.*$ ]] && MakeURLCompatible && URL=$(echo "$URL" | sed 's/\//\\\//g; s/&/\\&/g') && sed -ri "s/\s\(\*\)$/ > $URL/g" "$EndResults" || { sed -ri "s/\s\(\*\)$/ > Could not process this link/g" "$EndResults"; }
		else
			[[ "$URL" =~ ^https?://[a-zA-Z0-9._-]{1,}\.[a-zA-Z0-9._-]{2,}(:[0-9]{1,5})?(/|%2F|\?|#)?.*$ ]] && MakeURLCompatible && URL=$(echo "$URL" | sed 's/\//\\\//g; s/&/\\&/g') && sed -ri "s/\s\(\*\)$/ > $URL/g" "$SimultaneouslyEndResult" || { sed -ri "s/\s\(\*\)$/ > Could not process this link/g" "$SimultaneouslyEndResult"; }
			rm -f "$RequestRunning"
		fi
	fi

}

# Remove invalid code strokes and escape some characters to avoid errors when submitting the text to the Telegram API
MakeURLCompatible(){

	if [ "$BatchMode" != 'true' ]; then
		URL=$(echo "$URL" | sed -r 's/(%26|&){2,}//g; s/(\?&|%3f%26|%3F%26)/?/g; s/(%26|&)$//; s/(%3f|%3F|\?)$//; s/%26/&/g; s/(\s|%(25)?20)/ /g; s/%(25)?23/#/g; s/(%2F|\/)$//g') && SolveURLIssues --fix-wrong-decoding
		URL=$(EncodeText "$URL" | sed 's/%20/%2520/g') && SolveURLIssues --escape-character
	else
		URL=$(echo "$URL" | sed -r 's/&{2,}//g; s/\?&/?/g; s/(%26|&)$//; s/(%3F|\?)$//; s/(%2F|\/)$//g') && SolveURLIssues --fix-wrong-decoding
		URL=$(DecodeText "$URL" | sed -r 's/\s/%20/g') && SolveURLIssues --escape-character
	fi

}

# Delete files and and/or exit process
cleanup(){

	ChatAction --stop-broadcast
	rm -rf "$OriginalLinksFilename" "$EndResults" "$CleanedURLs" "$SpecialEndRegex" "$EndRegex" "$TrashURLFilename" "$LinksFilename" "$GetFromURLsFilename" "$DNSAnswerFilename" "$IPAddressFilename" "$SimultaneouslyRequestsDirectory"
	exit '0'

}

# The "GenerateUserAgent" function is used to randomly generate valid user agents. Each request made via curl uses a different user agent.
# This is used to prevent websites accessed from tracing the access history and possibly blocking Unalix due to "suspicious traffic".

# Client versions are randomly generated, however operating system information is valid.
# Note that the purpose of this function is not to generate real user agents, but to generate user agents in valid format. That's enough to "trick" most websites.
# To make access even more "random" and secure, run Unalix over the Tor network and change your IP address (get a new identity) regularly (e.g: within 15 or 30 minutes).
GenerateUserAgent(){

	# http://en.wikipedia.org/wiki/List_of_Microsoft_Windows_versions
	WindowsVersions=('1.01' '1.02' '1.03' '1.04' '2.03' '2.10' '2.11' '3.00' '3.10' 'NT 3.1' '3.11' '3.2' 'NT 3.5' 'NT 3.51' '4.00' 'NT 4.0' '4.10' 'NT 5.0' '4.90' 'NT 5.1' 'NT 5.2' 'NT 6.0' 'NT 6.1' 'NT 6.2' 'NT 6.3' 'NT 10.0')
	
	# http://macworld.co.uk/feature/mac/os-x-macos-versions-3662757
	macOS_Versions=('10' '10.0' '10.1' '10.2' '10.3' '10.4' '10.4.4' '10.5' '10.6' '10.7' '10.8' '10.9' '10.10' '10.11' '10.12' '10.13' '10.14' '10.15')

	# http://source.android.com/setup/start/build-numbers#source-code-tags-and-builds
	AndroidVersions=('1.6' '2.0' '2.1' '2.2' '2.2.1' '2.2.2' '2.2.3' '2.3' '2.3.3' '2.3.3' '2.3.4' '2.3.5' '2.3.6' '2.3.7' '4.0.1' '4.0.2' '4.0.3' '4.0.4' '4.1.1' '4.1.2' '4.2' '4.2.1' '4.2.2' '4.3' '4.3.1' '4.4' '4.4.1' '4.4.2' '4.4.3' '4.4.4' '5.0.0' '5.0.1' '5.0.2' '5.1.0' '5.1.1' '6.0.0' '6.0.1' '7.0.0' '7.1.0' '7.1.1' '7.1.2' '8.0.0' '8.1.0' '9.0.0' '10.0.0')
	
	# http://en.wikipedia.org/wiki/IOS_version_history
	iOSVersions=('3.1.3' '4.2.1' '5.1.1' '6.1.6' '7.1.2' '9.3.5' '9.3.6' '10.3.3' '10.3.4' '12.4.4' '13.3')
	
	# System architectures
	SystemArchitectures=('32' '64')

	# Number = Browser
	# 0 = Firefox
	# 1 = Chrome
	# 2 = Opera
	# 3 = Vivaldi
	# 4 = Yandex
	# 5 = Generic browser (this include bots and web crawlers)
	
	# Number = Operating System
	# 0 = Windows
	# 1 = macOS
	# 2 = Linux
	# 3 = Android
	# 4 = iOS

	# Generate a random number between 0 and 4 (pick a browser)
	BrowserSelection=$(tr -dc '0-5' < '/dev/urandom' | head -c '1')

	# Generate a random user agent based on the number contained in the "$BrowserSelection" variable
	if [ "$BrowserSelection" = '0' ]; then
		GenerateFirefox
	elif [ "$BrowserSelection" = '1' ]; then
		GenerateChrome
	elif [ "$BrowserSelection" = '2' ]; then
		GenerateOpera
	elif [ "$BrowserSelection" = '3' ]; then
		GenerateVivaldi
	elif [ "$BrowserSelection" = '4' ]; then
		GenerateYandex
	elif [ "$BrowserSelection" = '5' ]; then
		GenerateGeneric
	else
		UserAgent='Mozilla/5.0 (X11; Linux x86_64; rv:68.0) Gecko/20100101 Firefox/68.0'
	fi

}

# Template: http://whatismybrowser.com/guides/the-latest-user-agent/chrome
GenerateChrome(){

	# Generate a random number between 0 and 4 (pick a operating system)
 	SystemSelection=$(tr -dc '0-4' < '/dev/urandom' | head -c '1')

	# Chrome on Windows
	if [ "$SystemSelection" = '0' ]; then
		UserAgent="Mozilla/5.0 (Windows ${WindowsVersions[$(shuf -i 0-25 --random-source '/dev/urandom' | head -c '2')]}; Win${SystemArchitectures[$(tr -dc 0-1 < '/dev/urandom' | head -c '1')]}; x${SystemArchitectures[$(tr -dc 0-1 < '/dev/urandom' | head -c '1')]}) AppleWebKit/$(tr -dc '1-9' < '/dev/urandom' | head -c '3').$(tr -dc '1-9' < '/dev/urandom' | head -c '2') (KHTML, like Gecko) Chrome/$(tr -dc '1-9' < '/dev/urandom' | head -c '2').0.$(tr -dc '1-9' < '/dev/urandom' | head -c '4').$(tr -dc '1-9' < '/dev/urandom' | head -c '2') Safari/$(tr -dc '1-9' < '/dev/urandom' | head -c '3').$(tr -dc '1-9' < '/dev/urandom' | head -c '2')"
	# Chrome on macOS
	elif [ "$SystemSelection" = '1' ]; then
		UserAgent="Mozilla/5.0 (Macintosh; Intel Mac OS X ${macOS_Versions[$(shuf -i 0-17 --random-source '/dev/urandom' | head -c '2')]}) AppleWebKit/$(tr -dc '1-9' < '/dev/urandom' | head -c '3').$(tr -dc '1-9' < '/dev/urandom' | head -c '2') (KHTML, like Gecko) Chrome/$(tr -dc '1-9' < '/dev/urandom' | head -c '2').0.$(tr -dc '1-9' < '/dev/urandom' | head -c '4').$(tr -dc '1-9' < '/dev/urandom' | head -c '2') Safari/$(tr -dc '1-9' < '/dev/urandom' | head -c '3').$(tr -dc '1-9' < '/dev/urandom' | head -c '2')"
	# Chrome on Linux
	elif [ "$SystemSelection" = '2' ]; then
		UserAgent="Mozilla/5.0 (X11; Linux x86_${SystemArchitectures[$(tr -dc 0-1 < '/dev/urandom' | head -c '1')]}) AppleWebKit/$(tr -dc '1-9' < '/dev/urandom' | head -c '3').$(tr -dc '1-9' < '/dev/urandom' | head -c '2') (KHTML, like Gecko) Chrome/$(tr -dc '1-9' < '/dev/urandom' | head -c '2').0.$(tr -dc '1-9' < '/dev/urandom' | head -c '4').$(tr -dc '1-9' < '/dev/urandom' | head -c '2') Safari/$(tr -dc '1-9' < '/dev/urandom' | head -c '3').$(tr -dc '1-9' < '/dev/urandom' | head -c '2')"
	# Chrome on Android
	elif [ "$SystemSelection" = '3' ]; then
		UserAgent="Mozilla/5.0 (Linux; Android ${AndroidVersions[$(shuf -i 0-44 --random-source '/dev/urandom' | head -c '2')]}) AppleWebKit/$(tr -dc '1-9' < '/dev/urandom' | head -c '3').$(tr -dc '1-9' < '/dev/urandom' | head -c '2') (KHTML, like Gecko) Chrome/$(tr -dc '1-9' < '/dev/urandom' | head -c '2').0.$(tr -dc '1-9' < '/dev/urandom' | head -c '4').$(tr -dc '1-9' < '/dev/urandom' | head -c '2') Mobile Safari/$(tr -dc '1-9' < '/dev/urandom' | head -c '3').$(tr -dc '1-9' < '/dev/urandom' | head -c '2')"
	# Chrome on iOS
	elif [ "$SystemSelection" = '4' ]; then
		UserAgent="Mozilla/5.0 (iPhone; CPU iPhone OS ${iOSVersions[$(shuf -i 0-10 --random-source '/dev/urandom' | head -c '2')]} like Mac OS X) AppleWebKit/$(tr -dc '1-9' < '/dev/urandom' | head -c '3').$(tr -dc '1-9' < '/dev/urandom' | head -c '2') (KHTML, like Gecko) CriOS/$(tr -dc '1-9' < '/dev/urandom' | head -c '2').0.$(tr -dc '1-9' < '/dev/urandom' | head -c '4').$(tr -dc '1-9' < '/dev/urandom' | head -c '2') Mobile/$(tr -dc 'A-Z0-9' < '/dev/urandom' | head -c '7') Safari/$(tr -dc '1-9' < '/dev/urandom' | head -c '3').$(tr -dc '1-9' < '/dev/urandom' | head -c '2')"
	else
		# If for some reason the "SystemSelection" variable returns an invalid value, set a predefined user agent (Chrome on Linux)
		UserAgent='Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/79.0.3945.88 Safari/537.36'
	fi

}

# Template: http://whatismybrowser.com/guides/the-latest-user-agent/firefox
GenerateFirefox(){

	# Generate a random number between 0 and 4 (pick a operating system)
	SystemSelection=$(tr -dc '0-4' < '/dev/urandom' | head -c '1')

	# Firefox on Windows
	if [ "$SystemSelection" = '0' ]; then
		UserAgent="Mozilla/5.0 (Windows ${WindowsVersions[$(shuf -i 0-25 --random-source '/dev/urandom' | head -c '2')]}; WOW${SystemArchitectures[$(tr -dc 0-1 < '/dev/urandom' | head -c '1')]}; rv:$(tr -dc '1-9' < '/dev/urandom' | head -c '2').0) Gecko/$(tr -dc '0-9' < '/dev/urandom' | head -c '8') Firefox/$(tr -dc '1-9' < '/dev/urandom' | head -c '2').0"
	# Firefox on macOS
	elif [ "$SystemSelection" = '1' ]; then
		UserAgent="Mozilla/5.0 (Macintosh; Intel Mac OS X ${macOS_Versions[$(shuf -i 0-17 --random-source '/dev/urandom' | head -c '2')]}; rv:$(tr -dc '1-9' < '/dev/urandom' | head -c '2').0) Gecko/$(tr -dc '0-9' < '/dev/urandom' | head -c '8') Firefox/$(tr -dc '1-9' < '/dev/urandom' | head -c '2').0"
	# Firefox on Linux
	elif [ "$SystemSelection" = '2' ]; then
		UserAgent="Mozilla/5.0 (X11; Linux i586; rv:$(tr -dc '1-9' < '/dev/urandom' | head -c '2').0) Gecko/$(tr -dc '0-9' < '/dev/urandom' | head -c '8') Firefox/$(tr -dc '1-9' < '/dev/urandom' | head -c '2').0"
	# Firefox on Android
	elif [ "$SystemSelection" = '3' ]; then
		UserAgent="Mozilla/5.0 (Android ${AndroidVersions[$(shuf -i 0-44 --random-source '/dev/urandom' | head -c '2')]}; Mobile; rv:$(tr -dc '1-9' < '/dev/urandom' | head -c '2').0) Gecko/$(tr -dc '0-9' < '/dev/urandom' | head -c '8') Firefox/$(tr -dc '1-9' < '/dev/urandom' | head -c '2').0"
	# Firefox on iOS
	elif [ "$SystemSelection" = '4' ]; then
		UserAgent="Mozilla/5.0 (iPhone; CPU iPhone OS ${iOSVersions[$(shuf -i 0-10 --random-source '/dev/urandom' | head -c '2')]} like Mac OS X) AppleWebKit/$(tr -dc '1-9' < '/dev/urandom' | head -c '3').$(tr -dc '0-9' < '/dev/urandom' | head -c '1').$(tr -dc '0-9' < '/dev/urandom' | head -c '2') (KHTML, like Gecko) FxiOS/$(tr -dc '1-9' < '/dev/urandom' | head -c '2').0 Mobile/$(tr -dc A-Z1-9 < '/dev/urandom' | head -c '5') Safari/$(tr -dc '1-9' < '/dev/urandom' | head -c '3').$(tr -dc '0-9' < '/dev/urandom' | head -c '1').$(tr -dc '0-9' < '/dev/urandom' | head -c '2')"
	else
		# If for some reason the "SystemSelection" variable returns an invalid value, set a predefined user agent (Firefox on Linux)
		UserAgent='Mozilla/5.0 (X11; Linux i586; rv:31.0) Gecko/20100101 Firefox/71.0'
	fi

}

# Template: http://whatismybrowser.com/guides/the-latest-user-agent/opera
GenerateOpera(){

	# Generate a random number between 0 and 3 (pick a operating system)
	SystemSelection=$(tr -dc '0-3' < '/dev/urandom' | head -c '1')

	# Opera on Windows
	if [ "$SystemSelection" = '0' ]; then
		UserAgent="Mozilla/5.0 (Windows ${WindowsVersions[$(shuf -i 0-25 --random-source '/dev/urandom' | head -c '2')]}; Win${SystemArchitectures[$(tr -dc 0-1 < '/dev/urandom' | head -c '1')]}; x${SystemArchitectures[$(tr -dc 0-1 < '/dev/urandom' | head -c '1')]}) AppleWebKit/$(tr -dc '1-9' < '/dev/urandom' | head -c '3').$(tr -dc '1-9' < '/dev/urandom' | head -c '2') (KHTML, like Gecko) Chrome/$(tr -dc '1-9' < '/dev/urandom' | head -c '2').0.$(tr -dc '1-9' < '/dev/urandom' | head -c '4').$(tr -dc '1-9' < '/dev/urandom' | head -c '2') Safari/$(tr -dc '1-9' < '/dev/urandom' | head -c '3').$(tr -dc '1-9' < '/dev/urandom' | head -c '2') OPR/$(tr -dc '1-9' < '/dev/urandom' | head -c '2').0.$(tr -dc '1-9' < '/dev/urandom' | head -c '4').$(tr -dc '1-9' < '/dev/urandom' | head -c '2')"
	# Opera on macOS
	elif [ "$SystemSelection" = '1' ]; then
		UserAgent="Mozilla/5.0 (Macintosh; Intel Mac OS X ${macOS_Versions[$(shuf -i 0-17 --random-source '/dev/urandom' | head -c '2')]}) AppleWebKit/$(tr -dc '1-9' < '/dev/urandom' | head -c '3').$(tr -dc '1-9' < '/dev/urandom' | head -c '2') (KHTML, like Gecko) Chrome/$(tr -dc '1-9' < '/dev/urandom' | head -c '2').0.$(tr -dc '1-9' < '/dev/urandom' | head -c '4').$(tr -dc '1-9' < '/dev/urandom' | head -c '2') Safari/$(tr -dc '1-9' < '/dev/urandom' | head -c '3').$(tr -dc '1-9' < '/dev/urandom' | head -c '2') OPR/$(tr -dc '1-9' < '/dev/urandom' | head -c '2').0.$(tr -dc '1-9' < '/dev/urandom' | head -c '4').$(tr -dc '1-9' < '/dev/urandom' | head -c '2')"
	# Opera on Linux
	elif [ "$SystemSelection" = '2' ]; then
		UserAgent="Mozilla/5.0 (X11; Linux x86_${SystemArchitectures[$(tr -dc 0-1 < '/dev/urandom' | head -c '1')]}) AppleWebKit/$(tr -dc '1-9' < '/dev/urandom' | head -c '3').$(tr -dc '1-9' < '/dev/urandom' | head -c '2') (KHTML, like Gecko) Chrome/$(tr -dc '1-9' < '/dev/urandom' | head -c '2').0.$(tr -dc '1-9' < '/dev/urandom' | head -c '4').$(tr -dc '1-9' < '/dev/urandom' | head -c '2') Safari/$(tr -dc '1-9' < '/dev/urandom' | head -c '3').$(tr -dc '1-9' < '/dev/urandom' | head -c '2') OPR/$(tr -dc '1-9' < '/dev/urandom' | head -c '2').0.$(tr -dc '1-9' < '/dev/urandom' | head -c '4').$(tr -dc '1-9' < '/dev/urandom' | head -c '2')"
	# Opera on Android
	elif [ "$SystemSelection" = '3' ]; then
		UserAgent="Mozilla/5.0 (Linux; Android ${AndroidVersions[$(shuf -i 0-44 --random-source '/dev/urandom' | head -c '2')]}; AppleWebKit/$(tr -dc '1-9' < '/dev/urandom' | head -c '3').$(tr -dc '1-9' < '/dev/urandom' | head -c '2') (KHTML, like Gecko) Chrome/$(tr -dc '1-9' < '/dev/urandom' | head -c '2').0.$(tr -dc '1-9' < '/dev/urandom' | head -c '4').$(tr -dc '1-9' < '/dev/urandom' | head -c '2') Mobile Safari/$(tr -dc '1-9' < '/dev/urandom' | head -c '3').$(tr -dc '1-9' < '/dev/urandom' | head -c '2') OPR/$(tr -dc '1-9' < '/dev/urandom' | head -c '2').0.$(tr -dc '1-9' < '/dev/urandom' | head -c '4').$(tr -dc '1-9' < '/dev/urandom' | head -c '2')"
	else
		# If for some reason the "SystemSelection" variable returns an invalid value, set a predefined user agent (Opera on Linux)
		UserAgent='Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/79.0.3945.88 Safari/537.36 OPR/65.0.3467.72'
	fi

}

# Template http://whatismybrowser.com/guides/the-latest-user-agent/vivaldi
GenerateVivaldi(){

	# Generate a random number between 0 and 3 (pick a operating system)
	SystemSelection=$(tr -dc '0-3' < '/dev/urandom' | head -c '1')

	# Vivaldi on Windows
	if [ "$SystemSelection" = '0' ]; then
		UserAgent="Mozilla/5.0 (Windows ${WindowsVersions[$(shuf -i 0-25 --random-source '/dev/urandom' | head -c '2')]}; WOW${SystemArchitectures[$(tr -dc 0-1 < '/dev/urandom' | head -c '1')]}) AppleWebKit/$(tr -dc '1-9' < '/dev/urandom' | head -c '3').$(tr -dc '1-9' < '/dev/urandom' | head -c '2') (KHTML, like Gecko) Chrome/$(tr -dc '1-9' < '/dev/urandom' | head -c '2').0.$(tr -dc '1-9' < '/dev/urandom' | head -c '4').$(tr -dc '1-9' < '/dev/urandom' | head -c '2') Safari/$(tr -dc '1-9' < '/dev/urandom' | head -c '3').$(tr -dc '1-9' < '/dev/urandom' | head -c '2') Vivaldi/$(tr -dc '1-9' < '/dev/urandom' | head -c '1').$(tr -dc '0-9' < '/dev/urandom' | head -c '1')"
	# Vivaldi on macOS
	elif [ "$SystemSelection" = '1' ]; then
		UserAgent="Mozilla/5.0 (Macintosh; Intel Mac OS X ${macOS_Versions[$(shuf -i 0-17 --random-source '/dev/urandom' | head -c '2')]}) AppleWebKit/$(tr -dc '1-9' < '/dev/urandom' | head -c '3').$(tr -dc '1-9' < '/dev/urandom' | head -c '2') (KHTML, like Gecko) Chrome/$(tr -dc '1-9' < '/dev/urandom' | head -c '2').0.$(tr -dc '1-9' < '/dev/urandom' | head -c '4').$(tr -dc '1-9' < '/dev/urandom' | head -c '2') Safari/$(tr -dc '1-9' < '/dev/urandom' | head -c '3').$(tr -dc '1-9' < '/dev/urandom' | head -c '2') Safari/$(tr -dc '1-9' < '/dev/urandom' | head -c '3').$(tr -dc '1-9' < '/dev/urandom' | head -c '2') Vivaldi/$(tr -dc '1-9' < '/dev/urandom' | head -c '1').$(tr -dc '0-9' < '/dev/urandom' | head -c '1')"
	# Vivaldi on Linux
	elif [ "$SystemSelection" = '2' ]; then
		UserAgent="Mozilla/5.0 (X11; Linux x86_${SystemArchitectures[$(tr -dc 0-1 < '/dev/urandom' | head -c '1')]}) AppleWebKit/$(tr -dc '1-9' < '/dev/urandom' | head -c '3').$(tr -dc '1-9' < '/dev/urandom' | head -c '2') (KHTML, like Gecko) Chrome/$(tr -dc '1-9' < '/dev/urandom' | head -c '2').0.$(tr -dc '1-9' < '/dev/urandom' | head -c '4').$(tr -dc '1-9' < '/dev/urandom' | head -c '2') Safari/$(tr -dc '1-9' < '/dev/urandom' | head -c '3').$(tr -dc '1-9' < '/dev/urandom' | head -c '2') Vivaldi/$(tr -dc '1-9' < '/dev/urandom' | head -c '1').$(tr -dc '0-9' < '/dev/urandom' | head -c '1')"
	# Vivaldi on Android (This template was manually picked up by me from Vivaldi Beta for Android)
	elif [ "$SystemSelection" = '3' ]; then
		UserAgent="Mozilla/5.0 (Linux; Android ${AndroidVersions[$(shuf -i 0-44 --random-source '/dev/urandom' | head -c '2')]}) AppleWebKit/$(tr -dc '1-9' < '/dev/urandom' | head -c '3').$(tr -dc '1-9' < '/dev/urandom' | head -c '2') (KHTML, like Gecko) Chrome/$(tr -dc '1-9' < '/dev/urandom' | head -c '2').0.$(tr -dc '1-9' < '/dev/urandom' | head -c '4').$(tr -dc '1-9' < '/dev/urandom' | head -c '2') Safari/$(tr -dc '1-9' < '/dev/urandom' | head -c '3').$(tr -dc '1-9' < '/dev/urandom' | head -c '2') Mobile Safari/$(tr -dc '1-9' < '/dev/urandom' | head -c '3').$(tr -dc '1-9' < '/dev/urandom' | head -c '2') Vivaldi/$(tr -dc '1-9' < '/dev/urandom' | head -c '1').$(tr -dc '0-9' < '/dev/urandom' | head -c '1').$(tr -dc '0-9' < '/dev/urandom' | head -c '4').$(tr -dc '0-9' < '/dev/urandom' | head -c '2')"
	else
		# If for some reason the "SystemSelection" variable returns an invalid value, set a predefined user agent (Vivaldi on Linux)
		UserAgent='Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/79.0.3945.88 Safari/537.36 Vivaldi/2.9'
	fi

}

# Template http://whatismybrowser.com/guides/the-latest-user-agent/yandex
GenerateYandex(){

	# Generate a random number between 0 to 1 and between 3 to 4 (pick a operating system)
	SystemSelection=$(tr -dc '0-13-4' < '/dev/urandom' | head -c '1')

	# Yandex on Windows
	if [ "$SystemSelection" = '0' ]; then
		UserAgent="Mozilla/5.0 (Windows ${WindowsVersions[$(shuf -i 0-25 --random-source '/dev/urandom' | head -c '2')]}) AppleWebKit/$(tr -dc '1-9' < '/dev/urandom' | head -c '3').$(tr -dc '1-9' < '/dev/urandom' | head -c '2') (KHTML, like Gecko) Chrome/$(tr -dc '1-9' < '/dev/urandom' | head -c '2').0.$(tr -dc '1-9' < '/dev/urandom' | head -c '4').$(tr -dc '1-9' < '/dev/urandom' | head -c '2') YaBrowser/$(tr -dc '1-9' < '/dev/urandom' | head -c '2').$(tr -dc '0-9' < '/dev/urandom' | head -c '1').$(tr -dc '0-9' < '/dev/urandom' | head -c '1').$(tr -dc '0-9' < '/dev/urandom' | head -c '3') Yowser/$(tr -dc '1-9' < '/dev/urandom' | head -c '1').$(tr -dc '0-9' < '/dev/urandom' | head -c '1') Safari/$(tr -dc '1-9' < '/dev/urandom' | head -c '3').$(tr -dc '1-9' < '/dev/urandom' | head -c '2')"
	# Yandex on macOS
	elif [ "$SystemSelection" = '1' ]; then
		UserAgent="Mozilla/5.0 (Macintosh; Intel Mac OS X ${macOS_Versions[$(shuf -i 0-17 --random-source '/dev/urandom' | head -c '2')]}) AppleWebKit/$(tr -dc '1-9' < '/dev/urandom' | head -c '3').$(tr -dc '1-9' < '/dev/urandom' | head -c '2') (KHTML, like Gecko) Chrome/$(tr -dc '1-9' < '/dev/urandom' | head -c '2').0.$(tr -dc '1-9' < '/dev/urandom' | head -c '4').$(tr -dc '1-9' < '/dev/urandom' | head -c '2') YaBrowser/$(tr -dc '1-9' < '/dev/urandom' | head -c '2').$(tr -dc '0-9' < '/dev/urandom' | head -c '1').$(tr -dc '0-9' < '/dev/urandom' | head -c '1').$(tr -dc '1-9' < '/dev/urandom' | head -c '4') Yowser/$(tr -dc '1-9' < '/dev/urandom' | head -c '1').$(tr -dc '0-9' < '/dev/urandom' | head -c '1') Safari/$(tr -dc '1-9' < '/dev/urandom' | head -c '3').$(tr -dc '1-9' < '/dev/urandom' | head -c '2')"
	# Yandex on Android
	elif [ "$SystemSelection" = '3' ]; then
		UserAgent="Mozilla/5.0 (Linux; Android ${AndroidVersions[$(shuf -i 0-44 --random-source '/dev/urandom' | head -c '2')]}) AppleWebKit/$(tr -dc '1-9' < '/dev/urandom' | head -c '3').$(tr -dc '1-9' < '/dev/urandom' | head -c '2') (KHTML, like Gecko) Chrome/$(tr -dc '1-9' < '/dev/urandom' | head -c '2').0.$(tr -dc '1-9' < '/dev/urandom' | head -c '4').$(tr -dc '1-9' < '/dev/urandom' | head -c '2') YaBrowser/$(tr -dc '1-9' < '/dev/urandom' | head -c '2').$(tr -dc '1-9' < '/dev/urandom' | head -c '2').$(tr -dc '0-9' < '/dev/urandom' | head -c '1').$(tr -dc '1-9' < '/dev/urandom' | head -c '3') Safari/$(tr -dc '1-9' < '/dev/urandom' | head -c '3').$(tr -dc '1-9' < '/dev/urandom' | head -c '2')"
	# Yandex on iOS
	elif [ "$SystemSelection" = '4' ]; then
		UserAgent="Mozilla/5.0 (iPhone; CPU iPhone OS ${iOSVersions[$(shuf -i 0-10 --random-source '/dev/urandom' | head -c '2')]} like Mac OS X) AppleWebKit/$(tr -dc '1-9' < '/dev/urandom' | head -c '3').$(tr -dc '0-9' < '/dev/urandom' | head -c '1').$(tr -dc '1-9' < '/dev/urandom' | head -c '2') (KHTML, like Gecko) Version/$(tr -dc '1-9' < '/dev/urandom' | head -c '2').$(tr -dc '0-9' < '/dev/urandom' | head -c '1') YaBrowser/$(tr -dc '1-9' < '/dev/urandom' | head -c '2').$(tr -dc '1-9' < '/dev/urandom' | head -c '2').$(tr -dc '0-9' < '/dev/urandom' | head -c '1').$(tr -dc '1-9' < '/dev/urandom' | head -c '3') Mobile/$(tr -dc A-Z1-9 < '/dev/urandom' | head -c '5') Safari/$(tr -dc '1-9' < '/dev/urandom' | head -c '3').$(tr -dc '1-9' < '/dev/urandom' | head -c '2')"
	else
		# If for some reason the "SystemSelection" variable returns an invalid value, set a predefined user agent (Yandex on macOS)
		UserAgent='Mozilla/5.0 (Macintosh; Intel Mac OS X 10_14_1) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/79.0.3945.88 YaBrowser/19.6.0.1583 Yowser/2.5 Safari/537.36'
	fi

}

GenerateGeneric(){

	# Generate a random number between 0 and 8
	Selection=$(tr -dc '0-8' < '/dev/urandom' | head -c '1')

	# Generic browser on Android
	if [ "$Selection" = '0' ]; then
		UserAgent="Dalvik/$(tr -dc '1-9' < '/dev/urandom' | head -c '1').$(tr -dc '0-9' < '/dev/urandom' | head -c '1').$(tr -dc '0-9' < '/dev/urandom' | head -c '1') (Linux; U; Android ${AndroidVersions[$(shuf -i 0-44 --random-source '/dev/urandom' | head -c '2')]})"
	# OkHttp on generic system
	elif [ "$Selection" = '1' ]; then
		UserAgent="okhttp/$(tr -dc '1-9' < '/dev/urandom' | head -c '1').$(tr -dc '0-9' < '/dev/urandom' | head -c '2').$(tr -dc '0-9' < '/dev/urandom' | head -c '1')"
	# Generic WebView on Android
	elif [ "$Selection" = '2' ]; then
		UserAgent="(Linux; U; Android ${AndroidVersions[$(shuf -i 0-44 --random-source '/dev/urandom' | head -c '2')]}; Cronet/$(tr -dc '1-9' < '/dev/urandom' | head -c '2').0.$(tr -dc '1-9' < '/dev/urandom' | head -c '4').$(tr -dc '1-9' < '/dev/urandom' | head -c '2'))"
	# UptimeRobot on generic system (bot)
	elif [ "$Selection" = '3' ]; then
		UserAgent="Mozilla/$(tr -dc '4-5' < '/dev/urandom' | head -c '1').0+(compatible; UptimeRobot/$(tr -dc '1-9' < '/dev/urandom' | head -c '1').$(tr -dc '0-9' < '/dev/urandom' | head -c '1'); http://www.uptimerobot.com/)"
	# Zgrab on generic system
	elif [ "$Selection" = '4' ]; then
		UserAgent="Mozilla/$(tr -dc '4-5' < '/dev/urandom' | head -c '1').0 zgrab/0.x"
	# Telegram RSS (bot)
	elif [ "$Selection" = '5' ]; then
		UserAgent="Mozilla/$(tr -dc '4-5' < '/dev/urandom' | head -c '1').0 (compatible; rss2tg bot; +http://komar.in/en/rss2tg_crawler)"
	 # WordPress on generic system
	elif [ "$Selection" = '6' ]; then
		UserAgent="WordPress/$(tr -dc '1-9' < '/dev/urandom' | head -c '1').$(tr -dc '0-9' < '/dev/urandom' | head -c '1').$(tr -dc '0-9' < '/dev/urandom' | head -c '1')"
	# Googlebot on Android
	elif [ "$Selection" = '7' ]; then
		UserAgent="Mozilla/5.0 (Linux; Android ${AndroidVersions[$(shuf -i 0-44 --random-source '/dev/urandom' | head -c '2')]}) AppleWebKit/$(tr -dc '1-9' < '/dev/urandom' | head -c '3').$(tr -dc '1-9' < '/dev/urandom' | head -c '2') (KHTML, like Gecko) Chrome/$(tr -dc '1-9' < '/dev/urandom' | head -c '2').0.$(tr -dc '1-9' < '/dev/urandom' | head -c '4').$(tr -dc '1-9' < '/dev/urandom' | head -c '2') Mobile Safari/$(tr -dc '1-9' < '/dev/urandom' | head -c '3').$(tr -dc '1-9' < '/dev/urandom' | head -c '2') (compatible; Googlebot/$(tr -dc '1-9' < '/dev/urandom' | head -c '1').$(tr -dc '0-9' < '/dev/urandom' | head -c '1'); +http://www.google.com/bot.html)"
	# Nimbostratus-Bot
	elif [ "$Selection" = '8' ]; then
		UserAgent="Mozilla/5.0 (compatible; Nimbostratus-Bot/v$(tr -dc '1-9' < '/dev/urandom' | head -c '1').$(tr -dc '0-9' < '/dev/urandom' | head -c '1').$(tr -dc '0-9' < '/dev/urandom' | head -c '1'); http://cloudsystemnetworks.com)"
	else
		# If for some reason the "Selection" variable returns an invalid value, set a predefined user agent (Generic browser on generic system)
		UserAgent='Generic/1.0.0'
	fi

}

# Try to solve character parsing/decoding issues
SolveURLIssues(){

	if [ "$1" = '--fix-wrong-decoding' ]; then
		# Decide whether or not the "+" (plus sign) character should be considered a blank space 
		if [[ "$URL" =~ .*\?.*\+.* ]]; then
			OriginalString=$(echo "$URL" | grep -Eo '\?.*[^?]' | sed 's/\//\\\//g')
			[ "$BatchMode" != 'true' ] && ModifiedString=${OriginalString//+/ } || { ModifiedString=${OriginalString//+/%20}; }
			URL=${URL//$OriginalString/$ModifiedString}
		fi
	elif [ "$1" = '--escape-character' ]; then
		# Fix twitter search
		if [[ "$URL" =~ .*twitter\.com(/|%2(f|F))search(\?|%3(f|F))q(\=|%3(d|D)).* ]]; then
			[ "$BatchMode" != 'true' ] && URL=${URL//%23/%2523} || { URL=${URL//#/%23}; }
		fi
	else
		# Fix twitter search
		[[ "$URL" =~ .*twitter\.com/search\?q\=.* ]] && URL=${URL//#/%23}
		return '0'
	fi

}

# This function is used to send an "action" to the chat of the user who sent a link. This status will be sent while Unalix is processing a link
ChatAction(){

	# This is a loop. The action will be sent when the [-f "$MessageSent" ] command returns a positive value (0)
	if [ "$1" = '--start-broadcast' ]; then
		MessageSent="$HOME/Unalix/TempFiles/MessageSent-$(tr -dc '[:alnum:]' < '/dev/urandom' | head -c 10).txt" && touch "$MessageSent"
		if [ "$2" = '--typing' ]; then
			while [ -f "$MessageSent" ]
			do
				sendChatAction --chat_id "$message_chat_id" --action 'typing' 1 > '/dev/null' 2 > '/dev/null'
			done &
		elif [ "$2" = '--sending-document' ]; then
			while [ -f "$MessageSent" ]
			do
				sendChatAction --chat_id "$message_chat_id" --action 'upload_document' 1 > '/dev/null' 2 > '/dev/null'
			done &
		else
			echo -e '\033[0;31mInvalid function call received!\033[0m'; return '1'
		fi
	# The loop will be broken when the $MessageSent file is deleted.
	elif [ "$1" = '--stop-broadcast' ]; then
		rm -f "$MessageSent"
	else
		echo -e '\033[0;31mInvalid function call received!\033[0m'; return '1'
	fi

}

# Process links sent by users
ProcessLinks(){

	if [ "$GetFromURL" = 'true' ]; then
		echo -e "$message_text" | ParseText > "$GetFromURLsFilename"
		for Links in $(cat "$GetFromURLsFilename")
		do
			GetLinksContent | ParseText >> "$LinksFilename"
		done
		[[ $(wc -c < "$LinksFilename") = '0' ]] && SendErrorMessage && cleanup
	elif [ "$GetFromFile" = 'true' ]; then
		if [ "$message_document_file_size" -gt '20000000' ]; then
			sendMessage --reply_to_message_id "$message_message_id" --chat_id "$message_chat_id" --text 'This file exceeds the maximum limit of 20 MB. Try sending a smaller file.' || { SendErrorMessage; }; cleanup
		else
			DownloadFilePath=$(getFile --file_id "$message_document_file_id" | grep -Eo 'documents/.+')
			DownloadFile | ParseText > "$LinksFilename" || { SendErrorMessage; }
		fi
	else
		echo -e "$message_text" | ParseText > "$LinksFilename"
	fi

	if [[ $(wc -l < "$LinksFilename") -gt '1' ]]; then

		ChatAction --start-broadcast --sending-document && BatchMode='true' && mv "$LinksFilename" "$OriginalLinksFilename" || { SendErrorMessage; }

		for Domain in $(GetHostname < "$OriginalLinksFilename")
		do
			GetPunycode --from-file
		done

		if [ "$Simultaneously" != 'true' ]; then
			for URL in $(cat "$OriginalLinksFilename"); do
				echo "$URL (*)" >> "$EndResults"
				ParseTrackingParameters && GetEndResults
			done
		else
			SimultaneouslyRequestsDirectory="$HOME/Unalix/TempFiles/SimultaneouslyRequestsDirectory-$(tr -dc '[:alnum:]' < '/dev/urandom' | head -c 10)"
			mkdir -m '700' -p "$SimultaneouslyRequestsDirectory"
			for URL in $(cat "$OriginalLinksFilename"); do
				SetFilenameVariables --simultaneously
				touch "$RequestRunning" && echo "$URL (*)" >> "$SimultaneouslyEndResult"
				{
					ParseTrackingParameters && GetEndResults
				} &
			done
			set +f 
			while [[ $(ls $SimultaneouslyRequestsDirectory/RequestRunning-* 2>/dev/null | wc -c) -gt '0' ]]
			do
				true
			done
			EndResults="$SimultaneouslyRequestsDirectory/AllResults-$(tr -dc '[:alnum:]' < '/dev/urandom' | head -c 10).txt"
			cat "$SimultaneouslyRequestsDirectory"/EndResult-* > "$EndResults"
			set -f
		fi

		head -c '50000000' < "$EndResults" > "$CleanedURLs"
		ChatAction --stop-broadcast && sendDocument --reply_to_message_id "$message_message_id" --chat_id "$message_chat_id" --document "@$CleanedURLs" || { SendErrorMessage; }; cleanup

	else
		URL=$(ParseText < "$LinksFilename" | head -n '1')
		rm -f "$OriginalLinksFilename" "$LinksFilename"
			
		ChatAction --start-broadcast --typing
	
		Domain=$(echo "$URL" | GetHostname)
		GetPunycode --from-variable
	
		ParseTrackingParameters && GetEndResults || { SendErrorMessage; }; cleanup

	fi

	cleanup

}


# This function is used to send an error message to the user when an operation returns a negative value.
SendErrorMessage(){

	ChatAction --stop-broadcast; sendMessage --reply_to_message_id "$message_message_id" --chat_id "$message_chat_id" --text 'An error occurred while trying to process your request.'; cleanup

}

# This function is used to download txt files
DownloadFile(){

	timeout -s '9' "$ConnectionTimeout" curl -LNkZB --raw --no-progress-meter --no-sessionid --ssl-no-revoke --no-keepalive $NetworkProtocol $Socks5 $CACertOptions $DoHOptions -H 'Accept:' --request 'GET' --user-agent "$UserAgent" --url "https://api.telegram.org:443/file/bot$BotToken/$DownloadFilePath"
	
}

# This function is used to obtain the contents of the URLs sent using the command "/getfromurl"
GetLinksContent(){

	timeout -s '9' "$ConnectionTimeout" curl -LNkZB --raw --no-progress-meter --no-sessionid --ssl-no-revoke --no-keepalive $NetworkProtocol $Socks5 $CACertOptions $DoHOptions -H 'Accept:' --request 'GET' --user-agent "$UserAgent" --url "$Links" | head -c '5242880'

}

# This function is used to decode messages sent by users (e.g: from "N%c3%a3o" to "Não").
# Code taken from: https://gist.github.com/cdown/1163649
DecodeText(){

	printf '%b' "${*//%/\\x}"

}

# This function is used to encode messages sent by users (e.g: from "Não" to "N%c3%a3o").
# Code taken from: https://gist.github.com/cdown/1163649#gistcomment-1256298
EncodeText(){

	local BytesCount="${#1}"
	for (( i = 0; i < BytesCount; i++ )); do
		local URL="${1:i:1}"
		case "$URL" in
			[a-zA-Z0-9.~_-])
				printf "$URL";;
			*)
				printf "$URL" | xxd -p -c '1' | while read -r 'Result'; do printf "%%%s" "$Result"; done;;
		esac
	done

}

# This function is used to process the text of messages, txt files and web pages (obtain valid values).
ParseText(){

	xmlstarlet -q 'unesc' | sed -r 's/(\s|\t|"|\(|\)|<|>|,|'\'')+/\n/g; s/(H|h)(T|t)(T|t)(P|p)(S|s)?(:\/\/|%3A%2F%2F|%3a%2f%2f)/http\6/g' | grep -Eo "\bhttps?(://|%3A%2F%2F|%3a%2f%2f)[^\ $(printf '\n')$(printf '\t')\"(')<>,]+" | sed -r '/.{1,}\..{2,}(:[0-9]{1,5})?(\/|%2F|\?|#)?/!d' | awk 'NF && !seen[$0]++'

}

# This function is used to obtain the hostname of links
GetHostname(){

	if [ "$1" = '--keep-port-number' ]; then
		sed -r 's/^.*:\/\/|\/.*//g' | tr '[:upper:]' '[:lower:]'
	else
		sed -r 's/^.*:\/\/|\/.*//g; s/:[0-9]{1,5}.*//g' | tr '[:upper:]' '[:lower:]'
	fi

}

# This function is used to encode non-UTF-8 texts sent from the "/encodetext" command.
BotCommand_encodetext(){

	# Send basic command usage information
	if [ "$1" = '--send-usage' ]; then
		sendMessage --reply_to_message_id "$message_message_id" --chat_id "$message_chat_id" --text '*Usage:*\n\n`/encodetext <string_or_text_here>`\nor\n`!encodetext <string_or_text_here>`\n\n*Example:*\n\n`/encodetext %e3%81%86%e3%81%a1%e3%81%ae%e5%a8%98%e3%81%ae%e7%82%ba%e3%81%aa%e3%82%89%e3%81%b0%e3%80%81%e4%bf%ba%e3%81%af%e3%82%82%e3%81%97%e3%81%8b%e3%81%97%e3%81%9f%e3%82%89%e9%ad%94%e7%8e%8b%e3%82%82%e5%80%92%e3%81%9b%e3%82%8b%e3%81%8b%e3%82%82%e3%81%97%e3%82%8c%e3%81%aa%e3%81%84%e3%80%82`\nor\n`!encodetext %e3%81%86%e3%81%a1%e3%81%ae%e5%a8%98%e3%81%ae%e7%82%ba%e3%81%aa%e3%82%89%e3%81%b0%e3%80%81%e4%bf%ba%e3%81%af%e3%82%82%e3%81%97%e3%81%8b%e3%81%97%e3%81%9f%e3%82%89%e9%ad%94%e7%8e%8b%e3%82%82%e5%80%92%e3%81%9b%e3%82%8b%e3%81%8b%e3%82%82%e3%81%97%e3%82%8c%e3%81%aa%e3%81%84%e3%80%82`\n\n*Description:*\n\nThis command allows the user to convert non-UTF-8 characters to valid UTF-8 format.' --parse_mode 'markdown' || { SendErrorMessage; }; exit
	# Encode text
	elif [ "$1" = '--encode-text' ]; then
		DecodedText=$(echo -e "$message_text" | sed -r 's/^(\!|\/)(e|E)(n|N)(c|C)(o|O)(d|D)(e|E)(t|T)(e|E)(x|X)(t|T)\s*//g' )
		sendMessage --reply_to_message_id "$message_message_id" --chat_id "$message_chat_id" --text "\`$(EncodeText "$DecodedText" | sed 's/%/%25/g' | head -c '4096')\`" --parse_mode 'markdown' || { SendErrorMessage; }; exit
	else
		echo -e '\033[0;31mInvalid function call received!\033[0m'; return '1'
	fi
	
}

# This function is used to decode UTF-8 texts sent from the "/decodetext" command.
BotCommand_decodetext(){

	# Send basic command usage information
	if [ "$1" = '--send-usage' ]; then
		sendMessage --reply_to_message_id "$message_message_id" --chat_id "$message_chat_id" --text '*Usage:*\n\n`/decodetext <string_or_text_here>`\nor\n`!decodetext <string_or_text_here>`\n\n*Example:*\n\n`/decodetext %25c3%25a3%25c4%2581%25c3%25a5%25c3%25a4`\nor\n`!decodetext %25c3%25a3%25c4%2581%25c3%25a5%25c3%25a4`\n\n*Description:*\n\nThis command allows the user to convert UTF-8 characters to human-readable text.' --parse_mode 'markdown' || { SendErrorMessage; }; exit
	# Decode text
	elif [ "$1" = '--decode-text' ]; then
		EndResults="$HOME/Unalix/TempFiles/EndResults-$(tr -dc '[:alnum:]' < '/dev/urandom' | head -c 10).txt"
		message_text=$(echo "$message_text" | sed -r 's/^(\!|\/)(d|D)(e|E)(c|C)(o|O)(d|D)(e|E)(t|T)(e|E)(x|X)(t|T)\s*//g')
		DecodeText "$message_text" > "$EndResults"
		sendDocument --reply_to_message_id "$message_message_id" --chat_id "$message_chat_id" --document "@$EndResults" || { SendErrorMessage; }; exit "$?"
	else
		echo -e '\033[0;31mInvalid function call received!\033[0m'; return '1'
	fi

}

# Check if the query sent by the user is valid
CheckUserQuery(){

	if echo "$UserQuery" | grep -Eq '\.onion$'; then
		sendMessage --reply_to_message_id "$message_message_id" --chat_id "$message_chat_id" --text 'Tor/Onion-related domains cannot be resolved.' || { SendErrorMessage; }; cleanup
	elif echo "$UserQuery" | grep -Eq '\.i2p$'; then
		sendMessage --reply_to_message_id "$message_message_id" --chat_id "$message_chat_id" --text 'Domains related to the I2P network cannot be resolved.' || { SendErrorMessage; }; cleanup
	elif echo "$UserQuery" | grep -Pq '[0-9a-zA-Z\.-]+\.[a-zA-Z\.]{2,6}'; then
		GetPunycode --from-user-query && ChatAction --start-broadcast --typing && MakeDNSTest && ResolveQuery && QueryIP
	elif echo "$UserQuery" | grep -Pq '((?:[a-f0-9]{1,4}:){6}(?::[a-f0-9]{1,4})|(?:[a-f0-9]{1,4}:){5}(?::[a-f0-9]{1,4}){1,2}|(?:[a-f0-9]{1,4}:){4}(?::[a-f0-9]{1,4}){1,3}|(?:[a-f0-9]{1,4}:){3}(?::[a-f0-9]{1,4}){1,4}|(?:[a-f0-9]{1,4}:){2}(?::[a-f0-9]{1,4}){1,5}|(?:[a-f0-9]{1,4}:)(?::[a-f0-9]{1,4}){1,6}|(?:[a-f0-9]{1,4}:){1,6}:|:(?::[a-f0-9]{1,4}){1,6}|[a-f0-9]{0,4}::|(?:[a-f0-9]{1,4}:){7}[a-f0-9]{1,4}|[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3})'; then
		ChatAction --start-broadcast --typing && IPAddress="$UserQuery" && QueryIP
	else
		sendMessage --reply_to_message_id "$message_message_id" --chat_id "$message_chat_id" --text 'Your query is invalid.' || { SendErrorMessage; }; cleanup
	fi

}

# This function is used to verify that DNS resolvers are operational
MakeDNSTest(){

	# These are the DNS servers that can be used to resolve domains sent using the "/ip" command.
	# Cloudflare DNS (Anycast) | http://1.1.1.1
	if CheckIfReachable 'https://1.1.1.1:443/dns-query?name=gnu.org' --dns; then
		DNSResolver='https://1.1.1.1:443/dns-query?name='
	# Cloudflare DNS (Anycast) | http://1.0.0.1
	elif CheckIfReachable 'https://1.0.0.1:443/dns-query?name=gnu.org' --dns; then
		DNSResolver='https://1.0.0.1:443/dns-query?name=',
	# Uncensored DNS (Netherlands) | http://securedns.eu
	elif CheckIfReachable 'https://doh.securedns.eu:443/dns-query?name=gnu.org' --dns; then
		DNSResolver='https://doh.securedns.eu:443/dns-query?name='
	# Uncensored DNS (Finland) | http://snopyta.org/service/dns
	elif CheckIfReachable 'https://fi.doh.dns.snopyta.org:443/dns-query?name=gnu.org' --dns; then
		DNSResolver='https://fi.doh.dns.snopyta.org:443/dns-query?name='
	# Google DNS | http://developers.google.com/speed/public-dns (privacy-unfriendly)
	elif CheckIfReachable 'https://dns.google:443/resolve?name=gnu.org' --dns; then
		DNSResolver='https://dns.google:443/resolve?name='
	else
		sendMessage --reply_to_message_id "$message_message_id" --chat_id "$message_chat_id" --text 'No DNS server can process your request at this time.' || { SendErrorMessage; }; cleanup
	fi

}

# This function is used to check if the response sent by the server is positive
CheckIfReachable(){

	if [ "$2" = '--dns' ]; then
		timeout -s '9' "$ConnectionTimeout" curl --silent -LNkBf -H 'accept: application/dns-json' --no-progress-meter --head --no-sessionid --ssl-no-revoke --no-keepalive $NetworkProtocol $Socks5 $CACertOptions $DoHOptions -H 'Accept:' --request 'GET' --user-agent "$UserAgent" --url "$1" -o '/dev/null' && echo -e "\033[0;32m\"$(echo $1 | GetHostname)\" is reachable!\033[0m" || { echo -e "\033[0;31m\"$(echo $1 | GetHostname)\" is unreachable!\033[0m"; return '1'; }
	else
		timeout -s '9' "$ConnectionTimeout" curl --silent -LNkBf --head --raw --no-progress-meter --no-sessionid --ssl-no-revoke --no-keepalive $NetworkProtocol $Socks5 $CACertOptions $DoHOptions -H 'Accept:' --request 'GET' --user-agent "$UserAgent" --url "$1" -o '/dev/null' && echo -e "\033[0;32m\"$(echo $1 | GetHostname)\" is reachable!\033[0m" || { echo -e "\033[0;31m\"$(echo $1 | GetHostname)\" is unreachable!\033[0m"; return '1'; }
	fi

}

# This function is used to make requests to DNS resolvers and also for IP address lookup APIs
MakeRequest(){

	if [ "$2" = '--resolve' ]; then
		timeout -s '9' "$ConnectionTimeout" curl -LNkBf -H 'accept: application/dns-json' --no-progress-meter --no-sessionid --ssl-no-revoke --no-keepalive $NetworkProtocol $Socks5 $CACertOptions $DoHOptions --request 'GET' --user-agent "$UserAgent" --url "$DNSResolver$1&do=false&cd=false" -o "$DNSAnswerFilename"
	else
		timeout -s '9' "$ConnectionTimeout" curl -LNkBf --no-progress-meter --no-sessionid --ssl-no-revoke --no-keepalive $NetworkProtocol $Socks5 $CACertOptions $DoHOptions -H 'Accept:' --request 'GET' --user-agent "$UserAgent" --url "$API" -o "$IPAddressFilename"
	fi

}

# This function will resolve domain names using the DNS resolver selected by the "MakeDNSTest" function
ResolveQuery(){

	# IPv4
	if MakeRequest "$UserQuery&type=A" --resolve && IsPv4; then
		IsPv4 --set-variable || { SendErrorMessage; }
	# IPv6
	elif MakeRequest "$UserQuery&type=AAAA" --resolve && IsPv6; then
		IsPv6 --set-variable || { SendErrorMessage; }
	else
		sendMessage --reply_to_message_id "$message_message_id" --chat_id "$message_chat_id" --text 'An error occurred while trying to resolve the domain name.' || { SendErrorMessage; }; cleanup
	fi

	echo "$IPAddress"

}

# This function is used to verify that the IP address returned by the DNS resolver is a valid IPv4 address.
IsPv4(){

	if [ "$1" != '--set-variable' ]; then
		sed -r 's/edns_client_subnet.*//g' < "$DNSAnswerFilename" | grep -Pq '\b((25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b'
	else
		IPAddress=$(sed -r 's/edns_client_subnet.*//g' < "$DNSAnswerFilename" | grep -Po '\b((25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b' | head -n '1')
	fi

}

# This function is used to verify that the IP address returned by the DNS resolver is a valid IPv6 address.
IsPv6(){

	if [ "$1" != '--set-variable' ]; then
		sed -r 's/edns_client_subnet.*//g' < "$DNSAnswerFilename" | grep -Pq '(?:[a-f0-9]{1,4}:){6}(?::[a-f0-9]{1,4})|(?:[a-f0-9]{1,4}:){5}(?::[a-f0-9]{1,4}){1,2}|(?:[a-f0-9]{1,4}:){4}(?::[a-f0-9]{1,4}){1,3}|(?:[a-f0-9]{1,4}:){3}(?::[a-f0-9]{1,4}){1,4}|(?:[a-f0-9]{1,4}:){2}(?::[a-f0-9]{1,4}){1,5}|(?:[a-f0-9]{1,4}:)(?::[a-f0-9]{1,4}){1,6}|(?:[a-f0-9]{1,4}:){1,6}:|:(?::[a-f0-9]{1,4}){1,6}|[a-f0-9]{0,4}::|(?:[a-f0-9]{1,4}:){7}[a-f0-9]{1,4}'
	else
		IPAddress=$(sed -r 's/edns_client_subnet.*//g' < "$DNSAnswerFilename" | grep -Po '(?:[a-f0-9]{1,4}:){6}(?::[a-f0-9]{1,4})|(?:[a-f0-9]{1,4}:){5}(?::[a-f0-9]{1,4}){1,2}|(?:[a-f0-9]{1,4}:){4}(?::[a-f0-9]{1,4}){1,3}|(?:[a-f0-9]{1,4}:){3}(?::[a-f0-9]{1,4}){1,4}|(?:[a-f0-9]{1,4}:){2}(?::[a-f0-9]{1,4}){1,5}|(?:[a-f0-9]{1,4}:)(?::[a-f0-9]{1,4}){1,6}|(?:[a-f0-9]{1,4}:){1,6}:|:(?::[a-f0-9]{1,4}){1,6}|[a-f0-9]{0,4}::|(?:[a-f0-9]{1,4}:){7}[a-f0-9]{1,4}' | head -n '1')
	fi

}


# This function will query information about IP addresses and then send it to the user using the Telegram API
QueryIP(){

	if CheckIfReachable 'https://ipapi.co:443/json'; then
		API="https://ipapi.co:443/$IPAddress/json" && APIName='ipapi.co'
	elif CheckIfReachable 'http://ip-api.com:80/json'; then
		API="http://ip-api.com:80/json/$IPAddress" && APIName='ip-api.com'
	else
		sendMessage --reply_to_message_id "$message_message_id" --chat_id "$message_chat_id" --text 'No API can process your request at this time.' || { SendErrorMessage; }; cleanup
	fi

	if MakeRequest; then
		ChatAction --stop-broadcast
		if [ "$APIName" = 'ipapi.co' ]; then
			sendMessage --reply_to_message_id "$message_message_id" --chat_id "$message_chat_id" --text "*Query*: \`$(jq -r '.ip' < "$IPAddressFilename")\`\n*Owner*: \`$(jq -r '.asn' < "$IPAddressFilename")\` - \`$(jq -r '.org' < "$IPAddressFilename")\`\n*City*: \`$(jq -r '.city' < "$IPAddressFilename")\`\n*Region/State*: \`$(jq -r '.region' < "$IPAddressFilename")\`\n*Country*: \`$(jq -r '.country_name' < "$IPAddressFilename")\`\n*Latitude*: \`$(jq -r '.latitude' < "$IPAddressFilename")\`\n*Longitude*: \`$(jq -r '.longitude' < "$IPAddressFilename")\`\n*Postal Code*: \`$(jq -r '.postal' < "$IPAddressFilename")\`\n*Timezone*: \`$(jq -r '.timezone' < "$IPAddressFilename")\`" --parse_mode 'markdown' || { SendErrorMessage; }; cleanup
		elif [ "$APIName" = 'ip-api.com' ]; then
			sendMessage --reply_to_message_id "$message_message_id" --chat_id "$message_chat_id" --text "*Query*: \`$(jq -r '.query' < "$IPAddressFilename")\`\n*Owner*: \`$(jq -r '.as' < "$IPAddressFilename")\`\n*City*: \`$(jq -r '.city' < "$IPAddressFilename")\`\n*Region/State*: \`$(jq -r '.regionName' < "$IPAddressFilename")\`\n*Country*: \`$(jq -r '.country' < "$IPAddressFilename")\`\n*Latitude*: \`$(jq -r '.lat' < "$IPAddressFilename")\`\n*Longitude*: \`$(jq -r '.lon' < "$IPAddressFilename")\`\n*Postal Code*: \`$(jq -r '.zip' < "$IPAddressFilename")\`\n*Timezone*: \`$(jq -r '.timezone' < "$IPAddressFilename")\`" --parse_mode 'markdown' || { SendErrorMessage; }; cleanup
		else
			SendErrorMessage
		fi
	else
		SendErrorMessage
	fi

}

# This function is used to obtain the valid punycode of the domain names of the links sent by the user.
# This is only relevant for domain names that contain emojis and/or non-Latin characters.
GetPunycode(){

	if [ "$1" != '--from-user-query' ]; then
		idn "$Domain" 1>/dev/null 2>&1 && Punycode=$(idn "$Domain")
		idn2 "$Domain" 1>/dev/null 2>&1 && Punycode=$(idn2 "$Domain")
		if [ "$Punycode" ]; then
			if [ "$1" = '--from-file' ]; then
				[ "$Punycode" != "$Domain" ] && sed -i "s/$Domain/$Punycode/g" "$OriginalLinksFilename"
			elif [ "$1" = '--from-variable' ]; then
				[ "$Punycode" != "$Domain" ] && URL="${URL//$Domain/$Punycode}"
			fi
			unset 'Punycode'
		fi
	else
		idn "$UserQuery" 1>/dev/null 2>&1 && Punycode=$(idn "$UserQuery")
		idn2 "$UserQuery" 1>/dev/null 2>&1 && Punycode=$(idn2 "$UserQuery")
		if [ "$Punycode" ]; then
			[ "$Punycode" != "$UserQuery" ] && UserQuery="$Punycode"
		fi
	fi

	return '0'

}

# This command allows users to perform a HEAD request to websites/IP addresses.
BotCommand_head(){

	# Send basic command usage information
	if [ "$1" = '--send-usage' ]; then
		sendMessage --reply_to_message_id "$message_message_id" --chat_id "$message_chat_id" --text '*Usage:*\n\n`/head <ipv4_address_here>`\nor\n`!head <ipv4_address_here>`\n\n*Example:*\n\n`/head http://www.example.org/robots.txt`\nor\n`!head http://www.example.org/robots.txt`\n\n*Description:*\n\nThis command allows users to perform a HEAD request to websites/servers. The request will be made using cURL and all network traffic will pass through the Tor network. Note that IPv6 is not supported.' --parse_mode 'markdown' || { SendErrorMessage; }; exit
	# Decode text
	elif [ "$1" = '--make-request' ]; then
		if echo "$URL" | grep -Pq '(https?(://|%3A%2F%2F|%3a%2f%2f))?([0-9a-zA-Z\.-]+\.[a-zA-Z\.]{2,6}|((25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?))[^\ $(printf '\n')$(printf '\t')"('\'')<>,]*'; then
			sendMessage --reply_to_message_id "$message_message_id" --chat_id "$message_chat_id" --text "$(MakeHeadRequest)" --parse_mode 'markdown' || { SendErrorMessage; }; exit
		else
			sendMessage --reply_to_message_id "$message_message_id" --chat_id "$message_chat_id" --text 'Your request is invalid.' --parse_mode 'markdown' || { SendErrorMessage; }; exit
		fi
	else
		echo -e '\033[0;31mInvalid function call received!\033[0m'; return '1'
	fi

}

# This function is used to make HEAD requests to websites/IP addresses sent through the command "/head"
MakeHeadRequest(){

	timeout -s '9' "25" curl --silent -NkBL --head --raw --no-progress-meter --no-sessionid --ssl-no-revoke --no-keepalive --proto-default 'http' $NetworkProtocol $Socks5 $CACertOptions $DoHOptions -H 'Accept:' --request 'GET' --user-agent "$UserAgent" --url "$URL" | sed -r 's/^(HTTP\/[0-9](\.[0-9])?)/Protocol: \1\n/g; s/^\s([0-9]{3}(\s\w)?)\b/Status: \1/gm; s/^([A-Za-z0-9-]+):(\s)(.+)$/*\1*:\2\`\3\`/gm; s/\r//g'

}

# This function is used to check updates of the custom CA certificate store
CheckCAUpdate(){

	timeout -s '9' "25" curl -LNkB --no-progress-meter --no-sessionid --ssl-no-revoke --no-keepalive --remote-name --time-cond "$HOME/Unalix/Dependencies/cacert.pem" $NetworkProtocol $Socks5 $CACertOptions $DoHOptions -H 'Accept:' --request 'GET' --user-agent "$UserAgent" --url 'https://curl.haxx.se:443/ca/cacert.pem'
	
}

# Initial setup
SetupUnalix

# Generate (or not) a random user agent before each request
[ "$GenerateUserAgents" != 'false' ] && GenerateUserAgent || { UserAgent='Mozilla/5.0 (X11; Linux i586; rv:31.0) Gecko/20100101 Firefox/71.0'; }

# A basic internet connection check
echo -e '\033[0;33mChecking internet connection...\033[0m' && timeout -s '9' "$ConnectionTimeout" curl -s --raw --ignore-content-length --head $CACertOptions $NetworkProtocol $Socks5 $DoHOptions -H 'Accept:' --request 'GET' --user-agent "$UserAgent" --url 'http://www.gnu.org:80/robots.txt' -o '/dev/null' && echo -e '\033[0;32mSuccess!\033[0m' || { echo -e '\033[0;31mNo valid response received!\033[0m'; exit; }

# Check updates of the custom CA certificate store (http://curl.haxx.se/docs/caextract.html)
if [ "$CurlCustomCertificates" = 'true' ]; then
	if [ "$CurlCustomCertificatesPath" = "$HOME/Unalix/Dependencies/cacert.pem" ]; then
		echo -e '\033[0;33mChecking updates for the custom CA certificate store...\033[0m'
		CheckCAUpdate && echo -e '\033[0;32mSuccess!\033[0m' || { echo -e '\033[0;31mAn unknown error occurred!\033[0m'; }
	fi
fi

# Check if the API can be accessed
echo -e '\033[0;33mChecking access to the API...\033[0m' && timeout -s '9' "$ConnectionTimeout" curl -s --raw --ignore-content-length --head $CACertOptions $NetworkProtocol $Socks5 $DoHOptions -H 'Accept:' --request 'GET' --user-agent "$UserAgent" --url 'https://api.telegram.org:443/robots.txt' -o '/dev/null' && echo -e '\033[0;32mSuccess!\033[0m' || { echo -e '\033[0;31mNo valid response received!\033[0m'; exit; }

# Import ShellBot functions library
echo -e '\033[0;33mImporting functions..\033[0m.' && source "$HOME/Unalix/Dependencies/ShellBot.sh" && echo -e '\033[0;32mSuccess!\033[0m' || { echo -e '\033[0;31mAn unknown error has occurred!\033[0m'; exit; }

# Start the bot
echo -e '\033[0;33mStarting bot...\033[0m' && init --token "$BotToken" 1>/dev/null; echo -e '\033[0;32mSuccess!\033[0m'

# Trap signals and other events
trap "cleanup" 'INT' 'TERM'

echo -e '\033[0;33mGetting updates from the API...\033[0m'

while true; do

	# Generate (or not) a random user agent before each request
	[ "$GenerateUserAgents" != 'false' ] && GenerateUserAgent || { UserAgent='Mozilla/5.0 (X11; Linux i586; rv:31.0) Gecko/20100101 Firefox/71.0'; }
	
	# Get updates from the API
	getUpdates --limit '1' --offset "$(OffsetNext)" --timeout "$ConnectionTimeout"

	# List received data
	for id in "$(ListUpdates)"; do

		# Check if the text sent is part of a file (e.g: photo, video or document)
		[ -z "$message_text" ] && message_text="$message_caption"

		if [[ "$message_text" =~ ^(\!|/)(S|s)(T|t)(A|a)(R|r)(T|t)$ ]]; then
			sendMessage --reply_to_message_id "$message_message_id" --chat_id "$message_chat_id" --text 'Send via a message or inside a txt file the links you want to be "clean". Unalix will begin processing your request and within a few seconds (or minutes, depending on the number of links), it will send you the final result.\n\nUnalix is also able to process links from web pages. To do this, submit the URLs using the `/getfromurl` command. Unalix will download the entire contents of these URLs, obtain all the `http`/`https` links and process them in a batch operation.\n\nIn order to be able to identify the links contained in the message, txt file or web page, they must be in the following format:\n\n• It must start with `http://` or `https://` (case-insensitive)\n• It must have a domain name in Latin (`example.org`) or non-Latin (`президент.рф`) alphabet. Links with emoji domain name (`i❤️.ws`) are also supported.\n\n[Testing the bot with a link from an Amazon product](http://raw.githubusercontent.com/SnwMds/Unalix/master/Documentation/images/Example.png)\n\nIf you want Unalix to process multiple links from a single message, txt file or web page, separate them by a whitespace character (`\s`), tab (`\\t`), comma (`,`) or a new line (`\\n`).\n\n_Note: If you submit more than 1 link, the results will be sent in a txt file._\n\n[Testing the bot with multiple links in a single message](http://raw.githubusercontent.com/SnwMds/Unalix/master/Documentation/images/Example2.png)\n\nNote that Unalix can also identify links in forwarded messages and file captions.\n\nFor more information about Unalix, take a look at our [GitHub repository](http://github.com/SnwMds/Unalix) (Yes, it'\''s fully open source!).' --parse_mode 'markdown' --disable_web_page_preview 'true' || { SendErrorMessage; }; cleanup
		elif [[ "$message_text" =~ ^(\!|/)(e|E)(n|N)(c|C)(o|O)(d|D)(e|E)(t|T)(e|E)(x|X)(t|T)$ ]]; then
			BotCommand_encodetext --send-usage
		elif [[ "$message_text" =~ ^(\!|/)(e|E)(n|N)(c|C)(o|O)(d|D)(e|E)(t|T)(e|E)(x|X)(t|T).+$ ]]; then
			BotCommand_encodetext --encode-text
		elif [[ "$message_text" =~ ^(\!|/)(d|D)(e|E)(c|C)(o|O)(d|D)(e|E)(t|T)(e|E)(x|X)(t|T)$ ]]; then
			BotCommand_decodetext --send-usage
		elif [[ "$message_text" =~ ^(\!|/)(d|D)(e|E)(c|C)(o|O)(d|D)(e|E)(t|T)(e|E)(x|X)(t|T).+$ ]]; then
			BotCommand_decodetext --decode-text
		elif [[ "$message_text" =~ ^(\!|/)(i|I)(p|P)$ ]]; then
			sendMessage --reply_to_message_id "$message_message_id" --chat_id "$message_chat_id" --text '*Usage:*\n\n`/ip <ipv4_or_ipv6_address_here>`\nor\n`!ip <ipv4_or_ipv6_address_here>`\n\n*Example:*\n\n`/ip uncensored.any.dns.nixnet.xyz`\nor\n`!ip uncensored.any.dns.nixnet.xyz`\n\n*Description:*\n\nThis command allows users to query information about IPv4/IPv6 addresses. If a domain name is sent, Unalix will try to resolve the IPv4 address first and, if it fails, it will try to resolve the IPv6 address.' --parse_mode 'markdown'
		elif [[ "$message_text" =~ ^(\!|/)(i|I)(p|P).+$ ]]; then
			UserQuery=$(echo "$message_text" | sed -r 's/^(\!|\/)(i|I)(p|P)\s+//g' | GetHostname --keep-port-number) && SetFilenameVariables --ip-query && CheckUserQuery || { SendErrorMessage; }; exit
		elif [[ "$message_text" =~ ^(\!|/)(p|P)(u|U)(n|N)(y|Y)(c|C)(o|O)(d|D)(e|E)$ ]]; then
			sendMessage --reply_to_message_id "$message_message_id" --chat_id "$message_chat_id" --text '*Usage:*\n\n`/punycode <domain_name_here>`\nor\n`!punycode <domain_name_here>`\n\n*Example:*\n\n`/punycode президент.рф`\nor\n`!punycode президент.рф`\n\n*Description:*\n\nUse this command to obtain the valid punycode of domain names that have letters in non-Latin alphabet and/or that have emojis.' --parse_mode 'markdown' || { SendErrorMessage; }; exit
		elif [[ "$message_text" =~ ^(\!|/)(p|P)(u|U)(n|N)(y|Y)(c|C)(o|O)(d|D)(e|E).+$ ]]; then
			UserQuery=$(echo "$message_text" | sed -r 's/^(\!|\/)(p|P)(u|U)(n|N)(y|Y)(c|C)(o|O)(d|D)(e|E)\s+//g' | GetHostname) && GetPunycode --from-user-query
			sendMessage --reply_to_message_id "$message_message_id" --chat_id "$message_chat_id" --text "\`$UserQuery\`" --parse_mode 'markdown' || { SendErrorMessage; }; exit
		elif [[ "$message_text" =~ ^(\!|/)(h|H)(e|E)(a|A)(d|D)$ ]]; then
			BotCommand_head --send-usage
		elif [[ "$message_text" =~ ^(\!|/)(h|H)(e|E)(a|A)(d|D).+ ]]; then
			URL=$(echo "$message_text" | sed -r 's/^(\!|\/)(h|H)(e|E)(a|A)(d|D)\s+//g') && URL=$(DecodeText "$URL") && Domain=$(echo "$URL" | GetHostname) && GetPunycode --from-variable && BotCommand_head --make-request || { SendErrorMessage; }; exit
		elif [ "$message_document_mime_type" = 'text/plain' ]; then
			SetFilenameVariables && GetFromFile='true' && ProcessLinks
		elif [[ "$message_text" =~ ^(\!|/)(g|G)(e|E)(t|T)(f|F)(r|R)(o|O)(m|M)(u|U)(r|R)(l|L)$ ]]; then
			sendMessage --reply_to_message_id "$message_message_id" --chat_id "$message_chat_id" --text '*Usage:*\n\n`/getfromurl <url_or_link_here>`\nor\n`!getfromurl <url_or_link_here>`\n\n*Example:*\n\n`/getfromurl http://example.org/links.txt`\nor\n`!getfromurl http://example.org/links.txt`\n\n*Description:*\n\nUnalix will download the contents of these `<urls>`, obtain all the http/https links from the page and process them in a batch operation. The results will be sent in a txt file (if the final result has more than 1 link) or via message (if the final result has only 1 link).' --parse_mode 'markdown' || { SendErrorMessage; }; exit
		elif [[ "$message_text" =~ ^(\!|/)(g|G)(e|E)(t|T)(f|F)(r|R)(o|O)(m|M)(u|U)(r|R)(l|L).+$ ]]; then
			SetFilenameVariables && GetFromURL='true' && ProcessLinks
		elif [[ "$message_text" =~ .*(H|h)(T|t)(T|t)(P|p)(S|s)?(://|%3A%2F%2F|%3a%2f%2f)[^\ $(printf '\n')$(printf '\t')\"]* ]]; then
			SetFilenameVariables && ProcessLinks
		elif [ "$message_text" ]; then
			sendMessage --reply_to_message_id "$message_message_id" --chat_id "$message_chat_id" --text 'Send me any link that starts with `http://` or `https://` (case-insensitive).' --parse_mode 'markdown' || { SendErrorMessage; }; exit
		else
			exit '0'
		fi
	done & # Loops run in background
done

trap - 'INT' 'TERM'
