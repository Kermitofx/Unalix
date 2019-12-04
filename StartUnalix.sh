#!/bin/bash

# The network requests function. This will be used to find the direct link of shortened URLs
MakeNetworkRequest(){
	GenerateUserAgent
	# Make request
	timeout -s '9' '25' wget --max-redirect '999' --ignore-length --no-host-directories --no-cookies --no-dns-cache --no-cache --spider --no-proxy --no-check-certificate --no-hsts --user-agent "$UserAgent" "$URL" 2>&1 | grep -Eo '(http|https)://[^ \"]+' > "$TrashURLFilename"
	# Set received data
	URL=$(cat "$TrashURLFilename" | tail -1); SetFilenameVariables; echo "$URL" > "$TrashURLFilename"
}

# Delete placeholder files (from git), creat all needed directories and set all environment variables
SetupUnalix(){
	rm -f "$HOME/Unalix/Administrators/placeholder" "$HOME/Unalix/Reports/placeholder"
	[ -d "$HOME/Unalix/Rules" ] || { mkdir -p "$HOME/Unalix/Rules"; }
	[ -d "$HOME/Unalix/TempFiles" ] || { mkdir -p "$HOME/Unalix/TempFiles"; }
	[ -d "$HOME/Unalix/PatternDetection" ] || { mkdir -p "$HOME/Unalix/PatternDetection"; }
	[ -d "$HOME/Unalix/Administrators" ] || { mkdir -p "$HOME/Unalix/Administrators"; }
	[ -d "$HOME/Unalix/Reports" ] || { mkdir -p "$HOME/Unalix/Reports"; }
}

# Remove trackings parameters using regex patterns stored in the "$EndRegex" file
RemoveTrackingParameters(){
	# Parse "redirection" patterns
	cat "$EndRegex" | grep -E '^Redirection\=' | sed -r '/^#.*|^$/d' | sed -r 's/^Redirection\=//g' | while read -r 'RegexRules'
	do
		sed -ri "s/$RegexRules/\1/g" "$TrashURLFilename"
	done

	# Remove specific parameters
	cat "$EndRegex" | sed -r '/^Redirection\=/d' | sed -r '/^#.*|^$/d' | while read -r 'RegexRules'
	do
		sed -ri "s/$RegexRules//g" "$TrashURLFilename"
	done

	URL=$(cat "$TrashURLFilename"); rm -f "$EndRegex" "$TrashURLFilename"

}

DetectPatterns(){
	# Import all variables from scripts in "Unalix/PatternDetection"
	# This is used to decide which regex patterns will be (or not) used to remove tracking parameters of links sent by users
	# To learn how Unalix decides which regex rules should be used or not, read the ClearURLs wiki at http://gitlab.com/KevinRoebert/ClearUrls/wikis/Technical-details/Rules-file
	source "$HOME/Unalix/PatternDetection/MozawsPatternDetection.sh" "$URL"
	source "$HOME/Unalix/PatternDetection/DoubleclickPatternDetection.sh" "$URL"
	source "$HOME/Unalix/PatternDetection/TechcrunchPatternDetection.sh" "$URL"
	source "$HOME/Unalix/PatternDetection/FacebookPatternDetection.sh" "$URL"
	source "$HOME/Unalix/PatternDetection/GoogleAdsPatternDetection.sh" "$URL"
	source "$HOME/Unalix/PatternDetection/NytimesPatternDetection.sh" "$URL"
	source "$HOME/Unalix/PatternDetection/NetParadePatternDetection.sh" "$URL"
	source "$HOME/Unalix/PatternDetection/VivaldiPatternDetection.sh" "$URL"
	source "$HOME/Unalix/PatternDetection/YoukuPatternDetection.sh" "$URL"
	source "$HOME/Unalix/PatternDetection/EbayPatternDetection.sh" "$URL"
	source "$HOME/Unalix/PatternDetection/GatePatternDetection.sh" "$URL"
	source "$HOME/Unalix/PatternDetection/GitHubPatternDetection.sh" "$URL"
	source "$HOME/Unalix/PatternDetection/TchiboPatternDetection.sh" "$URL"
	source "$HOME/Unalix/PatternDetection/MozillaZinePatternDetection.sh" "$URL"
	source "$HOME/Unalix/PatternDetection/HhdotruPatternDetection.sh" "$URL"
	source "$HOME/Unalix/PatternDetection/SteamcommunityPatternDetection.sh" "$URL"
	source "$HOME/Unalix/PatternDetection/LinksynergyPatternDetection.sh" "$URL"
	source "$HOME/Unalix/PatternDetection/SteampoweredPatternDetection.sh" "$URL"
	source "$HOME/Unalix/PatternDetection/DailycodingproblemPatternDetection.sh" "$URL"
	source "$HOME/Unalix/PatternDetection/TwitchPatternDetection.sh" "$URL"
	source "$HOME/Unalix/PatternDetection/GooglePatternDetection.sh" "$URL"
	source "$HOME/Unalix/PatternDetection/PrvnizpravyPatternDetection.sh" "$URL"
	source "$HOME/Unalix/PatternDetection/TwitterPatternDetection.sh" "$URL"
	source "$HOME/Unalix/PatternDetection/DeviantartPatternDetection.sh" "$URL"
	source "$HOME/Unalix/PatternDetection/YouTubePatternDetection.sh" "$URL"
	source "$HOME/Unalix/PatternDetection/NypostPatternDetection.sh" "$URL"
	source "$HOME/Unalix/PatternDetection/GovdeliveryPatternDetection.sh" "$URL"
	source "$HOME/Unalix/PatternDetection/SitePatternDetection.sh" "$URL"
	source "$HOME/Unalix/PatternDetection/MozillaPatternDetection.sh" "$URL"
	source "$HOME/Unalix/PatternDetection/Site3PatternDetection.sh" "$URL"
	source "$HOME/Unalix/PatternDetection/GenericPatternDetection.sh" "$URL"
	source "$HOME/Unalix/PatternDetection/IndeedPatternDetection.sh" "$URL"
	source "$HOME/Unalix/PatternDetection/AmazonPatternDetection.sh" "$URL"
	source "$HOME/Unalix/PatternDetection/VitamixPatternDetection.sh" "$URL"
	source "$HOME/Unalix/PatternDetection/WootPatternDetection.sh" "$URL"
	source "$HOME/Unalix/PatternDetection/DisqusPatternDetection.sh" "$URL"
	source "$HOME/Unalix/PatternDetection/WalmartPatternDetection.sh" "$URL"
	source "$HOME/Unalix/PatternDetection/AmazonAdsPatternDetection.sh" "$URL"
	source "$HOME/Unalix/PatternDetection/ImdbPatternDetection.sh" "$URL"
	source "$HOME/Unalix/PatternDetection/TweakersPatternDetection.sh" "$URL"
	source "$HOME/Unalix/PatternDetection/MessengerPatternDetection.sh" "$URL"
	source "$HOME/Unalix/PatternDetection/RedditPatternDetection.sh" "$URL"
	source "$HOME/Unalix/PatternDetection/NormlPatternDetection.sh" "$URL"
	source "$HOME/Unalix/PatternDetection/ReaddcPatternDetection.sh" "$URL"
	source "$HOME/Unalix/PatternDetection/CnetPatternDetection.sh" "$URL"
	source "$HOME/Unalix/PatternDetection/OzonPatternDetection.sh" "$URL"
	source "$HOME/Unalix/PatternDetection/SpiegelPatternDetection.sh" "$URL"
	source "$HOME/Unalix/PatternDetection/BingPatternDetection.sh" "$URL"
	source "$HOME/Unalix/PatternDetection/GiphyPatternDetection.sh" "$URL"
	source "$HOME/Unalix/PatternDetection/AliExpressPatternDetection.sh" "$URL"
	source "$HOME/Unalix/PatternDetection/SmartredirectPatternDetection.sh" "$URL"
	source "$HOME/Unalix/PatternDetection/LinkedInPatternDetection.sh" "$URL"
	source "$HOME/Unalix/PatternDetection/9GAGPatternDetection.sh" "$URL"
	source "$HOME/Unalix/PatternDetection/CurseforgePatternDetection.sh" "$URL"
	source "$HOME/Unalix/PatternDetection/VKPatternDetection.sh" "$URL"
	source "$HOME/Unalix/PatternDetection/Site2PatternDetection.sh" "$URL"
	source "$HOME/Unalix/PatternDetection/NetflixPatternDetection.sh" "$URL"
	source "$HOME/Unalix/PatternDetection/ShutterstockPatternDetection.sh" "$URL"
	source "$HOME/Unalix/PatternDetection/TelefonicaVivoPatternDetection.sh" "$URL"
	source "$HOME/Unalix/PatternDetection/GoogleAMPPatternDetection.sh" "$URL"
	# Import all regex patterns that will be used
	[ "$UseMozawsRegex" = 'true' ] && cat "$HOME/Unalix/Rules/MozawsRules.txt" > "$EndRegex" && unset 'UseMozawsRegex'
	[ "$UseDoubleclickRegex" = 'true' ] && cat "$HOME/Unalix/Rules/DoubleclickRules.txt" >> "$EndRegex" && unset 'UseDoubleclickRegex'
	[ "$UseTechcrunchRegex" = 'true' ] && cat "$HOME/Unalix/Rules/TechcrunchRules.txt" >> "$EndRegex" && unset 'UseTechcrunchRegex'
	[ "$UseFacebookRegex" = 'true' ] && cat "$HOME/Unalix/Rules/FacebookRules.txt" >> "$EndRegex" && unset 'UseFacebookRegex'
	[ "$UseNetflixRegex" = 'true' ] && cat "$HOME/Unalix/Rules/NetflixRules.txt" >> "$EndRegex" && unset 'UseNetflixRegex'
	[ "$UseCnetRegex" = 'true' ] && cat "$HOME/Unalix/Rules/CnetRules.txt" >> "$EndRegex" && unset 'UseCnetRegex'
	[ "$UseAliExpressRegex" = 'true' ] && cat "$HOME/Unalix/Rules/AliExpressRules.txt" >> "$EndRegex" && unset 'UseAliExpressRegex'
	[ "$UseCurseforgeRegex" = 'true' ] && cat "$HOME/Unalix/Rules/CurseforgeRules.txt" >> "$EndRegex" && unset 'UseCurseforgeRegex'
	[ "$UseSpiegelRegex" = 'true' ] && cat "$HOME/Unalix/Rules/SpiegelRules.txt" >> "$EndRegex" && unset 'UseSpiegelRegex'
	[ "$UseYoukuRegex" = 'true' ] && cat "$HOME/Unalix/Rules/YoukuRules.txt" >> "$EndRegex" && unset 'UseYoukuRegex'
	[ "$UseTwitterRegex" = 'true' ] && cat "$HOME/Unalix/Rules/TwitterRules.txt" >> "$EndRegex" && unset 'UseTwitterRegex'
	[ "$UsePrvnizpravyRegex" = 'true' ] && cat "$HOME/Unalix/Rules/PrvnizpravyRules.txt" >> "$EndRegex" && unset 'UsePrvnizpravyRegex'
	[ "$UseBingRegex" = 'true' ] && cat "$HOME/Unalix/Rules/BingRules.txt" >> "$EndRegex" && unset 'UseBingRegex'
	[ "$UseEbayRegex" = 'true' ] && cat "$HOME/Unalix/Rules/EbayRules.txt" >> "$EndRegex" && unset 'UseEbayRegex'
	[ "$UseOzonRegex" = 'true' ] && cat "$HOME/Unalix/Rules/OzonRules.txt" >> "$EndRegex" && unset 'UseOzonRegex'
	[ "$UseLinkedInRegex" = 'true' ] && cat "$HOME/Unalix/Rules/LinkedInRules.txt" >> "$EndRegex" && unset 'UseLinkedInRegex'
	[ "$UseFacebookRegex" = 'true' ] && cat "$HOME/Unalix/Rules/FacebookRules.txt" >> "$EndRegex" && unset 'UseFacebookRegex'
	[ "$UseYouTubeRegex" = 'true' ] && cat "$HOME/Unalix/Rules/YouTubeRules.txt" >> "$EndRegex" && unset 'UseYouTubeRegex'
	[ "$UseDailycodingproblemRegex" = 'true' ] && cat "$HOME/Unalix/Rules/DailycodingproblemRules.txt" >> "$EndRegex" && unset 'UseDailycodingproblemRegex'
	[ "$UseVivaldiRegex" = 'true' ] && cat "$HOME/Unalix/Rules/VivaldiRules.txt" >> "$EndRegex" && unset 'UseVivaldiRegex'
	[ "$UseReaddcRegex" = 'true' ] && cat "$HOME/Unalix/Rules/ReaddcRules.txt" >> "$EndRegex" && unset 'UseReaddcRegex'
	[ "$UseTchiboRegex" = 'true' ] && cat "$HOME/Unalix/Rules/TchiboRules.txt" >> "$EndRegex" && unset 'UseTchiboRegex'
	[ "$UseVKRegex" = 'true' ] && cat "$HOME/Unalix/Rules/VKRules.txt" >> "$EndRegex" && unset 'UseVKRegex'
	[ "$UseSiteRegex" = 'true' ] && cat "$HOME/Unalix/Rules/Site.txt" >> "$EndRegex" && unset 'UseSiteRegex'
	[ "$UseWalmartRegex" = 'true' ] && cat "$HOME/Unalix/Rules/WalmartRules.txt" >> "$EndRegex" && unset 'UseWalmartRegex'
	[ "$UseNormlRegex" = 'true' ] && cat "$HOME/Unalix/Rules/NormlRules.txt" >> "$EndRegex" && unset 'UseNormlRegex'
	[ "$UseSteampoweredRegex" = 'true' ] && cat "$HOME/Unalix/Rules/SteampoweredRules.txt" >> "$EndRegex" && unset 'UseSteampoweredRegex'
	[ "$UseSite2Regex" = 'true' ] && cat "$HOME/Unalix/Rules/Site2Rules.txt" >> "$EndRegex" && unset 'UseSite2Regex'
	[ "$UseGoogleAdsRegex" = 'true' ] && cat "$HOME/Unalix/Rules/GoogleAdsRules.txt" >> "$EndRegex" && unset 'UseGoogleAdsRegex'
	[ "$UseWootRegex" = 'true' ] && cat "$HOME/Unalix/Rules/WootRules.txt" >> "$EndRegex" && unset 'UseWootRegex'
	[ "$Use9GAGRegex" = 'true' ] && cat "$HOME/Unalix/Rules/9GAGRules.txt" >> "$EndRegex" && unset 'Use9GAGRegex'
	[ "$UseImdbRegex" = 'true' ] && cat "$HOME/Unalix/Rules/ImdbRules.txt" >> "$EndRegex" && unset 'UseImdbRegex'
	[ "$UseMozawsRegex" = 'true' ] && cat "$HOME/Unalix/Rules/MozawsRules.txt" >> "$EndRegex" && unset 'UseMozawsRegex'
	[ "$UseGitHubRegex" = 'true' ] && cat "$HOME/Unalix/Rules/GitHubRules.txt" >> "$EndRegex" && unset 'UseGitHubRegex'
	[ "$UseSteamcommunityRegex" = 'true' ] && cat "$HOME/Unalix/Rules/SteamcommunityRules.txt" >> "$EndRegex" && unset 'UseSteamcommunityRegex'
	[ "$UseShutterstockRegex" = 'true' ] && cat "$HOME/Unalix/Rules/ShutterstockRules.txt" >> "$EndRegex" && unset 'UseShutterstockRegex'
	[ "$UseNetParadeRegex" = 'true' ] && cat "$HOME/Unalix/Rules/NetParadeRules.txt" >> "$EndRegex" && unset 'UseNetParadeRegex'
	[ "$UseGovdeliveryRegex" = 'true' ] && cat "$HOME/Unalix/Rules/GovdeliveryRules.txt" >> "$EndRegex" && unset 'UseGovdeliveryRegex'
	[ "$UseMessengerRegex" = 'true' ] && cat "$HOME/Unalix/Rules/MessengerRules.txt" >> "$EndRegex" && unset 'UseMessengerRegex'
	[ "$UseGoogleRegex" = 'true' ] && cat "$HOME/Unalix/Rules/GoogleRules.txt" >> "$EndRegex" && unset 'UseGoogleRegex'
	[ "$UseSmartredirectRegex" = 'true' ] && cat "$HOME/Unalix/Rules/SmartredirectRules.txt" >> "$EndRegex" && unset 'UseSmartredirectRegex'
	[ "$UseVitamixRegex" = 'true' ] && cat "$HOME/Unalix/Rules/VitamixRules.txt" >> "$EndRegex" && unset 'UseVitamixRegex'
	[ "$UseIndeedRegex" = 'true' ] && cat "$HOME/Unalix/Rules/IndeedRules.txt" >> "$EndRegex" && unset 'UseIndeedRegex'
	[ "$UseMozillaZineRegex" = 'true' ] && cat "$HOME/Unalix/Rules/MozillaZineRules.txt" >> "$EndRegex" && unset 'UseMozillaZineRegex'
	[ "$UseGiphyRegex" = 'true' ] && cat "$HOME/Unalix/Rules/GiphyRules.txt" >> "$EndRegex" && unset 'UseGiphyRegex'
	[ "$UseGenericRegex" = 'true' ] && cat "$HOME/Unalix/Rules/GlobalRules.txt" >> "$EndRegex" && unset 'UseGenericRegex'
	[ "$UseTwitchRegex" = 'true' ] && cat "$HOME/Unalix/Rules/TwitchRules.txt" >> "$EndRegex" && unset 'UseTwitchRegex'
	[ "$UseLinksynergyRegex" = 'true' ] && cat "$HOME/Unalix/Rules/LinksynergyRules.txt" >> "$EndRegex" && unset 'UseLinksynergyRegex'
	[ "$UseAmazonRegex" = 'true' ] && cat "$HOME/Unalix/Rules/AmazonRules.txt" >> "$EndRegex" && unset 'UseAmazonRegex'
	[ "$UseTweakersRegex" = 'true' ] && cat "$HOME/Unalix/Rules/TweakersRules.txt" >> "$EndRegex" && unset 'UseTweakersRegex'
	[ "$UseAmazonAdsRegex" = 'true' ] && cat "$HOME/Unalix/Rules/AmazonAdsRules.txt" >> "$EndRegex" && unset 'UseAmazonAdsRegex'
	[ "$UseSite3Regex" = 'true' ] && cat "$HOME/Unalix/Rules/Site3Rules.txt" >> "$EndRegex" && unset 'UseSite3Regex'
	[ "$UseRedditRegex" = 'true' ] && cat "$HOME/Unalix/Rules/RedditRules.txt" >> "$EndRegex" && unset 'UseRedditRegex'
	[ "$UseDeviantartRegex" = 'true' ] && cat "$HOME/Unalix/Rules/DeviantartRules.txt" >> "$EndRegex" && unset 'UseDeviantartRegex'
	[ "$UseMozillaRegex" = 'true' ] && cat "$HOME/Unalix/Rules/MozillaRules.txt" >> "$EndRegex" && unset 'UseMozillaRegex'
	[ "$UseDisqusRegex" = 'true' ] && cat "$HOME/Unalix/Rules/DisqusRules.txt" >> "$EndRegex" && unset 'UseDisqusRegex'
	[ "$UseHhdotruRegex" = 'true' ] && cat "$HOME/Unalix/Rules/HhdotruRules.txt" >> "$EndRegex" && unset 'UseHhdotruRegex'
	[ "$UseNytimesRegex" = 'true' ] && cat "$HOME/Unalix/Rules/NytimesRules.txt" >> "$EndRegex" && unset 'UseNytimesRegex'
	[ "$UseNypostRegex" = 'true' ] && cat "$HOME/Unalix/Rules/NypostRules.txt" >> "$EndRegex" && unset 'UseNypostRegex'
	[ "$UseGateRegex" = 'true' ] && cat "$HOME/Unalix/Rules/GateRules.txt" >> "$EndRegex" && unset 'UseGateRegex'
	[ "$UseTelefonicaVivoRegex" = 'true' ] && cat "$HOME/Unalix/Rules/TelefonicaVivoRules.txt" >> "$EndRegex" && unset 'UseTelefonicaVivoRegex'
	[ "$UseGoogleAMPRegex" = 'true' ] && cat "$HOME/Unalix/Rules/Special/GoogleAMPRules.txt" >> "$SpecialEndRegex" && unset 'UseGoogleAMPRegex'
}

# Set filename variables
SetFilenameVariables(){
	SpecialEndRegex="$HOME/Unalix/TempFiles/Regex-$(tr -dc A-Za-z0-9_ < /dev/urandom | head -c 10).txt"
	EndRegex="$HOME/Unalix/TempFiles/Regex-$(tr -dc A-Za-z0-9_ < /dev/urandom | head -c 10).txt"
	TrashURLFilename="$HOME/Unalix/TempFiles/TrashURL-$(tr -dc A-Za-z0-9_ < /dev/urandom | head -c 10).txt"
}

# This is the main function. It calls all other functions related to removal of tracking parameters
ParseTrackingParameters(){
	
	SetFilenameVariables
	
	echo "$URL" > "$TrashURLFilename"

	DecodeNonASCII

	DetectPatterns; RemoveTrackingParameters
	
	MakeNetworkRequest
	
	DecodeNonASCII

	DetectPatterns; RemoveTrackingParameters

	rm -f "$EndRegex" "$TrashURLFilename"
	
}

# Get end results and check if it's valid
GetEndResults(){
	[[ "$URL" =~ ^(http|https):\/\/.+$ ]] && MakeURLCompatible && ShellBot.sendMessage --reply_to_message_id "$message_message_id" --chat_id "$message_chat_id" --text "\`$URL\`" --parse_mode 'markdown' || { ShellBot.sendMessage --reply_to_message_id "$message_message_id" --chat_id "$message_chat_id" --text "The \`ParseTrackingParameters\` function has returned an invalid result." --parse_mode 'markdown'; }
}

# Remove invalid code strokes and escape some characters to avoid errors when submitting the text to the Telegram API
MakeURLCompatible(){
	URL=$(echo "$URL" | sed -r 's/&{2,}//g; s/\?&/?/g; s/&$//; s/\?$//; s/&/\%26/g; s/\s/%7F/g')
}

# This function is used to "decode" all (or most of it) ASCII characters
DecodeNonASCII(){
	cat "$HOME/Unalix/Rules/NonASCIIRules.txt" | sed -r '/^#.*|^$/d' | while read -r 'RegexRules'
	do
		sed -ri "$RegexRules" "$TrashURLFilename"
	done
}

# The network requests function. This will be used to test the connection to DNS servers
DNSCheck(){
	GenerateUserAgent
	# Make request
	timeout -s '9' '25' wget -q --header 'accept: application/dns-json' --max-redirect '999' --ignore-length --no-host-directories --no-cookies --no-dns-cache --no-cache --spider --no-proxy --no-check-certificate --no-hsts --user-agent "$UserAgent" "$1"
}

# This function is used to test the connection to DNS servers
MakeDNSTest(){
	# Set filename variables
	DNSAnswerFilename="$HOME/Unalix/TempFiles/Resolved-$(tr -dc A-Za-z0-9_ < /dev/urandom | head -c 10).txt"
	IPAddressFilename="$HOME/Unalix/TempFiles/IPAddress-$(tr -dc A-Za-z0-9_ < /dev/urandom | head -c 10).txt"
	IPQueryResultFilename="$HOME/Unalix/TempFiles/IPQuery-$(tr -dc A-Za-z0-9_ < /dev/urandom | head -c 10).txt"

	UserAgent='g'
	# These are the DNS servers that can be used to resolve domains sent using the "/ip" command.
	# Uncensored Anycast | http://nixnet.xyz/dns
	if DNSCheck 'https://uncensored.any.dns.nixnet.xyz/dns-query?name=gnu.org'; then
		DNSResolver='https://uncensored.any.dns.nixnet.xyz/dns-query?name='
	# Uncensored Anycast (Las Vegas) | http://nixnet.xyz/dns
	elif DNSCheck 'https://uncensored.lv1.dns.nixnet.xyz/dns-query?name=gnu.org'; then
		DNSResolver='https://uncensored.lv1.dns.nixnet.xyz/dns-query?name='
	# Uncensored Anycast (New York) | http://nixnet.xyz/dns
	elif DNSCheck 'https://uncensored.ny1.dns.nixnet.xyz/dns-query?name=gnu.org'; then
		DNSResolver='https://uncensored.ny1.dns.nixnet.xyz/dns-query?name='
	# Uncensored Anycast (Luxembourg) | http://nixnet.xyz/dns
	elif DNSCheck 'https://uncensored.lux1.dns.nixnet.xyz/dns-query?name=gnu.org'; then
		DNSResolver='https://uncensored.lux1.dns.nixnet.xyz/dns-query?name='
	# Uncensored DNS (Germany) | http://github.com/bhanupratapys/dnswarden/blob/master/README.md
	elif DNSCheck 'https://doh.dnswarden.com/uncensored?name=gnu.org'; then
		DNSResolver='https://doh.dnswarden.com/dns-query?name='
	# Uncensored DNS (Austria) | http://appliedprivacy.net/services/dns
	elif DNSCheck 'https://doh.appliedprivacy.net/query?name=gnu.org'; then
		DNSResolver='https://doh.appliedprivacy.net/dns-query?name='
	# Uncensored DNS (Netherlands) | http://securedns.eu
	elif DNSCheck 'https://doh.securedns.eu/dns-query?name=gnu.org'; then
		DNSResolver='https://doh.securedns.eu/dns-query?name='
	# Uncensored DNS (Finland) | http://snopyta.org/service/dns
	elif DNSCheck 'https://fi.doh.dns.snopyta.org/dns-query?name=gnu.org'; then
		DNSResolver='https://fi.doh.dns.snopyta.org/dns-query?name='
	# Google DNS | http://developers.google.com/speed/public-dns (privacy-unfriendly)
	elif DNSCheck 'https://dns.google/resolve?name=gnu.org'; then
		DNSResolver='https://dns.google/resolve?name='
	else
		ShellBot.sendMessage --reply_to_message_id "$message_message_id" --chat_id "$message_chat_id" --text 'No DNS server can process your request at this time.'; cleanup
	fi
	CheckUserQuery
}

CheckUserQuery(){
	if echo "$UserQuery" | grep -qE '\.onion$'; then
		ShellBot.sendMessage --reply_to_message_id "$message_message_id" --chat_id "$message_chat_id" --text 'Tor/Onion-related domains cannot be resolved.'; cleanup
	elif echo "$UserQuery" | grep -qE '\.i2p$'; then
		ShellBot.sendMessage --reply_to_message_id "$message_message_id" --chat_id "$message_chat_id" --text 'Domains related to the I2P network cannot be resolved.'; cleanup
	elif echo "$UserQuery" | grep -qE '[a-zA-Z0-9._-]{1,}\.[a-zA-Z0-9._-]{2,}'; then
		RequestType='Domain' && HostQuery="$UserQuery"
	elif echo "$UserQuery" | grep -qE '\b(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b'; then
		RequestType='IPv4'
	elif echo "$UserQuery" | grep -qE '\b(?:[a-f0-9]{1,4}:){6}(?::[a-f0-9]{1,4})|(?:[a-f0-9]{1,4}:){5}(?::[a-f0-9]{1,4}){1,2}|(?:[a-f0-9]{1,4}:){4}(?::[a-f0-9]{1,4}){1,3}|(?:[a-f0-9]{1,4}:){3}(?::[a-f0-9]{1,4}){1,4}|(?:[a-f0-9]{1,4}:){2}(?::[a-f0-9]{1,4}){1,5}|(?:[a-f0-9]{1,4}:)(?::[a-f0-9]{1,4}){1,6}|(?:[a-f0-9]{1,4}:){1,6}:|:(?::[a-f0-9]{1,4}){1,6}|[a-f0-9]{0,4}::|(?:[a-f0-9]{1,4}:){7}[a-f0-9]{1,4}\b'; then
		RequestType='IPv6'
	else
		ShellBot.sendMessage --reply_to_message_id "$message_message_id" --chat_id "$message_chat_id" --text 'Your query is invalid.'; cleanup
	fi
	GetIPAddress
}

# This function is used to resolve domain names sent by users using the "/ip" command.
GetIPAddress(){
	GenerateUserAgent
	# IPv4
	if timeout -s '9' '25' wget -q --header 'accept: application/dns-json' -q --max-redirect '999' --ignore-length --no-host-directories --no-cookies --no-dns-cache --no-cache --no-proxy --no-check-certificate --no-hsts --user-agent "$UserAgent" "$DNSResolver$UserQuery&type=A" -O "$DNSAnswerFilename"; then
		if cat "$DNSAnswerFilename" | grep -Eoq '\b(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b'; then
			UsingIPv4='true'
		# IPv6
		elif timeout -s '9' '25' wget -q --header 'accept: application/dns-json' -q --max-redirect '999' --ignore-length --no-host-directories --no-cookies --no-dns-cache --no-cache --no-proxy --no-check-certificate --no-hsts --user-agent "$UserAgent" "$DNSResolver$UserQuery&type=AAAA" -O "$DNSAnswerFilename"; then
			cat "$DNSAnswerFilename" | sed -r 's/.*data":"|".*//g' | grep -Eq '(?:[a-f0-9]{1,4}:){6}(?::[a-f0-9]{1,4})|(?:[a-f0-9]{1,4}:){5}(?::[a-f0-9]{1,4}){1,2}|(?:[a-f0-9]{1,4}:){4}(?::[a-f0-9]{1,4}){1,3}|(?:[a-f0-9]{1,4}:){3}(?::[a-f0-9]{1,4}){1,4}|(?:[a-f0-9]{1,4}:){2}(?::[a-f0-9]{1,4}){1,5}|(?:[a-f0-9]{1,4}:)(?::[a-f0-9]{1,4}){1,6}|(?:[a-f0-9]{1,4}:){1,6}:|:(?::[a-f0-9]{1,4}){1,6}|[a-f0-9]{0,4}::|(?:[a-f0-9]{1,4}:){7}[a-f0-9]{1,4}' && \
			UsingIPv6='true' || { ShellBot.sendMessage --reply_to_message_id "$message_message_id" --chat_id "$message_chat_id" --text 'An error occurred while trying to resolve the domain name.'; cleanup; }
		fi
	else
		ShellBot.sendMessage --reply_to_message_id "$message_message_id" --chat_id "$message_chat_id" --text 'An error occurred while trying to resolve the domain name. The attempt to connect to the DNS resolver has resulted in a failure.'; cleanup
	fi
	if [ "$UsingIPv4" = 'true' ]; then
		IPAddress="$(cat "$DNSAnswerFilename" | grep -E -o '\b(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b' | head -1)"; API_URL="https://ipapi.co:443/$IPAddress/json"
	elif [ "$UsingIPv6" = 'true' ]; then
		IPAddress="$(cat "$DNSAnswerFilename" | sed -r 's/.*data":"|".*//g' | head -1)"; API_URL="https://ipapi.co:443/$IPAddress/json"
	else
		ShellBot.sendMessage --reply_to_message_id "$message_message_id" --chat_id "$message_chat_id" --text 'An error occurred while trying to resolve the domain name.'; cleanup
	fi
	QueryIP
}

# This function is used to query information about the IP address. The query is made using the ipapi.co API.
# This API is very privacy-unfriendly, but I couldn't find something better
QueryIP(){
		GenerateUserAgent
		# Query API
		if timeout -s '9' '25' wget -q --max-redirect '999' --ignore-length --no-host-directories --no-cookies --no-dns-cache --no-cache --no-proxy --no-check-certificate --no-hsts --user-agent "$UserAgent" "$API_URL" -O "$IPQueryResultFilename"; then
			[[ "$(cat "$IPQueryResultFilename" | wc -c)" = '0' ]] && ShellBot.sendMessage --reply_to_message_id "$message_message_id" --chat_id "$message_chat_id" --text 'No valid response were received from the IP Address Query API.' && cleanup || { ParseIPAddress; SendQueryResult; }
		else
			ShellBot.sendMessage --reply_to_message_id "$message_message_id" --chat_id "$message_chat_id" --text 'Could not query IP address. The attempt to connect to the IP Address Query API has resulted in a failure.'; cleanup
		fi
		cleanup
}

# This function processes all data that has been received from the IP Address Query API (ipapi.co). All relevant information is stored in variables for future use.
ParseIPAddress(){
		IPAddress="$(cat "$IPQueryResultFilename" | grep '"ip"' | sed -r 's/^.*:\s"?|"|,$//g')"; [ ! "$IPAddress" ] && IPAddress='Unknown'; [ "$IPAddress" = 'null' ] && IPAddress='Unknown'
		City="$(cat "$IPQueryResultFilename" | grep '"city"' | sed -r 's/^.*:\s"?|"|,$//g' )"; [ ! "$City" ] && City='Unknown'; [ "$City" = 'null' ] && City='Unknown'
		Region="$(cat "$IPQueryResultFilename" | grep '"region"' | sed -r 's/^.*:\s"?|"|,$//g')"; [ ! "$Region" ] && Region='Unknown'; [ "$Region" = 'null' ] && Region='Unknown'
		CountryName="$(cat "$IPQueryResultFilename" | grep '"country_name"' | sed -r 's/^.*:\s"?|"|,$//g')"; [ ! "$CountryName" ] && CountryName='Unknown'; [ "$CountryName" = 'null' ] && CountryName='Unknown'
		PostalCode="$(cat "$IPQueryResultFilename" | grep '"postal"' | sed -r 's/^.*:\s"?|"|,$//g')"; [ ! "$PostalCode" ] && PostalCode='Unknown'; [ "$PostalCode" = 'null' ] && PostalCode='Unknown'
		Latitude="$(cat "$IPQueryResultFilename" | grep '"latitude"' | sed -r 's/^.*:\s"?|"|,$//g')"; [ ! "$Latitude" ] && Latitude='Unknown'; [ "$Latitude" = 'null' ] && Latitude='Unknown'
		Longitude="$(cat "$IPQueryResultFilename" | grep '"longitude"' | sed -r 's/^.*:\s"?|"|,$//g')"; [ ! "$Longitude" ] && Longitude='Unknown'; [ "$Longitude" = 'null' ] && Longitude='Unknown'
		Timezone="$(cat "$IPQueryResultFilename" | grep '"timezone"' | sed -r 's/^.*:\s"?|"|,$//g')"; [ ! "$Timezone" ] && Timezone='Unknown'; [ "$Timezone" = 'null' ] && Timezone='Unknown'
		ASN="$(cat "$IPQueryResultFilename" | grep '"asn"' | sed -r 's/^.*:\s"?|"|,$//g')"; [ ! "$ASN" ] && ASN='Unknown'; [ "$ASN" = 'null' ] && ASN='Unknown'
		Org="$(cat "$IPQueryResultFilename" | grep '"org"' | sed -r 's/^.*:\s"?|"|,$//g')"; [ ! "$Org" ] && Org='Unknown'; [ "$Org" = 'null' ] && Org='Unknown'
}

# This function sends all received data to the Telegram API
SendQueryResult(){
	# Send data to the API
	ShellBot.sendMessage --reply_to_message_id "$message_message_id" --chat_id "$message_chat_id" --text "*Query:* $([ "$RequestType" = 'Domain' ] && echo "\`$HostQuery\` (\`$IPAddress\`)" || { echo "\`$IPAddress\`"; })\n*Owner:* \`$ASN\` - \`$Org\`\n*City:* \`$City\`\n*Region/State:* \`$Region\`\n*Country:* \`$CountryName\`\n*Latitude:* \`$Latitude\`\n*Longitude:* \`$Longitude\`\n*Postal Code:* \`$PostalCode\`\n*Timezone:* \`$Timezone\`" --parse_mode 'markdown'
 
	# Delete temporally files and exit
	cleanup
}

cleanup(){
	# Delete all temporarily files
	rm -f "$IPQueryResultFilename" "$IPAddressFilename" "$DNSAnswerFilename" "$EndRegex" "$TrashURLFilename" "$SpecialEndRegex" "$CommandOutput"

	# Exit process
	exit
}

GenerateUserAgent(){
	# https://en.wikipedia.org/wiki/List_of_Microsoft_Windows_versions
	WindowsVersions=('4.10' 'NT 5.0' '4.90' 'NT 5.1' 'NT 5.2' 'NT 6.0' 'NT 6.1' 'NT 6.2' 'NT 6.3' 'NT 10.0')
	
	# https://www.macworld.co.uk/feature/mac/os-x-macos-versions-3662757/
	macOS_Versions=('10.6' '10.7' '10.8' '10.9' '10.10' '10.11' '10.12' '10.13' '10.14' '10.15')
	
	# https://en.wikipedia.org/wiki/Android_version_history
	AndroidVersions=('5.1.1' '6.0' '6.0.1' '7.0' '7.1.0' '7.1.2' '8.0' '8.1' '9.0' '10.0')
	
	# https://en.wikipedia.org/wiki/IOS_version_history
	iOSVersions=('4.2.1' '5.1.1' '6.1.6' '7.1.2' '9.3.5' '9.3.6' '10.3.3' '10.3.4' '12.4.4' '13.3')
	
	# System architectures
	SystemArchitectures=('32' '64')
	
	# 0 = Firefox
	# 1 = Chrome
	
	BrowserSelection=$(tr -dc 0-1 < /dev/urandom | head -c '1')
	if [ "$BrowserSelection" = '0' ]; then
		Browser='Firefox'
	elif [ "$BrowserSelection" = '1' ]; then
		Browser='Chrome'
	else
		UserAgent='Mozilla/5.0 (X11; Linux x86_64; rv:68.0) Gecko/20100101 Firefox/68.0'
	fi
	
	# Can be "Firefox" or "Chrome"
	if [ "$Browser" = 'Firefox' ]; then
		GenerateFirefox
	elif [ "$Browser" = 'Chrome' ]; then
		GenerateChrome
	else
		UserAgent='Mozilla/5.0 (X11; Linux x86_64; rv:68.0) Gecko/20100101 Firefox/68.0'
	fi
}

# 0 = Windows
# 1 = macOS
# 2 = Linux
# 3 = Android
# 4 = iOS

# https://www.whatismybrowser.com/guides/the-latest-user-agent/chrome
GenerateChrome(){

 	SystemSelection=$(tr -dc 0-4 < /dev/urandom | head -c '1')

	if [ "$SystemSelection" = '0' ]; then
		UserAgent="Mozilla/5.0 (Windows ${WindowsVersions[$(tr -dc 0-9 < /dev/urandom | head -c '1')]}; Win${SystemArchitectures[$(tr -dc 0-1 < /dev/urandom | head -c '1')]}; x${SystemArchitectures[$(tr -dc 0-1 < /dev/urandom | head -c '1')]}) AppleWebKit/$(tr -dc 1-9 < /dev/urandom | head -c '3').$(tr -dc 1-9 < /dev/urandom | head -c '2') (KHTML, like Gecko) Chrome/$(tr -dc 1-9 < /dev/urandom | head -c '2').0.$(tr -dc 1-9 < /dev/urandom | head -c '4').$(tr -dc 1-9 < /dev/urandom | head -c '2') Safari/$(tr -dc 1-9 < /dev/urandom | head -c '3').$(tr -dc 1-9 < /dev/urandom | head -c '2')"
	elif [ "$SystemSelection" = '1' ]; then
		UserAgent="Mozilla/5.0 (Macintosh; Intel Mac OS X ${macOS_Versions[$(tr -dc 0-9 < /dev/urandom | head -c '1')]}) AppleWebKit/$(tr -dc 1-9 < /dev/urandom | head -c '3').$(tr -dc 1-9 < /dev/urandom | head -c '2') (KHTML, like Gecko) Chrome/$(tr -dc 1-9 < /dev/urandom | head -c '2').0.$(tr -dc 1-9 < /dev/urandom | head -c '4').$(tr -dc 1-9 < /dev/urandom | head -c '2') Safari/$(tr -dc 1-9 < /dev/urandom | head -c '3').$(tr -dc 1-9 < /dev/urandom | head -c '2')"
	elif [ "$SystemSelection" = '2' ]; then
		UserAgent="Mozilla/5.0 (X11; Linux x86_${SystemArchitectures[$(tr -dc 0-1 < /dev/urandom | head -c '1')]}) AppleWebKit/$(tr -dc 1-9 < /dev/urandom | head -c '3').$(tr -dc 1-9 < /dev/urandom | head -c '2') (KHTML, like Gecko) Chrome/$(tr -dc 1-9 < /dev/urandom | head -c '2').0.$(tr -dc 1-9 < /dev/urandom | head -c '4').$(tr -dc 1-9 < /dev/urandom | head -c '2') Safari/$(tr -dc 1-9 < /dev/urandom | head -c '3').$(tr -dc 1-9 < /dev/urandom | head -c '2')"
	elif [ "$SystemSelection" = '3' ]; then
		UserAgent="Mozilla/5.0 (Linux; Android ${AndroidVersions[$(tr -dc 0-9 < /dev/urandom | head -c '1')]};) AppleWebKit/$(tr -dc 1-9 < /dev/urandom | head -c '3').$(tr -dc 1-9 < /dev/urandom | head -c '2') (KHTML, like Gecko) Chrome/$(tr -dc 1-9 < /dev/urandom | head -c '2').0.$(tr -dc 1-9 < /dev/urandom | head -c '4').$(tr -dc 1-9 < /dev/urandom | head -c '2') Mobile Safari/$(tr -dc 1-9 < /dev/urandom | head -c '3').$(tr -dc 1-9 < /dev/urandom | head -c '2')"
	elif [ "$SystemSelection" = '4' ]; then
		UserAgent="Mozilla/5.0 (iPhone; CPU iPhone OS ${iOSVersions[$(tr -dc 0-9 < /dev/urandom | head -c '1')]} like Mac OS X) AppleWebKit/$(tr -dc 1-9 < /dev/urandom | head -c '3').$(tr -dc 1-9 < /dev/urandom | head -c '2') (KHTML, like Gecko) CriOS/$(tr -dc 1-9 < /dev/urandom | head -c '2').0.$(tr -dc 1-9 < /dev/urandom | head -c '4').$(tr -dc 1-9 < /dev/urandom | head -c '2') Mobile/$(tr -dc A-Z0-9 < /dev/urandom | head -c '7') Safari/$(tr -dc 1-9 < /dev/urandom | head -c '3').$(tr -dc 1-9 < /dev/urandom | head -c '2')"
	else
		UserAgent='Mozilla/5.0 (X11; Linux x86_64; rv:68.0) Gecko/20100101 Firefox/68.0'
	fi
}

# https://www.whatismybrowser.com/guides/the-latest-user-agent/firefox
GenerateFirefox(){

	SystemSelection=$(tr -dc 0-4 < /dev/urandom | head -c '1')

	if [ "$SystemSelection" = '0' ]; then
		UserAgent="Mozilla/5.0 (Windows ${WindowsVersions[$(tr -dc 0-9 < /dev/urandom | head -c '1')]}; WOW${SystemArchitectures[$(tr -dc 0-1 < /dev/urandom | head -c '1')]}; rv:$(tr -dc 1-9 < /dev/urandom | head -c '2').0) Gecko/$(tr -dc 0-9 < /dev/urandom | head -c '8') Firefox/$(tr -dc 1-9 < /dev/urandom | head -c '2').0"
	elif [ "$SystemSelection" = '1' ]; then
		UserAgent="Mozilla/5.0 (Macintosh; Intel Mac OS X ${macOS_Versions[$(tr -dc 0-9 < /dev/urandom | head -c '1')]}; rv:$(tr -dc 1-9 < /dev/urandom | head -c '2').0) Gecko/$(tr -dc 0-9 < /dev/urandom | head -c '8') Firefox/$(tr -dc 1-9 < /dev/urandom | head -c '2').0"
	elif [ "$SystemSelection" = '2' ]; then
		UserAgent="Mozilla/5.0 (X11; Linux i586; rv:$(tr -dc 1-9 < /dev/urandom | head -c '2').0) Gecko/$(tr -dc 0-9 < /dev/urandom | head -c '8') Firefox/$(tr -dc 1-9 < /dev/urandom | head -c '2').0"
	elif [ "$SystemSelection" = '3' ]; then
		UserAgent="Mozilla/5.0 (Android ${AndroidVersions[$(tr -dc 0-9 < /dev/urandom | head -c '1')]}; Mobile; rv:$(tr -dc 1-9 < /dev/urandom | head -c '2').0) Gecko/$(tr -dc 1-9 < /dev/urandom | head -c '2').0 Firefox/$(tr -dc 1-9 < /dev/urandom | head -c '2').0"
	elif [ "$SystemSelection" = '4' ]; then
		UserAgent="Mozilla/5.0 (iPhone; CPU iPhone OS ${iOSVersions[$(tr -dc 0-9 < /dev/urandom | head -c '1')]} like Mac OS X) AppleWebKit/$(tr -dc 1-9 < /dev/urandom | head -c '3').$(tr -dc 0-9 < /dev/urandom | head -c '1').$(tr -dc 0-9 < /dev/urandom | head -c '2') (KHTML, like Gecko) FxiOS/$(tr -dc 1-9 < /dev/urandom | head -c '2').0 Mobile/$(tr -dc A-Z1-9 < /dev/urandom | head -c '5') Safari/$(tr -dc 1-9 < /dev/urandom | head -c '3').$(tr -dc 0-9 < /dev/urandom | head -c '1').$(tr -dc 0-9 < /dev/urandom | head -c '2')"
	else
		UserAgent='Mozilla/5.0 (X11; Linux x86_64; rv:68.0) Gecko/20100101 Firefox/68.0'
	fi
}

# A basic internet connection check
echo '- Checking internet connection...' && wget --no-check-certificate --spider -T '10' 'https://www.gnu.org' 2>> '/dev/null' 1>> '/dev/null' && echo '- Success!' || { echo '* No response received!'; cleanup; }

# Import ShellBot API
echo '- Importing functions...' && source "$HOME/Unalix/ShellBotCore/ShellBot.sh" && echo '- Success!' || { echo '* An unknown error has occurred!'; cleanup; }

# Start the bot
echo '- Starting bot...' && SetupUnalix && ShellBot.init --token "$(cat "$HOME/Unalix/Token/Token.txt" | sed -r '/^#.*|^$/d')"

while :
do
	# Get updates from the API
	ShellBot.getUpdates --limit '10' --offset "$(ShellBot.OffsetNext)" --timeout '15'
	
	# List received data
	for id in "$(ShellBot.ListUpdates)"
	do
	# Thread
	(
		# Check if the message sent by the user is a valid link
		if [[ "$message_text" =~ ^(http|https):\/\/.+$ ]]; then
			URL="$message_text" && ParseTrackingParameters && GetEndResults

		# The command "/report" allows users to send messages directly to the bot administrators
		# This is useful for users who want to report bugs or give feedback
		# To prevent spam, users cannot submit new reports if a saved report already exists associated with their user ID
		# The maximum number of characters per message is 4096, and this does not include the text "/report"
		elif [[ "$message_text" =~ ^(\!report|/report)$ ]]; then
			# Send  basic command usage information
			ShellBot.sendMessage --reply_to_message_id "$message_message_id" --chat_id "$message_chat_id" --text '*Usage:*\n\n`/report <your_message_here>`\nor\n`!report <your_message_here>`' --parse_mode 'markdown'


			# Check if the commands "/report" and "!report" are followed by one or more character
		elif [[ "$message_text" =~ ^(\!report|/report).+$ ]]; then
			# Check if there is already a saved report with the same user ID
			if [ -f "$HOME/Unalix/Reports/$message_chat_id" ]; then
				ShellBot.sendMessage --reply_to_message_id "$message_message_id" --chat_id "$message_chat_id" --text "You have previously submitted a report. Wait for it to be viewed by an administrator or delete it using \`/delete_report_${message_chat_id[$id]}\` or \`!delete_report_${message_chat_id[$id]}\`." --parse_mode 'markdown'
			else
				# Save the report at "$HOME/Unalix/Reports/$message_chat_id"
				echo "$message_text" | sed -r 's/^(\!report|\/report)\s*//g' > "$HOME/Unalix/Reports/$message_chat_id" && ShellBot.sendMessage --reply_to_message_id "$message_message_id" --chat_id "$message_chat_id" --text 'Your report has been submitted.' || { ShellBot.sendMessage --reply_to_message_id "$message_message_id" --chat_id "$message_chat_id" --text 'An error occurred when trying to submit your report.'; }
				# Tell all bot administrators that a user has submitted a new report
				cd "$HOME/Unalix/Administrators"; ls | while read -r 'BotAdministrators'
				do
					ShellBot.sendMessage --chat_id "$BotAdministrators" --text "*An user has submitted the following report:*\n\n*User:*\n\n*Name:* \`${message_chat_first_name}\`\n*Username:* \`${message_chat_username}\`\n*Language:* \`${message_from_language_code}\`\n*User ID:* \`$message_from_id\`\n*Message ID:* \`${message_message_id}\`\n\n*Report:*\n\n\`$(cat "$HOME/Unalix/Reports/$message_chat_id")\`" --parse_mode 'markdown' || { ShellBot.sendMessage --chat_id "$BotAdministrators" --text "*An user has submitted the following report:*\n\n*User:*\n\n*Name:* \`${message_chat_first_name}\`\n*Username:* \`${message_chat_username}\`\n*Language:* \`${message_from_language_code}\`\n*User ID:* \`$message_from_id\`\n*Message ID:* \`${message_message_id}\`\n\n*Report:*\n\n\`The report was stored in "$HOME/Unalix/Reports/$message_chat_id")\`" --parse_mode 'markdown'; }
				done
			fi


		# The command "cmd" is used to execute commands inside the terminal where Unalix is running
		# Only administrators who have their user IDs saved in "$HOME/Unalix/Administrators" can use this command inside Telegram
		elif [[ "$message_text" =~ ^(\!cmd|/cmd)$ ]]; then
			# Send  basic command usage information
			ShellBot.sendMessage --reply_to_message_id "$message_message_id" --chat_id "$message_chat_id" --text '*Usage:*\n\n`/cmd <command>`\nor\n`!cmd <command>`' --parse_mode 'markdown'


		# Check if the command "/cmd" are followed by a command
		elif [[ "$message_text" =~ ^(\!cmd|/cmd).+$ ]]; then
			# Verify if the user is an administrator of the bot
			if [ -f "$HOME/Unalix/Administrators/$message_chat_id" ]; then
				# Set the filename for all command outputs
				CommandOutput="$HOME/Unalix/TempFiles/Output-$(tr -dc A-Za-z0-9_ < /dev/urandom | head -c 10).txt"
				# Remove the "!cmd" or "/cmd" strings 
				CommandToRun="$(echo "$message_text" | sed -r 's/^(\!cmd|\/cmd)\s*//g; s/\\*//g; s/"\""/'\''/g')"
				# Run the command in a subshell
				timeout -s '9' '25' bash -c "$CommandToRun" 2>>"$CommandOutput" 1>>"$CommandOutput"; ExitStatus="$?"
				# Send the output to the Telegram API
				[[ "$(cat "$CommandOutput" | wc -w)" != '0' ]] && ShellBot.sendMessage --reply_to_message_id "$message_message_id" --chat_id "$message_chat_id" --text "*OUTPUT (stdout and stderr):*\n\n\`$(cat $CommandOutput)\`" --parse_mode 'markdown' || { ShellBot.sendMessage --reply_to_message_id "$message_message_id" --chat_id "$message_chat_id" --text "The command was executed, but no standard output (stdout) or standard error (stderr) could be captured. The exit status code was \`$ExitStatus\`." --parse_mode 'markdown'; }
				# Remove the file with the output and unset variables
				cleanup
			else
				ShellBot.sendMessage --reply_to_message_id "$message_message_id" --chat_id "$message_chat_id" --text 'You are not an administrator of this bot, so you are not authorized to execute this command.'
			fi


		# The command "delete_report" allows users to delete a report that was previously submitted.
		elif [[ "$message_text" =~ ^(/delete_report|\!delete_report)$ ]]; then
			# Send  basic command usage information
			ShellBot.sendMessage --reply_to_message_id "$message_message_id" --chat_id "$message_chat_id" --text "*Usage:*\n\n\`/delete_report_$message_from_id\`\nor\n\`!delete_report_$message_from_id\`" --parse_mode 'markdown'


			# Check if the command "delete_report_" are followed by a user ID
		elif [[ "$message_text" =~ ^(/delete_report_|\!delete_report_).{6,}$ ]]; then
			# Remove the strings "/delete_report_" and "!delete_report_" from the variable
			DeletionRequest_ID=$(echo "$message_text" | sed -r 's/^(\/delete_report_|\!delete_report_)//g')
			# Check if the request ID and the the user ID are the same
			if [ "$DeletionRequest_ID" = "$message_from_id" ]; then
				# Check for any reports previously submitted by the user
				if [ -f "$HOME/Unalix/Reports/$message_from_id" ]; then
					# Delete the report submitted by the user and send the result to the Telegram API
					rm -f "$HOME/Unalix/Reports/$message_from_id" && ShellBot.sendMessage --reply_to_message_id "$message_message_id" --chat_id "$message_chat_id" --text 'Your report has been successfully deleted.' || { ShellBot.sendMessage --reply_to_message_id "$message_message_id" --chat_id "$message_chat_id" --text 'An error occurred while trying to delete your report.'; }
				else
					ShellBot.sendMessage --reply_to_message_id "$message_message_id" --chat_id "$message_chat_id" --text 'You have no saved reports.'
				fi

			# Bot administrators have privileges, so they can delete reports submitted by other users
			# The check below is basically the same as the previous one, but instead of verifying if the report deletion ID and the user ID that have requested the deletion are the same, it checks if the user ID requesting the deletion is in the list of bot administrators.

			# Check if the used are a valid administrator
			elif [ -f "$HOME/Unalix/Administrators/$message_from_id" ]; then
				# Check for any reports previously submitted by the specified user ID
				if [ -f "$HOME/Unalix/Reports/$DeletionRequest_ID" ]; then
					# Delete the report and send the result to the Telegram API
					rm -f "$HOME/Unalix/Reports/$DeletionRequest_ID" && ShellBot.sendMessage --reply_to_message_id "$message_message_id" --chat_id "$message_chat_id" --text 'This report has been successfully deleted.' || { ShellBot.sendMessage --reply_to_message_id "$message_message_id" --chat_id "$message_chat_id" --text 'An error occurred while trying to delete this report.'; }
				else
					ShellBot.sendMessage --reply_to_message_id "$message_message_id" --chat_id "$message_chat_id" --text "There are no reports associated with this user ID (\`$DeletionRequest_ID\`)." --parse_mode 'markdown'
				fi
			else
				ShellBot.sendMessage --reply_to_message_id "$message_message_id" --chat_id "$message_chat_id" --text 'You have attempted to delete a report that does not belong to your user ID. Only bot administrators can perform this action.'
			fi
		elif [[ "$message_text" =~ ^(\!ip|/ip)$ ]]; then
			ShellBot.sendMessage --reply_to_message_id "$message_message_id" --chat_id "$message_chat_id" --text '*Usage:*\n\n`/ip <example.com|172.217.2.206|2607:f8b0:4006:819::200e>`\nor\n`!ip <example.com|172.217.2.206|2607:f8b0:4006:819::200e>`' --parse_mode 'markdown'
		elif [[ "$message_text" =~ ^(\!ip|/ip).+$ ]]; then
			UserQuery=$(echo "$message_text" | sed -r 's/(\/ip|\!ip)\s+//g; s/^.*:\/\/|\/.*//g; s/:\d{1,5}.*//g') && MakeDNSTest
		else
			ShellBot.sendMessage --reply_to_message_id "$message_message_id" --chat_id "$message_chat_id" --text 'Send me any link that starts with `http://` or `https://`.' --parse_mode 'markdown' 2>/dev/null
		fi
	) &
	done
done
