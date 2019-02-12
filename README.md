# RSA NetWitness Lua Whitelist Windows 10 Connection Endpoints
whitelist Windows 10 traffic parser and script
uploaded 2 files

Pulls from this API
https://github.com/MicrosoftDocs/windows-itpro-docs/tree/master/windows/privacy

## Script
python script to connect to the GitHub site above to collect the data to generate the content for the whitelists

## Content
output of the script is a parser
### Lua Parser
this contains the hostnames that are returned from the GitHub site and added to the lua parser automatically


the data is intended to be written to the filter key in Netwitness that can be used to provide a filter point for data to include or exclude different data from investigations.

the parser includes 3 potential values for the hostnames added:
-whitelist
-windows10
-<service or endpoint>.
