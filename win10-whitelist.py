#!/usr/bin/env python

import urllib.request
import re
from datetime import datetime

#variables for output control
#master whitelist name
feed_col_whitelist = "whitelist"
#product whitelist value
feed_col_whitelist_name = "windows10_connection"

#generate parser date version
now = datetime.now()
parser_gen_date = now.strftime("%Y.%m.%d")
parser_date_string='local parserVersion = "' + parser_gen_date + '"\n'

#name of parser
parser_name='lua_whitelist_win10'
parser_name_string='local parserName = "' + parser_name + '"\n'

lua_script_pre='''
local win10 = nw.createParser(parserName, parserName .. ": " .. parserVersion)
-- this shows in the mouseover

nw.logDebug(parserName .. " " .. parserVersion)

local summary = {["parserName"] = parserName, ["parserVersion"] = parserVersion}

summary.parserDetails = [=[
https://riptutorial.com/lua/example/20315/lua-pattern-matching
from here
https://github.com/MicrosoftDocs/windows-itpro-docs/tree/master/windows/privacy

marks Windows 10 Connection Endpoint traffic as whitelisted
looks for hostname and domains in the following keys 
    alias.host
    host.src
    host.dst
    fqdn

then marks them in the following keys
filter
with whitelist meta
    whitelist                        - for global whitelisting
    windows10_connection             - for office365 specifics
]=]

summary.liveTags = {
    "whitelist",
}

--[[
    VERSION
        2018.08.11.1  eric.partington@rsa.com  11.1.0.0-8987.3  UDM
        2018.10.10.2  eric.partington@rsa.com  updated to work with different lua import list
        
    OPTIONS
        none

    IMPLEMENTATION
        Relies on meta registered by other parsers.

    TODO
        none?
--]]

--local debugParser = require('debugParser')

local lookup_list = ({
'''

lua_script_post='''
})

win10:setKeys({
	nwlanguagekey.create("filter", nwtypes.Text),
	nwlanguagekey.create("feed.name", nwtypes.Text),
})

function win10:onHost(idx, host)
    --lowercase the incoming value
    host = string.lower(host)
	--nw.logInfo(parserName .. " matching: " .. host)
    
    for domain in pairs(lookup_list) do
   
        -- replace the * wildcard in the list with .*
        domain_esc = string.gsub(domain, "%*", "%.%*")
        -- for hostnames that have a - in them we need to escape that with %% so the end string ends %- (first % escapes on replace)
        domain_esc = string.gsub(domain_esc, "%-", "%%-")
        -- for hostnames that have a . in them we need to escape that with %% so the end string ends %. (first % escapes on replace)
        domain_esc = string.gsub(domain_esc, "%.", "%%.")
        
        --print("domain after gsub for * " .. domain)
        --nw.logInfo(parserName .. " matching: " .. host)
        --nw.logInfo(parserName .. " matching with: " .. domain_esc)
        
        if string.match(host, "^"..domain_esc.."$") then
            -- QUESTIONS::
            -- should the list match both specific and wildcard matches?
            -- should the list only match specific first and then do wildcard only if no match
            -- if above is correct, list should be ordered specific first then wildcard so that first match exits the loop
            
            --print(domain_esc)
            --nw.logInfo(parserName .. " matched: " .. host)
            
            for index,list_value in ipairs(lookup_list[domain]) do
                -- this is the counter in the table
                --print(index)
                -- this is the value from the table
                --print(list_value)
                --nw.logInfo(parserName .. " wrote: " .. list_value)
                
                nw.createMeta(self.keys["filter"], list_value)
            end
            
            -- finally aftger writing all the values from the matched value update the  feed.name meta
            -- this throws an error oddly
            nw.createMeta(self.keys["feed.name"], parserName)
        
        --else
            --nw.logInfo(parserName .. " notmatched: " .. host)
        end
    end
    --end
end

win10:setCallbacks({
    [nwlanguagekey.create("alias.host")] = win10.onHost,
    [nwlanguagekey.create("fqdn")] = win10.onHost,
    [nwlanguagekey.create("host.src")] = win10.onHost,
    [nwlanguagekey.create("host.dst")] = win10.onHost
})
'''

#these are the pages that refer to network connections
#windows-endpoints-1709-non-enterprise-editions.md
#windows-endpoints-1809-non-enterprise-editions.md
#windows-endpoints-1803-non-enterprise-editions.md

pages_non_enterprise=['windows-endpoints-1709-non-enterprise-editions.md', 'windows-endpoints-1809-non-enterprise-editions.md', 'windows-endpoints-1803-non-enterprise-editions.md']
pages_enterprise=['manage-windows-1809-endpoints.md','manage-windows-1709-endpoints.md','manage-windows-1803-endpoints.md']

def f12(seq):
    # Raymond Hettinger
    # https://twitter.com/raymondh/status/944125570534621185
    return list(dict.fromkeys(seq))
    
# helper to call the webservice and parse the response
def webApiGet(instanceName):
    ws = "https://raw.githubusercontent.com/MicrosoftDocs/windows-itpro-docs/master/windows/privacy/"
    requestPath = ws + instanceName
    #print(requestPath)
    request = urllib.request.Request(requestPath)
    with urllib.request.urlopen(request) as response:
        return response.read()
   
#urls list from the md pages that are then sorted and uniqued   
urls=[]   

for pagename in pages_enterprise:
    endpointSetsBytes = webApiGet(pagename)
    print(pagename)
    print('\n')
    #iterate over the list of page names to get and parse 
    #endpointSetsBytes = webApiGet('windows-endpoints-1709-non-enterprise-editions.md')
    endpointSets = endpointSetsBytes.decode("utf8")
    #print(endpointSets)

    #split on the new line in the page list
    for word in endpointSets.split('\n'):
        word  =  word.strip()
        #print(word)
        if re.match(r'^\|',word):
            #print(word)
            #look for lines that start with |space word space|
            #extract the hostname part between the |
            
            matched=re.search(r'\|\s+([\*a-z][\.a-z][a-z\.\-\_*]+)\s+\|$',word)
            
            if matched:
                #build the parser list contents with filter lines
                
                #try to filter out **Destination** or ---
                urlList="[\""+matched.group(1)+"\"] = {\""+feed_col_whitelist+"\",\""+feed_col_whitelist_name+"\"},"
                urls.append(urlList)
                #print(matched.group(1))

#end for loop

for pagename in pages_non_enterprise:
    endpointSetsBytes = webApiGet(pagename)
    print(pagename)
    print('\n')
    #iterate over the list of page names to get and parse 
    #endpointSetsBytes = webApiGet('windows-endpoints-1709-non-enterprise-editions.md')
    endpointSets = endpointSetsBytes.decode("utf8")
    #print(endpointSets)

    #split on the new line in the page list
    for word in endpointSets.split('\n'):
        word  =  word.strip()
        if re.match(r'^\|',word):
            #look for lines that start with |space word space|
            #extract the hostname part between the |
            matched=re.search(r'^\|\s+([*\w][\.\w][\w\.\-\_*]+)\s+\|',word)
            if matched:
                #build the parser list contents with filter lines
                
                #try to filter out **Destination** or ---
                urlList="[\""+matched.group(1)+"\"] = {\""+feed_col_whitelist+"\",\""+feed_col_whitelist_name+"\"},"
                urls.append(urlList)
                #print(matched.group(1))

#end for loop
           
#at the end sort and unique the list
#print('\r\n'.join(sorted(f12(urls))))

#join the list to a string
lua_match_list='\n'.join(sorted(f12(urls)))
#trim the trailing , from the last line
lua_match_list = lua_match_list[:-1]

#print(lua_script_pre)
#print(lua_match_list)
#print(lua_script_post)

with open(parser_name + '.lua', 'w') as f:
    f.write(parser_date_string + parser_name_string + lua_script_pre + lua_match_list + lua_script_post)