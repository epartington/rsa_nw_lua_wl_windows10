local parserName = "lua_whitelist_win10"
-- this shows in the config screen
local parserVersion = "2019.01.15.3"

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
["*.*.akamai.net"] = {"whitelist","windows10_connection"},
["*.*.akamaiedge.net"] = {"whitelist","windows10_connection"},
["*.1.msftsrvcs.vo.llnwi.net"] = {"whitelist","windows10_connection"},
["*.a-msedge.net"] = {"whitelist","windows10_connection"},
["*.b.akamaiedge.net"] = {"whitelist","windows10_connection"},
["*.blob.core.windows.net"] = {"whitelist","windows10_connection"},
["*.c-msedge.net"] = {"whitelist","windows10_connection"},
["*.delivery.dsp.mp.microsoft.com.nsatc.net"] = {"whitelist","windows10_connection"},
["*.dl.delivery.mp.microsoft.com"] = {"whitelist","windows10_connection"},
["*.dscb1.akamaiedge.net"] = {"whitelist","windows10_connection"},
["*.dscd.akamai.net"] = {"whitelist","windows10_connection"},
["*.dspb.akamaiedge.net"] = {"whitelist","windows10_connection"},
["*.dspg.akamaiedge.net"] = {"whitelist","windows10_connection"},
["*.dspw65.akamai.net"] = {"whitelist","windows10_connection"},
["*.e-msedge.net"] = {"whitelist","windows10_connection"},
["*.g.akamai.net"] = {"whitelist","windows10_connection"},
["*.g.akamaiedge.net"] = {"whitelist","windows10_connection"},
["*.hwcdn.net"] = {"whitelist","windows10_connection"},
["*.l.windowsupdate.com"] = {"whitelist","windows10_connection"},
["*.login.msa.akadns6.net"] = {"whitelist","windows10_connection"},
["*.m1-msedge.net"] = {"whitelist","windows10_connection"},
["*.prod.do.dsp.mp.microsoft.com"] = {"whitelist","windows10_connection"},
["*.s-msedge.net"] = {"whitelist","windows10_connection"},
["*.search.msn.com"] = {"whitelist","windows10_connection"},
["*.telecommand.telemetry.microsoft.com.akadns.net"] = {"whitelist","windows10_connection"},
["*.telemetry.microsoft.com"] = {"whitelist","windows10_connection"},
["*.tlu.dl.delivery.mp.microsoft.com*"] = {"whitelist","windows10_connection"},
["*.tlu.dl.delivery.mp.microsoft.com.c.footprint.net"] = {"whitelist","windows10_connection"},
["*.wac.edgecastcdn.net"] = {"whitelist","windows10_connection"},
["*.wac.phicdn.net"] = {"whitelist","windows10_connection"},
["*.windowsupdate.com"] = {"whitelist","windows10_connection"},
["*.windowsupdate.com*"] = {"whitelist","windows10_connection"},
["*.wns.windows.com"] = {"whitelist","windows10_connection"},
["*g.akamaiedge.net"] = {"whitelist","windows10_connection"},
["*geo-prod.do.dsp.mp.microsoft.com"] = {"whitelist","windows10_connection"},
["*geo-prod.dodsp.mp.microsoft.com.nsatc.net"] = {"whitelist","windows10_connection"},
["*prod.do.dsp.mp.microsoft.com"] = {"whitelist","windows10_connection"},
["*prod.do.dsp.mp.microsoft.com.nsatc.net"] = {"whitelist","windows10_connection"},
["*wac.edgecastcdn.net"] = {"whitelist","windows10_connection"},
["*wac.phicdn.net"] = {"whitelist","windows10_connection"},
["2.dl.delivery.mp.microsoft.com"] = {"whitelist","windows10_connection"},
["2.tlu.dl.delivery.mp.microsoft.com"] = {"whitelist","windows10_connection"},
["3.dl.delivery.mp.microsoft.com"] = {"whitelist","windows10_connection"},
["3.dl.delivery.mp.microsoft.com.c.footprint.net"] = {"whitelist","windows10_connection"},
["3.tlu.dl.delivery.mp.microsoft.com"] = {"whitelist","windows10_connection"},
["3.tlu.dl.delivery.mp.microsoft.com.c.footprint.net"] = {"whitelist","windows10_connection"},
["arc.msn.com"] = {"whitelist","windows10_connection"},
["arc.msn.com.nsatc.net"] = {"whitelist","windows10_connection"},
["ars.smartscreen.microsoft.com"] = {"whitelist","windows10_connection"},
["au.download.windowsupdate.com"] = {"whitelist","windows10_connection"},
["au.download.windowsupdate.com*"] = {"whitelist","windows10_connection"},
["auth.gfx.ms"] = {"whitelist","windows10_connection"},
["blob.weather.microsoft.com"] = {"whitelist","windows10_connection"},
["browser.pipe.aria.microsoft.com"] = {"whitelist","windows10_connection"},
["candycrushsoda.king.com"] = {"whitelist","windows10_connection"},
["cdn.content.prod.cms.msn.com"] = {"whitelist","windows10_connection"},
["cdn.onenote.net"] = {"whitelist","windows10_connection"},
["cds.*.hwcdn.net"] = {"whitelist","windows10_connection"},
["ceuswatcab01.blob.core.windows.net"] = {"whitelist","windows10_connection"},
["ceuswatcab02.blob.core.windows.net"] = {"whitelist","windows10_connection"},
["client-office365-tas.msedge.net"] = {"whitelist","windows10_connection"},
["client-office365-tas.msedge.net*"] = {"whitelist","windows10_connection"},
["cloudtile.photos.microsoft.com.akadns.net"] = {"whitelist","windows10_connection"},
["co4.telecommand.telemetry.microsoft.com.akadns.net"] = {"whitelist","windows10_connection"},
["config.edge.skype.com"] = {"whitelist","windows10_connection"},
["cs12.wpc.v0cdn.net"] = {"whitelist","windows10_connection"},
["ctldl.windowsupdate.com"] = {"whitelist","windows10_connection"},
["cy2.displaycatalog.md.mp.microsoft.com.akadns.net"] = {"whitelist","windows10_connection"},
["cy2.licensing.md.mp.microsoft.com.akadns.net"] = {"whitelist","windows10_connection"},
["cy2.purchase.md.mp.microsoft.com.akadns.net"] = {"whitelist","windows10_connection"},
["cy2.settings.data.microsoft.com.akadns.net"] = {"whitelist","windows10_connection"},
["cy2.vortex.data.microsoft.com.akadns.net"] = {"whitelist","windows10_connection"},
["definitionupdates.microsoft.com"] = {"whitelist","windows10_connection"},
["displaycatalog.mp.microsoft.com"] = {"whitelist","windows10_connection"},
["displaycatalog.mp.microsoft.com*"] = {"whitelist","windows10_connection"},
["dl.delivery.mp.microsoft.com"] = {"whitelist","windows10_connection"},
["dm3p.wns.notify.windows.com.akadns.net"] = {"whitelist","windows10_connection"},
["dmd.metaservices.microsoft.com"] = {"whitelist","windows10_connection"},
["dmd.metaservices.microsoft.com.akadns.net"] = {"whitelist","windows10_connection"},
["download.windowsupdate.com"] = {"whitelist","windows10_connection"},
["dual-a-0001.a-msedge.net"] = {"whitelist","windows10_connection"},
["eaus2watcab01.blob.core.windows.net"] = {"whitelist","windows10_connection"},
["eaus2watcab02.blob.core.windows.net"] = {"whitelist","windows10_connection"},
["emdl.ws.microsoft.com"] = {"whitelist","windows10_connection"},
["evoke-windowsservices-tas.msedge.net"] = {"whitelist","windows10_connection"},
["fe2.update.microsoft.com"] = {"whitelist","windows10_connection"},
["fe2.update.microsoft.com*"] = {"whitelist","windows10_connection"},
["fe2.update.microsoft.com.nsatc.net"] = {"whitelist","windows10_connection"},
["fe3.delivery.dsp.mp.microsoft.com.nsatc.net"] = {"whitelist","windows10_connection"},
["fe3.delivery.mp.microsoft.com"] = {"whitelist","windows10_connection"},
["fg.download.windowsupdate.com.c.footprint.net"] = {"whitelist","windows10_connection"},
["flightingservicewus.cloudapp.net"] = {"whitelist","windows10_connection"},
["fp.msedge.net"] = {"whitelist","windows10_connection"},
["fs.microsoft.com"] = {"whitelist","windows10_connection"},
["g.live.com"] = {"whitelist","windows10_connection"},
["g.msn.com"] = {"whitelist","windows10_connection"},
["g.msn.com.nsatc.net"] = {"whitelist","windows10_connection"},
["geo-prod.do.dsp.mp.microsoft.com"] = {"whitelist","windows10_connection"},
["geo-prod.do.dsp.mp.microsoft.com.nsatc.net"] = {"whitelist","windows10_connection"},
["geo-prod.dodsp.mp.microsoft.com.nsatc.net"] = {"whitelist","windows10_connection"},
["geover-prod.do.dsp.mp.microsoft.com"] = {"whitelist","windows10_connection"},
["go.microsoft.com"] = {"whitelist","windows10_connection"},
["gpla1.wac.v2cdn.net"] = {"whitelist","windows10_connection"},
["img-prod-cms-rt-microsoft-com.akamaized.net"] = {"whitelist","windows10_connection"},
["inference.location.live.net"] = {"whitelist","windows10_connection"},
["int.whiteboard.microsoft.com"] = {"whitelist","windows10_connection"},
["ip5.afdorigin-prod-am02.afdogw.com"] = {"whitelist","windows10_connection"},
["ipv4.login.msa.akadns6.net"] = {"whitelist","windows10_connection"},
["licensing.mp.microsoft.com"] = {"whitelist","windows10_connection"},
["location-inference-westus.cloudapp.net"] = {"whitelist","windows10_connection"},
["login.live.com"] = {"whitelist","windows10_connection"},
["mediaredirect.microsoft.com"] = {"whitelist","windows10_connection"},
["modern.watson.data.microsoft.com.akadns.net"] = {"whitelist","windows10_connection"},
["msftsrvcs.vo.llnwd.net"] = {"whitelist","windows10_connection"},
["msnbot-*.search.msn.com"] = {"whitelist","windows10_connection"},
["msnbot-65-52-108-198.search.msn.com"] = {"whitelist","windows10_connection"},
["nexusrules.officeapps.live.com"] = {"whitelist","windows10_connection"},
["ocos-office365-s2s.msedge.net*"] = {"whitelist","windows10_connection"},
["ocsp.digicert.com*"] = {"whitelist","windows10_connection"},
["oem.twimg.com"] = {"whitelist","windows10_connection"},
["officeclient.microsoft.com"] = {"whitelist","windows10_connection"},
["oneclient.sfx.ms"] = {"whitelist","windows10_connection"},
["oneclient.sfx.ms*"] = {"whitelist","windows10_connection"},
["onecollector.cloudapp.aria.akadns.net"] = {"whitelist","windows10_connection"},
["peer1-wst.msedge.net"] = {"whitelist","windows10_connection"},
["peer4-wst.msedge.net"] = {"whitelist","windows10_connection"},
["prod.nexusrules.live.com.akadns.net"] = {"whitelist","windows10_connection"},
["pti.store.microsoft.com"] = {"whitelist","windows10_connection"},
["pti.store.microsoft.com.unistore.akadns.net"] = {"whitelist","windows10_connection"},
["purchase.mp.microsoft.com"] = {"whitelist","windows10_connection"},
["query.prod.cms.rt.microsoft.com"] = {"whitelist","windows10_connection"},
["query.prod.cms.rt.microsoft.com*"] = {"whitelist","windows10_connection"},
["ris.api.iris.microsoft.com"] = {"whitelist","windows10_connection"},
["ris.api.iris.microsoft.com*"] = {"whitelist","windows10_connection"},
["ris.api.iris.microsoft.com.akadns.net"] = {"whitelist","windows10_connection"},
["settings-win.data.microsoft.com"] = {"whitelist","windows10_connection"},
["settings.data.microsoft.com"] = {"whitelist","windows10_connection"},
["sls.update.microsoft.com"] = {"whitelist","windows10_connection"},
["sls.update.microsoft.com*"] = {"whitelist","windows10_connection"},
["sls.update.microsoft.com.nsatc.net"] = {"whitelist","windows10_connection"},
["star-mini.c10r.facebook.com"] = {"whitelist","windows10_connection"},
["store-images.microsoft.com"] = {"whitelist","windows10_connection"},
["store-images.s-microsoft.com"] = {"whitelist","windows10_connection"},
["storecatalogrevocation.storequality.microsoft.com"] = {"whitelist","windows10_connection"},
["storecatalogrevocation.storequality.microsoft.com*"] = {"whitelist","windows10_connection"},
["storeedgefd.dsx.mp.microsoft.com"] = {"whitelist","windows10_connection"},
["storeedgefd.dsx.mp.microsoft.com*"] = {"whitelist","windows10_connection"},
["tile-service.weather.microsoft.com"] = {"whitelist","windows10_connection"},
["tile-service.weather.microsoft.com*"] = {"whitelist","windows10_connection"},
["tsfe.trafficshaping.dsp.mp.microsoft.com"] = {"whitelist","windows10_connection"},
["unitedstates.smartscreen-prod.microsoft.com"] = {"whitelist","windows10_connection"},
["us.configsvc1.live.com.akadns.net"] = {"whitelist","windows10_connection"},
["v10.vortex-win.data.microsoft.com"] = {"whitelist","windows10_connection"},
["vip5.afdorigin-prod-am02.afdogw.com"] = {"whitelist","windows10_connection"},
["vip5.afdorigin-prod-ch02.afdogw.com"] = {"whitelist","windows10_connection"},
["wallet-frontend-prod-westus.cloudapp.net"] = {"whitelist","windows10_connection"},
["wallet.microsoft.com"] = {"whitelist","windows10_connection"},
["watson.telemetry.microsoft.com"] = {"whitelist","windows10_connection"},
["wbd.ms"] = {"whitelist","windows10_connection"},
["wd-prod-cp-us-east-2-fe.eastus.cloudapp.azure.com"] = {"whitelist","windows10_connection"},
["wd-prod-cp-us-west-3-fe.westus.cloudapp.azure.com"] = {"whitelist","windows10_connection"},
["wdcp.microsoft.akadns.net"] = {"whitelist","windows10_connection"},
["wdcp.microsoft.com"] = {"whitelist","windows10_connection"},
["weus2watcab01.blob.core.windows.net"] = {"whitelist","windows10_connection"},
["weus2watcab02.blob.core.windows.net"] = {"whitelist","windows10_connection"},
["whiteboard.microsoft.com"] = {"whitelist","windows10_connection"},
["whiteboard.ms"] = {"whitelist","windows10_connection"},
["wildcard.twimg.com"] = {"whitelist","windows10_connection"},
["www.bing.com"] = {"whitelist","windows10_connection"},
["www.facebook.com"] = {"whitelist","windows10_connection"}
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

--return summary