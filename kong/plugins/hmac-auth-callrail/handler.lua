local access = require "kong.plugins.hmac-auth-callrail.access"
local kong_meta = require "kong.meta"


local HMACAuthHandler = {
  VERSION = kong_meta.version,
  PRIORITY = 0,
}


function HMACAuthHandler:access(conf)
  access.execute(conf)
end


return HMACAuthHandler
