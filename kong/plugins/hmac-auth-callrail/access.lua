    local decode_base64 = ngx.decode_base64
    local encode_base64 = ngx.encode_base64
    local hmac_sha1 = ngx.hmac_sha1
    local kong_request = kong.request
    local SIGNATURE_NOT_VALID = "HMAC signature cannot be verified"

    local function get_signature()
      local signature, err = kong_request.get_header('signature')
      if not signature then
        return false, { status = 401, message = "Unauthorized" }
      end
      if err then
        kong.log.debug(err)
      end
      return signature
    end

    local function generate_sha1_hmac(body, secret)
      kong.log.debug("Data: "..body)
      local hmac = encode_base64(hmac_sha1(secret, body))
      return hmac
    end

    local function validate_signature(hmac)
      local signature = get_signature()
      kong.log.debug("HMAC: "..hmac)
      kong.log.debug("Signature: "..signature)
      if not hmac == signature then
        return false, { status = 401, message = SIGNATURE_NOT_VALID }
      end
    end

    local _M = {}

    function _M.execute(conf)
      local body = kong_request.get_raw_body()
      local hmac = generate_sha1_hmac(body, conf.secret)
      local ok, err = validate_signature(hmac)
      if not ok then
        kong.log.debug(err)
        return false, { status = 401, message = SIGNATURE_NOT_VALID }
      end
      return kong.response.error(err.status, err.message)
    end

    return _M
  handler.lua: |
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
