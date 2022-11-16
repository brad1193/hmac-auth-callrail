local decode_base64 = ngx.decode_base64
local encode_base64 = ngx.encode_base64
local hmac_sha1 = ngx.hmac_sha1
local kong_request = kong.request
local kong_response = kong.response

local function get_signature()
  local signature = kong_request.get_header('signature')
  if signature == nil then
    return kong_response.exit(403, "Forbidden")
  end
  return signature
end

local function generate_sha1_hmac(body, secret)
  local hmac = encode_base64(hmac_sha1(secret, body))
  return hmac
end

local function validate_signature(hmac)
  local signature = get_signature()
  return hmac == signature
end

local _M = {}

function _M.execute(conf)
  local body = kong_request.get_raw_body()
  local hmac = generate_sha1_hmac(body, conf.secret)
  local ok = validate_signature(hmac)
  if not ok then
    return kong_response.exit(401, "Unauthorized")
  end
end

return _M
