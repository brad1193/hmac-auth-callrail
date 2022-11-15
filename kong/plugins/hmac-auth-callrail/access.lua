local decode_base64 = ngx.decode_base64
local hmac_sha1 = ngx.hmac_sha1
local kong_request = kong.request

local SIGNATURE_NOT_VALID = "HMAC signature cannot be verified"

local function get_signature()
  local signature, err = kong_request.get_header('signature')
  if err then
    kong.log.debug(err)
  end
  return signature
end

local function generate_sha1_hmac(body, secret)
  local body, err = kong_request.get_raw_body()
  local key = conf.secret
  if err then
    kong.log.debug(err)
  end
  return  hmac_sha1(secret, body)
end

local function validate_signature(hmac)
  local signature_1 = generate_sha1_hmac()
  local signature_2 = decode_base64(get_signature())
  if not signature_1 == signature_2
    return false, { status = 401, message = SIGNATURE_NOT_VALID }
  end
end

local _M = {}

function _M.execute(conf)
  local body = kong_request.get_raw_body()
  local hmac = generate_sha1_hmac(body, conf.secret)
  local ok, err = validate_signature(hmac)
end

return _M

