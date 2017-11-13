local BasePlugin = require "kong.plugins.base_plugin"
local responses = require "kong.tools.responses"
local jwt_decoder = require "kong.plugins.jwt.jwt_parser"
local req_set_header = ngx.req.set_header
local ngx_re_gmatch = ngx.re.gmatch
local dump = require 'serial'

local JwtVerifyHandler = BasePlugin:extend()

local function retrieve_token(request, conf)
  
  local authorization_header = request.get_headers()["authorization"]
  if authorization_header then
    local iterator, iter_err = ngx_re_gmatch(authorization_header, "\\s*[Bb]earer\\s+(.+)")
    if not iterator then
      return nil, iter_err
    end

    local m, err = iterator()
    if err then
      return nil, err
    end

    if m and #m > 0 then
      return m[1]
    end
  end
end

function JwtVerifyHandler:new()
  JwtVerifyHandler.super.new(self, "jwt-verify")
end

function JwtVerifyHandler:access(conf)

  JwtVerifyHandler.super.access(self)
  
  local token, err = retrieve_token(ngx.req, conf)
  if err then
    return responses.send_HTTP_INTERNAL_SERVER_ERROR(err)
  end

  if not token then
    local msg = "Token not signed with recognized ISS" 
    return responses.send_HTTP_UNAUTHORIZED("Missing token")
  end

  local jwt, err = jwt_decoder:new(token)
  if err then
    return responses.send_HTTP_INTERNAL_SERVER_ERROR()
  end

  local is_valid = false
  for i, iss_public_key in ipairs(conf.iss_public_keys) do
    
    local jwt_verify_result = jwt:verify_signature( iss_public_key )
    if jwt_verify_result == true then
      is_valid = true
      break
    end
  end

  ngx.log( ngx.DEBUG, "jwt_verify_result: " .. tostring(is_valid) )

  if not is_valid then
    local msg = "Token not signed with recognized ISS" 
    return responses.send_HTTP_UNAUTHORIZED(msg)
  end 
end

-- set the plugin priority, which determines plugin execution order
JwtVerifyHandler.PRIORITY = 1005

return JwtVerifyHandler
