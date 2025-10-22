local ngx = ngx
local ngx_var = ngx.var
local ngx_req = ngx.req
local ngx_log = ngx.log
local ngx_ERR = ngx.ERR
local ngx_WARN = ngx.WARN

local kwaap = {
    _VERSION = "1.22.0", -- version in X.Y.Z format. Check hybrid-mode compatibility requirements.
}
kwaap.__index = kwaap

local function traceback ()
  local level = 1
  local str_trace = " "
  while true do
    local info = debug.getinfo(level, "Snl")
    if not info then break end
    if info.what == "C" then   -- is a C function?
      str_trace = str_trace .. string.format("{%d: C function}", level)
    else   -- a Lua function
      str_trace = str_trace .. string.format("{%d: [%s]: %d: %s}", level, info.short_src, info.currentline, info.name)
    end
    level = level + 1
  end
  return str_trace
end

function kwaap.rewrite()
    local http = require("resty.http")
    local partial_header_name=tostring(ngx_var.partial_header_name) or "x-envoy-auth-partial-body"
    local original_content_length_header_name=tostring(ngx_var.original_content_length_header_name) or "x-enforcerdd-original-content-length"
    local max_req_bytes = tonumber(ngx_var.max_req_bytes) or 10240
    local fail_open = ngx_var.fail_open  or "true"
    local enforcer_service_address = ngx_var.enforcer_service_address or "waas-enforcer.kwaf.svc.cluster.local"
    local enforcer_service_port = ngx_var.enforcer_service_port or 80
    local lua_socket_connect_timeout = tonumber(ngx_var.lua_socket_connect_timeout) or 1000
    local lua_socket_read_timeout = tonumber(ngx_var.lua_socket_read_timeout) or 1000
    local lua_socket_send_timeout = tonumber(ngx_var.lua_socket_send_timeout) or 1000
    local inspection_fail_error_code = (tonumber(ngx_var.inspection_fail_error_code)) or 406
    local inspection_fail_reason = ngx_var.inspection_fail_reason or ""
    local cloud_env = ngx_var.cloud_env or "local"
    local ngx_ctx= ngx.ctx
    local log_debug = (ngx_var.debug == "true") or false
    local keepalive = not((ngx_var.keepalive == "false") or false)
    local function log(msg, log_level)
      if log_debug then
          local str_trace = traceback()
          if not log_level then
              log_level = ngx_ERR
          end
          ngx_log(log_level, msg .. str_trace)
      end
    end
    local function read_body()
      local read_length = "*all"
      ngx_req.read_body()
      local r_body = ngx_req.get_body_data()
      if r_body == nil then
        local file = ngx_req.get_body_file()
        if file then
          local file_handle = io.open(file, "rb")
          if not file_handle then
            log("could not obtain file handle")
          else
            local req_body = file_handle:read(read_length)
            file_handle:close()
            r_body = req_body
          end
        else 
          log("get_body_file returned nil")
        end
      end
    
      if r_body == nil then
        log("nil body")
      else
        log("body size " .. #r_body, ngx_WARN)
      end
      return r_body
    end
    local kwaap_plugin = ngx_var.kwaap_plugin
    if kwaap_plugin ~= "on" then
      log("plugin kwaap is disabled and = " .. tostring(kwaap_plugin), ngx_WARN)
      return
    end
    local kwaf_fail_close = false
    if fail_open then
        kwaf_fail_close = (fail_open ~= "true")
    end
    local r_method = ngx_req.get_method()
    local r_request_uri = ngx_var.request_uri
    local r_headers = ngx_req.get_headers()
    if cloud_env == "aws" then
      r_headers["xff"] = ngx_var.xff
    end
    local r_content_length = ngx_var.http_content_length
    if r_content_length == nil then
      r_content_length = 0
    else
      r_content_length=tonumber(r_content_length)
    end 
    local enforcer_content_length = tonumber("0")
    local max_enforcer_content_length = max_req_bytes
    if r_content_length > max_enforcer_content_length then
      log("request bigger than max_enforcer_content_length (" .. tostring(r_content_length) .. "), will send only max_enforcer_content_length (" .. tostring(max_enforcer_content_length) .. ")", ngx_WARN)
      enforcer_content_length = max_enforcer_content_length
      r_headers[partial_header_name] = "true"
      r_headers[original_content_length_header_name] = r_content_length
    else
      enforcer_content_length=r_content_length
      r_headers[partial_header_name] = "false"
    end
    r_headers["content-length"] = tostring(enforcer_content_length)
    local r_body = ""
    if r_content_length > 0 then
      r_body = read_body()
    end
    if r_content_length > enforcer_content_length then
      r_body = r_body:sub(1, max_enforcer_content_length)
    end
    local httpc = http.new()
    httpc:set_timeouts(lua_socket_connect_timeout, lua_socket_send_timeout, lua_socket_read_timeout)
    local params = {}
    params.method = r_method
    params.body = r_body
    params.headers = r_headers
    params.keepalive = keepalive
    params.query  = ngx_var.query_string
    local i, j = string.find(r_request_uri, '?', 1, true)
    if i ~= nil then
      params.query = string.sub(r_request_uri, i)
      r_request_uri = string.sub(r_request_uri, 1, i-1)
    end
    local res, err = httpc:request_uri("http://" .. enforcer_service_address .. ":" .. enforcer_service_port .. r_request_uri, params)
    -- log( "request sent to enforcer [" .. r_request_uri .. " query  " .. tostring(params.query)   .."] ")

    if not res then
        if err == "timeout" then
          log("timeout connecting to enforcer. fail open = " .. tostring(fail_open))
          if kwaf_fail_close == false then
              return
          else
              ngx.status= inspection_fail_error_code
              ngx.say(inspection_fail_reason)
              ngx.exit(ngx.HTTP_OK)
          end
        end
        log("enforcer request failed: " .. err .. " when fail closed = " .. tostring(kwaf_fail_close))
        if kwaf_fail_close == false then
          return
        else
          ngx.status= inspection_fail_error_code
          ngx.say(inspection_fail_reason)
          ngx.exit(ngx.HTTP_OK)
        end
    else
      local s_status = res.status
      local s_headers = res.headers
      local s_body   = res.body

      if s_status == ngx.HTTP_FORBIDDEN then
        ngx.status = s_status
        for k, v in pairs(s_headers) do
            ngx.header[k] = v
        end
        ngx.say(s_body)
        return
      else
        -- Manage response logging
        if s_headers['x-enforcer-descriptors'] then
          local enforcer_descriptors = s_headers['x-enforcer-descriptors']
          ngx_ctx.enforcer_descriptors = enforcer_descriptors
        end
        return
      end
    end
end

function kwaap.log()
  local ngx = ngx
  local ngx_var = ngx.var
  local ngx_ctx = ngx.ctx
  local log_debug = (ngx_var.debug == "true") or false
  local response_status = tostring(ngx.status)
  local response_key = tostring(ngx_var.rater_response_tracking_key) or "response_code"
  local enforcer_descriptors = ngx_ctx.enforcer_descriptors
  local function log(msg, log_level)
    if log_debug then
        local str_trace = traceback()
        if not log_level then
            log_level = ngx_ERR
        end
        ngx_log(log_level, msg .. str_trace)
    end
  end
  
  local kwaap_plugin = ngx_var.kwaap_plugin
  if kwaap_plugin ~= "on" then
    log("plugin kwaap is disabled and = " .. tostring(kwaap_plugin), ngx_WARN)
    return
  end
  -- construct the custom access log message in
  -- the Lua variable "msg"
  if enforcer_descriptors then
      local flush_limit = tonumber(ngx_var.flush_limit) or 5
      local periodic_flush = tonumber(ngx_var.periodic_flush) or nil
      local host = ngx_var.rater_service_address
      local port = tonumber(ngx_var.rater_service_port) or 9929
      -- init configuration for response tracking
      local kwaap_logger = require("kwaap_logger")
      local pb_path = ngx_var.pb_path or "/etc/nginx/lua/otel_proto.pb"

      if not kwaap_logger.initted() then
        log("loading user config, periodic flush is " .. tostring(periodic_flush))
        local ok, err = kwaap_logger.init{
            host = host,
            port = port,
            flush_limit = flush_limit,
            drop_limit = 100,
            otel_proto_path = pb_path,
            periodic_flush = periodic_flush,
        }
        if not ok then
            log("failed to initialize kwaf logger: " .. err)
            return
        end
      end
      -- Build message
      local response_status_table = {}
      response_status_table["key"] = response_key
      response_status_table["value"] = { string_value = response_status }

      local enforcer_descriptors_table = {}
      enforcer_descriptors_table["key"] = "descriptors"
      enforcer_descriptors_table["value"] = { string_value = enforcer_descriptors}
      local msg = { enforcer_descriptors_table, response_status_table }
      local ok, err = kwaap_logger.logging(msg)
      if not ok  then
          log("failed to log message: " .. err)
          return
      end
  end
end
return kwaap