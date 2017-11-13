package = "kong-plugin-jwt-verify"
version = "1.0-1"
source = {
  url = "TBD"
}
description = {
  summary = "A Kong plugin that will verify JWT claims as request headers",
  license = "MIT"
}
dependencies = {
  "lua ~> 5.1"
}
build = {
  type = "builtin",
  modules = {
    ["kong.plugins.jwt-verify.handler"] = "kong/plugins/jwt-verify/handler.lua",
    ["kong.plugins.jwt-verify.schema"]  = "kong/plugins/jwt-verify/schema.lua"
  }
}