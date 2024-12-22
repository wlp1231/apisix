--
-- Licensed to the Apache Software Foundation (ASF) under one or more
-- contributor license agreements.  See the NOTICE file distributed with
-- this work for additional information regarding copyright ownership.
-- The ASF licenses this file to You under the Apache License, Version 2.0
-- (the "License"); you may not use this file except in compliance with
-- the License.  You may obtain a copy of the License at
--
--     http://www.apache.org/licenses/LICENSE-2.0
--
-- Unless required by applicable law or agreed to in writing, software
-- distributed under the License is distributed on an "AS IS" BASIS,
-- WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
-- See the License for the specific language governing permissions and
-- limitations under the License.
--
local require = require
local core = require("apisix.core")
local base_router = require("apisix.http.route")
local get_services = require("apisix.http.service").services
local cached_router_version
local cached_service_version


local _M = {version = 0.2}


    local uri_routes = {}
    local uri_router
function _M.match(api_ctx)
    -- 获取当前的用户路由配置
    local user_routes = _M.user_routes
    -- 获取服务版本
    local _, service_version = get_services()
    -- 检查缓存的路由版本和服务版本是否一致
    if not cached_router_version or cached_router_version ~= user_routes.conf_version
    
        or not cached_service_version or cached_service_version ~= service_version
    then
        -- 如果版本不匹配，创建一个新的 Radixtree 路由树
        uri_router = base_router.create_radixtree_uri_router(user_routes.values,
                                                             uri_routes, false)
        -- 更新缓存的路由版本和服务版本
        cached_router_version = user_routes.conf_version
        cached_service_version = service_version
    end

    -- 如果没有成功创建 URI 路由树，记录错误日志并返回 true
    if not uri_router then
        core.log.error("failed to fetch valid `uri` router: ")
        return true
    end

    -- 如果路由树创建成功，调用 matching 函数进行实际的路由匹配
    return _M.matching(api_ctx)
end


function _M.matching(api_ctx)
    core.log.info("route match mode: radixtree_uri")
    return base_router.match_uri(uri_router, api_ctx)
end


return _M
