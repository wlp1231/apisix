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
local http_route = require("apisix.http.route")
local apisix_upstream = require("apisix.upstream")
local core    = require("apisix.core")
local str_lower = string.lower
local ipairs  = ipairs


local _M = {version = 0.3}


local function filter(route)
    -- 将原始的 modifiedIndex 存储到 orig_modifiedIndex 中，保留该路由规则的初始版本号。
    route.orig_modifiedIndex = route.modifiedIndex

    -- 初始化 has_domain 属性，标记路由中是否包含域名配置
    route.has_domain = false
    -- 每个路由规则的实际配置信息通常存储在 value 字段中
    if not route.value then
        return
    end

    -- 将 host 或 hosts 转换为小写格式
    if route.value.host then
        route.value.host = str_lower(route.value.host)
    elseif route.value.hosts then
        for i, v in ipairs(route.value.hosts) do
            route.value.hosts[i] = str_lower(v)
        end
    end

    -- 对路由中的 upstream（上游配置）进行处理和过滤
    apisix_upstream.filter_upstream(route.value.upstream, route)

    core.log.info("filter route: ", core.json.delay_encode(route, true))
end


-- attach common methods if the router doesn't provide its custom implementation
local function attach_http_router_common_methods(http_router)
    if http_router.routes == nil then
        http_router.routes = function ()
            if not http_router.user_routes then
                return nil, nil
            end

            local user_routes = http_router.user_routes
            return user_routes.values, user_routes.conf_version
        end
    end

    -- 附加初始化函数
    if http_router.init_worker == nil then
        http_router.init_worker = function (filter)
            http_router.user_routes = http_route.init_worker(filter)
        end
    end
end

-- 在 HTTP 工作线程初始化时加载路由器、配置模块并执行必要的初始化逻辑
function _M.http_init_worker()
    -- 用于读取本地配置文件
    local conf = core.config.local_conf()
    -- 默认使用 Radix Tree（基数树）实现 HTTP 路由
    local router_http_name = "radixtree_uri"
    -- 默认使用 Radix Tree 实现基于 SNI（Server Name Indication）的 SSL 路由
    local router_ssl_name = "radixtree_sni"

    -- 从配置文件中读取用户指定的路由器
    if conf and conf.apisix and conf.apisix.router then
        router_http_name = conf.apisix.router.http or router_http_name
        router_ssl_name = conf.apisix.router.ssl or router_ssl_name
    end

    -- local router_http = require("apisix.http.router.radixtree_uri")
    -- 动态加载对应的 HTTP 路由器模块
    local router_http = require("apisix.http.router." .. router_http_name)
    -- 将一些通用方法附加到路由器对象上
    attach_http_router_common_methods(router_http)
    -- 调用 HTTP 路由器的初始化函数 init_worker，传递参数 filter（用于过滤或操作路由规则）
    router_http.init_worker(filter)
    -- 将 HTTP 路由器对象存储在 _M 表中，供其他模块使用
    _M.router_http = router_http

    -- 动态加载对应的 SSL 路由器模块，例如 radixtree_sni 对应 apisix.ssl.router.radixtree_sni
    local router_ssl = require("apisix.ssl.router." .. router_ssl_name)
    -- 调用 SSL 路由器的初始化函数。
    router_ssl.init_worker()
    -- 将 SSL 路由器对象存储在 _M 表中，供其他模块使用
    _M.router_ssl = router_ssl

    -- 加载 apisix.api_router 模块并存储在 _M.api 中。
    _M.api = require("apisix.api_router")
end


function _M.stream_init_worker()
    local router_ssl_name = "radixtree_sni"

    local router_stream = require("apisix.stream.router.ip_port")
    router_stream.stream_init_worker(filter)
    _M.router_stream = router_stream

    local router_ssl = require("apisix.ssl.router." .. router_ssl_name)
    router_ssl.init_worker()
    _M.router_ssl = router_ssl
end


function _M.ssls()
    return _M.router_ssl.ssls()
end

function _M.http_routes()
    if not _M.router_http then
        return nil, nil
    end
    return _M.router_http.routes()
end

function _M.stream_routes()
    -- maybe it's not inited.
    if not _M.router_stream then
        return nil, nil
    end
    return _M.router_stream.routes()
end


-- for test
_M.filter_test = filter


return _M
