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
local radixtree = require("resty.radixtree")
local router = require("apisix.utils.router")
local service_fetch = require("apisix.http.service").get
local core = require("apisix.core")
local expr = require("resty.expr.v1")
local plugin_checker = require("apisix.plugin").plugin_checker
local event = require("apisix.core.event")
local ipairs = ipairs
local type = type
local error = error
local loadstring = loadstring


local _M = {}

-- 将路由配置转换为一个基于 Radix Tree
-- 遍历路由配置 (routes)，过滤无效或禁用的路由。
-- 处理路由中的 hosts、filter_func 和 service_id 等字段。
-- 将路由规则转换为符合 Radix Tree 格式的表 (uri_routes)。
-- 创建并返回一个基于 Radix Tree 的高效路由器实例。
function _M.create_radixtree_uri_router(routes, uri_routes, with_parameter)
    routes = routes or {}

    -- 清空 uri_routes 表
    core.table.clear(uri_routes)

    -- 遍历 routes 数组中的每一项路由对象 route
    for _, route in ipairs(routes) do
        if type(route) == "table" then
            -- 检查路由的 status 是否为 0。如果是 0，说明该路由被禁用了
            local status = core.table.try_read_attr(route, "value", "status")
            -- check the status
            if status and status == 0 then
                goto CONTINUE
            end

            -- 如果路由对象 route.value 中定义了 filter_func（即过滤函数），会通过 loadstring 动态加载并执行该函数。
            -- filter_func 用于在匹配路由时对请求进行自定义处理。如果加载失败，记录错误并跳过当前路由。
            local filter_fun, err
            if route.value.filter_func then
                filter_fun, err = loadstring(
                                        "return " .. route.value.filter_func,
                                        "router#" .. route.value.id)
                if not filter_fun then
                    core.log.error("failed to load filter function: ", err,
                                   " route id: ", route.value.id)
                    goto CONTINUE
                end

                filter_fun = filter_fun()
            end

            -- 检查路由的 hosts 字段。如果该字段为空且路由配置中有 service_id，
            -- 则会根据 service_id 从服务配置中获取主机（hosts）信息
            local hosts = route.value.hosts or route.value.host
            if not hosts and route.value.service_id then
                local service = service_fetch(route.value.service_id)
                if not service then
                    core.log.error("failed to fetch service configuration by ",
                                   "id: ", route.value.service_id)
                    -- we keep the behavior that missing service won't affect the route matching
                else
                    hosts = service.value.hosts
                end
            end

            core.log.info("insert uri route: ",
                          core.json.delay_encode(route.value, true))
            -- 将过滤后的路由数据添加到 uri_routes 表中
            core.table.insert(uri_routes, {
                paths = route.value.uris or route.value.uri,
                methods = route.value.methods,
                priority = route.value.priority,
                hosts = hosts,
                remote_addrs = route.value.remote_addrs
                               or route.value.remote_addr,
                vars = route.value.vars,
                filter_fun = filter_fun,
                handler = function (api_ctx, match_opts)
                    api_ctx.matched_params = nil
                    api_ctx.matched_route = route
                    api_ctx.curr_req_matched = match_opts.matched
                end
            })

            ::CONTINUE::
        end
    end

    -- 路由规则完成后，推送一个事件 BUILD_ROUTER，并记录日志，显示路由信息
    event.push(event.CONST.BUILD_ROUTER, routes)
    core.log.info("route items: ", core.json.delay_encode(uri_routes, true))

    -- 根据 with_parameter 的值决定使用带参数的 Radix Tree 路由器
    if with_parameter then
        return radixtree.new(uri_routes)
    else
        return router.new(uri_routes)
    end
end


function _M.match_uri(uri_router, api_ctx)
    -- 使用 core.tablepool.fetch 创建一个新的 Lua 表 match_opts
    local match_opts = core.tablepool.fetch("route_match_opts", 0, 4)

    -- match_opts 是匹配选项表，设置了一些用于路由匹配的关键参数：
    -- method：HTTP 请求方法，如 GET、POST。
    -- host：请求的主机名（Host）。
    -- remote_addr：客户端的 IP 地址。
    -- vars：请求相关的变量表，包含许多上下文信息（如 uri、args 等）。
    -- matched：存储匹配结果的表，从 tablepool 中创建，用于记录匹配到的路由信息
    match_opts.method = api_ctx.var.request_method
    match_opts.host = api_ctx.var.host
    match_opts.remote_addr = api_ctx.var.remote_addr
    match_opts.vars = api_ctx.var
    match_opts.matched = core.tablepool.fetch("matched_route_record", 0, 4)

    -- uri_router:dispatch 是 Radix Tree 路由器的核心方法，用于实际执行路由匹配
    local ok = uri_router:dispatch(api_ctx.var.uri, match_opts, api_ctx, match_opts)
    -- 调用 core.tablepool.release 将 match_opts 表归还到表池，供后续复用。
    core.tablepool.release("route_match_opts", match_opts)
    return ok
end


-- additional check for synced route configuration, run after schema check
local function check_route(route)
    local ok, err = plugin_checker(route)
    if not ok then
        return nil, err
    end

    if route.vars then
        ok, err = expr.new(route.vars)
        if not ok then
            return nil, "failed to validate the 'vars' expression: " .. err
        end
    end

    return true
end

-- _M.user_routes 的初始化
function _M.init_worker(filter)
    -- 获取路由表信息
    local user_routes, err = core.config.new("/routes", {
            automatic = true,
            item_schema = core.schema.route,
            checker = check_route,
            filter = filter,
        })
    if not user_routes then
        error("failed to create etcd instance for fetching /routes : " .. err)
    end

    return user_routes
end


return _M
