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
local expr = require("resty.expr.v1")
local core = require("apisix.core")
local apisix_upstream = require("apisix.upstream")
local resource = require("apisix.admin.resource")
local schema_plugin = require("apisix.admin.plugins").check_schema
local type = type
local loadstring = loadstring


local function check_conf(id, conf, need_id, schema)
    -- 检查 host 和 hosts：
    -- 配置中只能包含 host 或 hosts，两者同时存在会导致冲突。
    -- 检查 remote_addr 和 remote_addrs：
    -- 类似逻辑，确保两者中只能存在一个字段。
    if conf.host and conf.hosts then
        return nil, {error_msg = "only one of host or hosts is allowed"}
    end

    if conf.remote_addr and conf.remote_addrs then
        return nil, {error_msg = "only one of remote_addr or remote_addrs is "
                                 .. "allowed"}
    end

    -- 使用 core.schema.check 方法，基于传入的 schema 校验 conf 是否符合定义
    local ok, err = core.schema.check(schema, conf)
    if not ok then
        return nil, {error_msg = "invalid configuration: " .. err}
    end

    -- 检查 upstream 字段：
    -- 如果 conf 中定义了 upstream，调用 apisix_upstream.check_upstream_conf 对其进行校验。
    local upstream_conf = conf.upstream
    if upstream_conf then
        local ok, err = apisix_upstream.check_upstream_conf(upstream_conf)
        if not ok then
            return nil, {error_msg = err}
        end
    end

    -- 获取 upstream_id 对应的配置：
    -- 从 etcd 中根据 upstream_id 获取对应的上游信息
    local upstream_id = conf.upstream_id
    if upstream_id then
        local key = "/upstreams/" .. upstream_id
        local res, err = core.etcd.get(key)
        if not res then
            return nil, {error_msg = "failed to fetch upstream info by "
                                     .. "upstream id [" .. upstream_id .. "]: "
                                     .. err}
        end

        if res.status ~= 200 then
            return nil, {error_msg = "failed to fetch upstream info by "
                                     .. "upstream id [" .. upstream_id .. "], "
                                     .. "response code: " .. res.status}
        end
    end

    -- 校验 service_id 和 plugin_config_id
    -- 类似于 upstream_id 的逻辑：
    local service_id = conf.service_id
    if service_id then
        local key = "/services/" .. service_id
        local res, err = core.etcd.get(key)
        if not res then
            return nil, {error_msg = "failed to fetch service info by "
                                     .. "service id [" .. service_id .. "]: "
                                     .. err}
        end

        if res.status ~= 200 then
            return nil, {error_msg = "failed to fetch service info by "
                                     .. "service id [" .. service_id .. "], "
                                     .. "response code: " .. res.status}
        end
    end

    local plugin_config_id = conf.plugin_config_id
    if plugin_config_id then
        local key = "/plugin_configs/" .. plugin_config_id
        local res, err = core.etcd.get(key)
        if not res then
            return nil, {error_msg = "failed to fetch plugin config info by "
                                     .. "plugin config id [" .. plugin_config_id .. "]: "
                                     .. err}
        end

        if res.status ~= 200 then
            return nil, {error_msg = "failed to fetch plugin config info by "
                                     .. "plugin config id [" .. plugin_config_id .. "], "
                                     .. "response code: " .. res.status}
        end
    end

    -- 使用 schema_plugin 校验 plugins 字段，确保插件配置的格式和规则正确。
    if conf.plugins then
        local ok, err = schema_plugin(conf.plugins)
        if not ok then
            return nil, {error_msg = err}
        end
    end

    -- 如果配置中定义了条件表达式（vars），使用 expr.new 对其进行校验
    if conf.vars then
        ok, err = expr.new(conf.vars)
        if not ok then
            return nil, {error_msg = "failed to validate the 'vars' expression: " .. err}
        end
    end

    -- 检查 filter_func：
    -- 使用 loadstring 将字符串解析为 Lua 函数。
    -- 检查解析结果是否为函数类型
    if conf.filter_func then
        local func, err = loadstring("return " .. conf.filter_func)
        if not func then
            return nil, {error_msg = "failed to load 'filter_func' string: "
                                     .. err}
        end

        if type(func()) ~= "function" then
            return nil, {error_msg = "'filter_func' should be a function"}
        end
    end

    -- 使用 loadstring 加载 Lua 脚本并验证结果是否为表
    if conf.script then
        local obj, err = loadstring(conf.script)
        if not obj then
            return nil, {error_msg = "failed to load 'script' string: "
                                     .. err}
        end

        if type(obj()) ~= "table" then
            return nil, {error_msg = "'script' should be a Lua object"}
        end
    end

    return true
end

-- 返回的对象继承了resource的get、put等方法
return resource.new({
    name = "routes",
    kind = "route",
    schema = core.schema.route,
    checker = check_conf
})
