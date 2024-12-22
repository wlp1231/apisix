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
local core    = require("apisix.core")
local ngx_time = ngx.time
local tonumber = tonumber
local ipairs = ipairs
local pairs = pairs


local _M = {}

-- 确保配置中 create_time 和 update_time 的正确性
local function inject_timestamp(conf, prev_conf, patch_conf)
    if not conf.create_time then
        if prev_conf and (prev_conf.node or prev_conf.list).value.create_time then
            conf.create_time = (prev_conf.node or prev_conf.list).value.create_time
        else
            -- As we don't know existent data's create_time, we have to pretend
            -- they are created now.
            conf.create_time = ngx_time()
        end
    end

    if not conf.update_time or
        -- For PATCH request, the modification is passed as 'patch_conf'
        -- If the sub path is used, the 'patch_conf' will be a placeholder `true`
        (patch_conf and (patch_conf == true or patch_conf.update_time == nil))
    then
        -- reset the update_time if:
        -- 1. PATCH request, with sub path
        -- 2. PATCH request, update_time not given
        -- 3. Other request, update_time not given
        conf.update_time = ngx_time()
    end
end
_M.inject_timestamp = inject_timestamp


function _M.inject_conf_with_prev_conf(kind, key, conf)
    --  从 etcd 获取资源
    local res, err = core.etcd.get(key)
    if not res or (res.status ~= 200 and res.status ~= 404) then
        core.log.error("failed to get " .. kind .. "[", key, "] from etcd: ", err or res.status)
        return nil, err
    end

    -- 根据状态码处理时间戳
    -- 根据资源是否存在（由 etcd 返回的状态码决定），对新配置 conf 注入时间戳。
    -- 调用 inject_timestamp 方法：
    -- 如果资源不存在（404），仅对新配置 conf 注入时间戳。
    -- 如果资源存在（200），结合现有配置 res.body 注入时间戳。
    if res.status == 404 then
        inject_timestamp(conf)
    else
        -- 时间戳注入的具体逻辑由 inject_timestamp 方法实现，通常包括：
        -- 添加创建时间（create_time）。
        -- 更新修改时间（update_time）。
        inject_timestamp(conf, res.body)
    end

    return true
end


-- fix_count makes the "count" field returned by etcd reasonable
function _M.fix_count(body, id)
    if body.count then
        if not id then
            -- remove the count of placeholder (init_dir)
            body.count = tonumber(body.count) - 1
        else
            body.count = tonumber(body.count)
        end
    end
end


function _M.decrypt_params(decrypt_func, body, schema_type)
    -- list
    if body.list then
        for _, route in ipairs(body.list) do
            if route.value and route.value.plugins then
                for name, conf in pairs(route.value.plugins) do
                    decrypt_func(name, conf, schema_type)
                end
            end
        end
        return
    end

    -- node
    local plugins = body.node and body.node.value
                    and body.node.value.plugins

    if plugins then
        for name, conf in pairs(plugins) do
            decrypt_func(name, conf, schema_type)
        end
    end

    -- metadata
    if schema_type == core.schema.TYPE_METADATA then
        local conf = body.node and body.node.value
        decrypt_func(conf.name, conf, schema_type)
    end
end

return _M
