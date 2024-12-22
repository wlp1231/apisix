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
local core = require("apisix.core")
local utils = require("apisix.admin.utils")
local apisix_ssl = require("apisix.ssl")
local apisix_consumer = require("apisix.consumer")
local setmetatable = setmetatable
local tostring = tostring
local ipairs = ipairs
local type = type


local _M = {
    need_v3_filter = true,
}


local mt = {
    __index = _M
}


local no_id_res = {
    consumers = true,
    plugin_metadata = true
}


local function split_typ_and_id(id, sub_path)
    local uri_segs = core.utils.split_uri(sub_path)
    local typ = id
    local id = nil
    if #uri_segs > 0 then
        id = uri_segs[1]
    end
    return typ, id
end


local function check_forbidden_properties(conf, forbidden_properties)
    local not_allow_properties = "the property is forbidden: "

    if conf then
        for _, v in ipairs(forbidden_properties) do
            if conf[v] then
                return not_allow_properties .. " " .. v
            end
        end

        if conf.upstream then
            for _, v in ipairs(forbidden_properties) do
                if conf.upstream[v] then
                    return not_allow_properties .. " upstream." .. v
                end
            end
        end

        if conf.plugins then
            for _, v in ipairs(forbidden_properties) do
                if conf.plugins[v] then
                    return not_allow_properties .. " plugins." .. v
                end
            end
        end
    end

    return nil
end


-- id：资源的标识符，可能由请求路径或配置字段提供。
-- conf：待校验的配置对象。
-- need_id：布尔值，指示是否要求配置中必须包含 id。
-- typ：资源的类型信息，主要针对特殊资源如 secrets。
-- allow_time：布尔值，指示是否允许配置中包含时间戳字段（create_time 和 update_time）。
function _M:check_conf(id, conf, need_id, typ, allow_time)
    -- 如果当前资源类型为 secrets，则将 id 扩展为 typ/id 的形式
    if self.name == "secrets" then
        id = typ .. "/" .. id
    end
    -- 检查传入的配置对象 conf 是否为空。
    if not conf then
        return nil, {error_msg = "missing configurations"}
    end

    -- 如果当前资源类型在 no_id_res 中，则不需要 id，跳过校验
    if not no_id_res[self.name] then
        id = id or conf.id
        if need_id and not id then
            return nil, {error_msg = "missing ".. self.kind .. " id"}
        end

        if not need_id and id then
            return nil, {error_msg = "wrong ".. self.kind .. " id, do not need it"}
        end

        if need_id and conf.id and tostring(conf.id) ~= tostring(id) then
            return nil, {error_msg = "wrong ".. self.kind .. " id"}
        end

        conf.id = id
    end

    -- 校验时间戳字段
    if not allow_time then
        local forbidden_properties = {"create_time", "update_time"}
        local err = check_forbidden_properties(conf, forbidden_properties)
        if err then
            return nil, {error_msg = err}
        end
    end

    core.log.info("conf  : ", core.json.delay_encode(conf))

    -- check the resource own rules
    if self.name ~= "secrets" then
        core.log.info("schema: ", core.json.delay_encode(self.schema))
    end

    --  调用资源特定规则校验
    local ok, err = self.checker(id, conf, need_id, self.schema, typ)

    if not ok then
        return ok, err
    else
        if no_id_res[self.name] then
            return ok
        else
            return need_id and id or true
        end
    end
end


function _M:get(id, conf, sub_path)
    if core.table.array_find(self.unsupported_methods, "get") then
        return 405, {error_msg = "not supported `GET` method for " .. self.kind}
    end

    local key = "/" .. self.name
    local typ = nil
    if self.name == "secrets" then
        key = key .. "/"
        typ, id = split_typ_and_id(id, sub_path)
    end

    if id then
        if self.name == "secrets" then
            key = key .. typ
        end
        key = key .. "/" .. id
    end

    -- some resources(consumers) have sub resources(credentials),
    -- the key format of sub resources will differ from the main resource
    if self.get_resource_etcd_key then
        key = self.get_resource_etcd_key(id, conf, sub_path)
    end

    local res, err = core.etcd.get(key, not id)
    if not res then
        core.log.error("failed to get ", self.kind, "[", key, "] from etcd: ", err)
        return 503, {error_msg = err}
    end

    if self.name == "ssls" then
        -- not return private key for security
        if res.body and res.body.node and res.body.node.value then
            res.body.node.value.key = nil
        end
    end

    -- consumers etcd range response will include credentials, so need to filter out them
    if self.name == "consumers" and res.body.list then
        res.body.list = apisix_consumer.filter_consumers_list(res.body.list)
        res.body.total = #res.body.list
    end

    utils.fix_count(res.body, id)
    return res.status, res.body
end


function _M:post(id, conf, sub_path, args)
    if core.table.array_find(self.unsupported_methods, "post") then
        return 405, {error_msg = "not supported `POST` method for " .. self.kind}
    end

    local id, err = self:check_conf(id, conf, false)
    if not id then
        return 400, err
    end

    if self.name == "ssls" then
        -- encrypt private key
        conf.key = apisix_ssl.aes_encrypt_pkey(conf.key)

        if conf.keys then
            for i = 1, #conf.keys do
                conf.keys[i] = apisix_ssl.aes_encrypt_pkey(conf.keys[i])
            end
        end
    end

    local key = "/" .. self.name
    utils.inject_timestamp(conf)

    local ttl = nil
    if args then
        ttl = args.ttl
    end

    local res, err = core.etcd.push(key, conf, ttl)
    if not res then
        core.log.error("failed to post ", self.kind, "[", key, "] to etcd: ", err)
        return 503, {error_msg = err}
    end

    return res.status, res.body
end


function _M:put(id, conf, sub_path, args)
    -- 检查是否支持 PUT 方法
    if core.table.array_find(self.unsupported_methods, "put") then
        return 405, {error_msg = "not supported `PUT` method for " .. self.kind}
    end

    -- /初始化关键路径变量
    -- key：基础路径，用于存储资源的 etcd 键，初始值为 / 加资源名（如 /routes）。
    -- typ：类型变量，初始化为空，用于特定资源类型的额外处理
    local key = "/" .. self.name
    local typ = nil
    if self.name == "secrets" then
        typ, id = split_typ_and_id(id, sub_path)
        key = key .. "/" .. typ
    end

    -- 校验配置
    -- 判断该资源是否需要 id
    local need_id = not no_id_res[self.name]
    -- 校验传入的 conf（配置）是否合法
    local ok, err = self:check_conf(id, conf, need_id, typ)
    if not ok then
        return 400, err
    end

    -- 对于非 secrets 资源，将校验函数返回的值赋给 id
    if self.name ~= "secrets" then
        id = ok
    end

    -- 对 ssls 资源的私钥 key 和多私钥列表 keys 进行加密
    if self.name == "ssls" then
        -- encrypt private key
        conf.key = apisix_ssl.aes_encrypt_pkey(conf.key)

        if conf.keys then
            for i = 1, #conf.keys do
                conf.keys[i] = apisix_ssl.aes_encrypt_pkey(conf.keys[i])
            end
        end
    end

    -- 将资源 ID 添加到 key，生成资源的完整 etcd 路径
    key = key .. "/" .. id

    -- 如果定义了 get_resource_etcd_key 方法，使用它生成 etcd 键。
    if self.get_resource_etcd_key then
        key = self.get_resource_etcd_key(id, conf, sub_path, args)
    end

    -- 特殊处理 credentials 资源
    if self.name == "credentials" then
        local consumer_key = apisix_consumer.get_consumer_key_from_credential_key(key)
        local res, err = core.etcd.get(consumer_key, false)
        if not res then
            return 503, {error_msg = err}
        end
        if res.status == 404 then
            return res.status, {error_msg = "consumer not found"}
        end
        if res.status ~= 200 then
            core.log.debug("failed to get consumer for the credential, credential key: ", key,
                ", consumer key: ", consumer_key, ", res.status: ", res.status)
            return res.status, {error_msg = "failed to get the consumer"}
        end
    end

    --  配置时间修改
    if self.name ~= "plugin_metadata" then
        local ok, err = utils.inject_conf_with_prev_conf(self.kind, key, conf)
        if not ok then
            return 503, {error_msg = err}
        end
    else
        -- 特殊处理，直接将 id 添加到配置 conf。
        conf.id = id
    end

    -- 从 args 中提取 TTL（存活时间），用于设置 etcd 键的过期时间
    local ttl = nil
    if args then
        ttl = args.ttl
    end

    -- 更新 etcd
    -- core.etcd.set：将 key 和 conf 写入 etcd，支持 TTL。
    -- 错误处理：如果写入失败，记录日志并返回 HTTP 状态码 503（服务不可用）
    local res, err = core.etcd.set(key, conf, ttl)
    if not res then
        core.log.error("failed to put ", self.kind, "[", key, "] to etcd: ", err)
        return 503, {error_msg = err}
    end

    return res.status, res.body
end

-- Keep the unused conf to make the args list consistent with other methods
function _M:delete(id, conf, sub_path, uri_args)
    if core.table.array_find(self.unsupported_methods, "delete") then
        return 405, {error_msg = "not supported `DELETE` method for " .. self.kind}
    end

    local key = "/" .. self.name
    local typ = nil
    if self.name == "secrets" then
        typ, id = split_typ_and_id(id, sub_path)
    end

    if not id then
        return 400, {error_msg = "missing " .. self.kind .. " id"}
    end

    -- core.log.error("failed to delete ", self.kind, "[", key, "] in etcd: ", err)

    if self.name == "secrets" then
        key = key .. "/" .. typ
    end

    key = key .. "/" .. id

    if self.get_resource_etcd_key then
        key = self.get_resource_etcd_key(id, conf, sub_path, uri_args)
    end

    if self.delete_checker and uri_args.force ~= "true" then
        local code, err = self.delete_checker(id)
        if err then
            return code, err
        end
    end

    if self.name == "consumers" then
        local res, err = core.etcd.rmdir(key .. "/credentials/")
        if not res then
            return 503, {error_msg = err}
        end
    end

    local res, err = core.etcd.delete(key)
    if not res then
        core.log.error("failed to delete ", self.kind, "[", key, "] in etcd: ", err)
        return 503, {error_msg = err}
    end

    return res.status, res.body
end


function _M:patch(id, conf, sub_path, args)
    if core.table.array_find(self.unsupported_methods, "patch") then
        return 405, {error_msg = "not supported `PATCH` method for " .. self.kind}
    end

    local key = "/" .. self.name
    local typ = nil
    if self.name == "secrets" then
        local uri_segs = core.utils.split_uri(sub_path)
        if #uri_segs < 1 then
            return 400, {error_msg = "no secret id"}
        end
        typ = id
        id = uri_segs[1]
        sub_path = core.table.concat(uri_segs, "/", 2)
    end

    if not id then
        return 400, {error_msg = "missing " .. self.kind .. " id"}
    end

    if self.name == "secrets" then
        key = key .. "/" .. typ
    end

    key = key .. "/" .. id

    if conf == nil then
        return 400, {error_msg = "missing new configuration"}
    end

    if not sub_path or sub_path == "" then
        if type(conf) ~= "table"  then
            return 400, {error_msg = "invalid configuration"}
        end
    end

    local res_old, err = core.etcd.get(key)
    if not res_old then
        core.log.error("failed to get ", self.kind, " [", key, "] in etcd: ", err)
        return 503, {error_msg = err}
    end

    if res_old.status ~= 200 then
        return res_old.status, res_old.body
    end
    core.log.info("key: ", key, " old value: ", core.json.delay_encode(res_old, true))

    local node_value = res_old.body.node.value
    local modified_index = res_old.body.node.modifiedIndex

    if sub_path and sub_path ~= "" then
        if self.name == "ssls" then
            if sub_path == "key" then
                conf = apisix_ssl.aes_encrypt_pkey(conf)
            elseif sub_path == "keys" then
                for i = 1, #conf do
                    conf[i] = apisix_ssl.aes_encrypt_pkey(conf[i])
                end
            end
        end
        local code, err, node_val = core.table.patch(node_value, sub_path, conf)
        node_value = node_val
        if code then
            return code, {error_msg = err}
        end
        utils.inject_timestamp(node_value, nil, true)
    else
        if self.name == "ssls" then
            if conf.key then
                conf.key = apisix_ssl.aes_encrypt_pkey(conf.key)
            end

            if conf.keys then
                for i = 1, #conf.keys do
                    conf.keys[i] = apisix_ssl.aes_encrypt_pkey(conf.keys[i])
                end
            end
        end
        node_value = core.table.merge(node_value, conf)
        utils.inject_timestamp(node_value, nil, conf)
    end

    core.log.info("new conf: ", core.json.delay_encode(node_value, true))

    local ok, err = self:check_conf(id, node_value, true, typ, true)
    if not ok then
        return 400, err
    end

    local ttl = nil
    if args then
        ttl = args.ttl
    end

    local res, err = core.etcd.atomic_set(key, node_value, ttl, modified_index)
    if not res then
        core.log.error("failed to set new ", self.kind, "[", key, "] to etcd: ", err)
        return 503, {error_msg = err}
    end

    return res.status, res.body
end

-- setmetatable 是 Lua 元表机制的核心，用于为普通表赋予新的行为或功能。
-- 通过配合 __index, __newindex, __add 等元方法，可以实现继承、运算符重载、自定义输出等高级特性
-- mt.__index = _M：为新对象设定默认的字段查找表 _M，即模块本身
function _M.new(opt)
    return setmetatable(opt, mt)
end


return _M
