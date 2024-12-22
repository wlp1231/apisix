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

--- Json schema validation module.
--
-- @module core.schema

local jsonschema = require('jsonschema')
local lrucache = require("apisix.core.lrucache")
-- 缓存实例：创建一个 LRU 缓存，用来存储生成的验证器对象（validator）
local cached_validator = lrucache.new({count = 1000, ttl = 0})
local pcall = pcall

local _M = {
    version = 0.3,

    TYPE_CONSUMER = 1,
    TYPE_METADATA = 2,
}


-- 使用 jsonschema.generate_validator 方法根据传入的 schema 生成一个验证器函数。
-- 用 pcall 包裹，捕获可能的错误。
local function create_validator(schema)
    -- local code = jsonschema.generate_validator_code(schema, opts)
    -- local file2=io.output("/tmp/2.txt")
    -- file2:write(code)
    -- file2:close()
    local ok, res = pcall(jsonschema.generate_validator, schema)
    if ok then
        return res
    end

    return nil, res -- error message
end


-- 尝试从缓存中获取指定 Schema 的验证器。
-- 如果缓存中不存在，调用 create_validator 生成新的验证器并加入缓存。
local function get_validator(schema)
    local validator, err = cached_validator(schema, nil,
                                create_validator, schema)

    if not validator then
        return nil, err
    end

    return validator, nil
end

function _M.check(schema, json)
    -- 调用 get_validator(schema) 尝试获取 Schema 对应的验证器
    local validator, err = get_validator(schema)

    if not validator then
        return false, err
    end

    -- 如果验证器存在，调用 validator(json) 执行校验
    return validator(json)
end

_M.valid = get_validator

return _M
