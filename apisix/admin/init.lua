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
local get_uri_args = ngx.req.get_uri_args
local route = require("apisix.utils.router")
local plugin = require("apisix.plugin")
local v3_adapter = require("apisix.admin.v3_adapter")
local utils = require("apisix.admin.utils")
local ngx = ngx
local get_method = ngx.req.get_method
local ngx_time = ngx.time
local ngx_timer_at = ngx.timer.at
local ngx_worker_id = ngx.worker.id
local tonumber = tonumber
local tostring = tostring
local str_lower = string.lower
local reload_event = "/apisix/admin/plugins/reload"
local ipairs = ipairs
local error = error
local type = type


local events
local MAX_REQ_BODY = 1024 * 1024 * 1.5      -- 1.5 MiB


local viewer_methods = {
    get = true,
}


local resources = {
    routes          = require("apisix.admin.routes"),
    services        = require("apisix.admin.services"),
    upstreams       = require("apisix.admin.upstreams"),
    consumers       = require("apisix.admin.consumers"),
    credentials     = require("apisix.admin.credentials"),
    schema          = require("apisix.admin.schema"),
    ssls            = require("apisix.admin.ssl"),
    plugins         = require("apisix.admin.plugins"),
    protos          = require("apisix.admin.proto"),
    global_rules    = require("apisix.admin.global_rules"),
    stream_routes   = require("apisix.admin.stream_routes"),
    plugin_metadata = require("apisix.admin.plugin_metadata"),
    plugin_configs  = require("apisix.admin.plugin_config"),
    consumer_groups = require("apisix.admin.consumer_group"),
    secrets         = require("apisix.admin.secrets"),
}


local _M = {version = 0.4}
local router


local function check_token(ctx)
    local local_conf = core.config.local_conf()

    -- check if admin_key is required
    if local_conf.deployment.admin.admin_key_required == false then
        return true
    end

    local admin_key = core.table.try_read_attr(local_conf, "deployment", "admin", "admin_key")
    if not admin_key then
        return true
    end

    local req_token = ctx.var.arg_api_key or ctx.var.http_x_api_key
                      or ctx.var.cookie_x_api_key
    if not req_token then
        return false, "missing apikey"
    end

    local admin
    for i, row in ipairs(admin_key) do
        if req_token == row.key then
            admin = row
            break
        end
    end

    if not admin then
        return false, "wrong apikey"
    end

    if admin.role == "viewer" and
       not viewer_methods[str_lower(get_method())] then
        return false, "invalid method for role viewer"
    end

    return true
end

-- Set the `apictx` variable and check admin api token, if the check fails, the current
-- request will be interrupted and an error response will be returned.
--
-- NOTE: This is a higher wrapper for `check_token` function.
local function set_ctx_and_check_token()
    local api_ctx = {}
    core.ctx.set_vars_meta(api_ctx)
    ngx.ctx.api_ctx = api_ctx

    local ok, err = check_token(api_ctx)
    if not ok then
        core.log.warn("failed to check token: ", err)
        core.response.exit(401, { error_msg = "failed to check token", description = err })
    end
end


local function strip_etcd_resp(data)
    if type(data) == "table"
        and data.header ~= nil
        and data.header.revision ~= nil
        and data.header.raft_term ~= nil
    then
        -- strip etcd data
        data.header = nil
        data.responses = nil
        data.succeeded = nil

        if data.node then
            data.node.createdIndex = nil
            data.node.modifiedIndex = nil
        end

        data.count = nil
        data.more = nil
        data.prev_kvs = nil

        if data.deleted then
            -- We used to treat the type incorrectly. But for compatibility we follow
            -- the existing type.
            data.deleted = tostring(data.deleted)
        end
    end

    return data
end


local function head()
    core.response.exit(200)
end


local function run()
    -- 这个函数调用用于设置上下文和检查请求中的令牌（例如，JWT token）。它通常用于确保请求经过认证和授权
    set_ctx_and_check_token()

    -- 使用 core.utils.split_uri 函数将请求的 URI (ngx.var.uri) 按照 / 分割成多个部分，
    -- 并存储到 uri_segs 变量中。uri_segs 将包含 URI 的各个部分，
    -- 例如 /apisix/admin/schema/route 会被分割为 ["apisix", "admin", "schema", "route"]
    local uri_segs = core.utils.split_uri(ngx.var.uri)
    -- 记录日志，输出分割后的 URI 片段，使用 core.json.delay_encode 将 uri_segs 转换为 JSON 格式。
    core.log.info("uri: ", core.json.delay_encode(uri_segs))

    -- /apisix/admin/schema/route
    -- 解析 URI 片段
    -- 从 URI 中提取资源类型（seg_res）和资源 ID（seg_id）。比如，如果 URI 是 /apisix/admin/schema/route，seg_res 就是 schema，seg_id 就是 route。
    -- seg_sub_path 获取从第六个元素开始的 URI 子路径。
    local seg_res, seg_id = uri_segs[4], uri_segs[5]
    local seg_sub_path = core.table.concat(uri_segs, "/", 6)

    --  特殊路径处理
    -- 如果 URI 是 /apisix/admin/schema/plugins/limit-count，则将 seg_res 设置为 plugins，seg_id 设置为 limit-count，同时更新 seg_sub_path
    if seg_res == "schema" and seg_id == "plugins" then
        -- /apisix/admin/schema/plugins/limit-count
        seg_res, seg_id = uri_segs[5], uri_segs[6]
        seg_sub_path = core.table.concat(uri_segs, "/", 7)
    end

    -- 检查流模式 (stream_routes)
    -- 如果请求的资源是 stream_routes，会检查当前配置的 proxy_mode 是否允许流模式。如果不允许，则返回 400 错误并退出。
    if seg_res == "stream_routes" then
        local local_conf = core.config.local_conf()
        if local_conf.apisix.proxy_mode ~= "stream" and
           local_conf.apisix.proxy_mode ~= "http&stream" then
            core.log.warn("stream mode is disabled, can not add any stream ",
                          "routes")
            core.response.exit(400, {error_msg = "stream mode is disabled, " ..
                               "can not add stream routes"})
        end
    end

    -- 特殊处理 consumers 和 credentials
    -- 如果 URI 路径包含 consumers 和 credentials，则将 seg_sub_path 更新为新的路径，同时更新 seg_res 和 seg_id
    if seg_res == "consumers" and #uri_segs >= 6 and uri_segs[6] == "credentials" then
        seg_sub_path = seg_id .. "/" .. seg_sub_path
        seg_res = uri_segs[6]
        seg_id = uri_segs[7]
    end

    -- 检查资源
    -- 查找 seg_res 对应的资源。如果该资源不存在，返回 404 错误
    local resource = resources[seg_res]
    if not resource then
        core.response.exit(404, {error_msg = "Unsupported resource type: ".. seg_res})
    end

    -- 获取请求方法
    -- 获取请求的方法（如 GET、POST 等），并检查该方法是否在资源中定义。如果没有定义，返回 404 错误。
    local method = str_lower(get_method())
    if not resource[method] then
        core.response.exit(404, {error_msg = "not found"})
    end

    -- 获取请求体
    -- 获取请求体内容，最大读取字节数由 MAX_REQ_BODY 限制。如果获取失败，则记录错误并返回 400 错误。
    local req_body, err = core.request.get_body(MAX_REQ_BODY)
    if err then
        core.log.error("failed to read request body: ", err)
        core.response.exit(400, {error_msg = "invalid request body: " .. err})
    end

    -- 解码 JSON 请求体
    -- 如果请求体存在，尝试将其解码为 JSON。如果解码失败，则返回 400 错误
    if req_body then
        local data, err = core.json.decode(req_body)
        if err then
            core.log.error("invalid request body: ", req_body, " err: ", err)
            core.response.exit(400, {error_msg = "invalid request body: " .. err,
                                     req_body = req_body})
        end

        req_body = data
    end

    -- 检查 URI 参数中的 ttl
    -- 如果 URI 中包含 ttl 参数，检查其是否为数字。如果不是数字，则返回 400 错误。
    local uri_args = ngx.req.get_uri_args() or {}
    if uri_args.ttl then
        if not tonumber(uri_args.ttl) then
            core.response.exit(400, {error_msg = "invalid argument ttl: "
                                                 .. "should be a number"})
        end
    end

    -- 执行资源对应的操作
    -- 根据请求的资源类型和请求方法，调用对应的资源处理函数，并传入 seg_id、请求体、子路径和 URI 参数。
    local code, data
    if seg_res == "schema" or seg_res == "plugins" then
        code, data = resource[method](seg_id, req_body, seg_sub_path, uri_args)
    else
        -- resource自身、路由id、请求体、url子路径、url类型
        code, data = resource[method](resource, seg_id, req_body, seg_sub_path, uri_args)
    end

    -- 数据解密（可选）
    if code then
        -- 如果响应的数据需要加密（例如 plugin.enable_data_encryption 为 true），则对响应数据进行解密。
        if method == "get" and plugin.enable_data_encryption then
            if seg_res == "consumers" or seg_res == "credentials" then
                utils.decrypt_params(plugin.decrypt_conf, data, core.schema.TYPE_CONSUMER)
            elseif seg_res == "plugin_metadata" then
                utils.decrypt_params(plugin.decrypt_conf, data, core.schema.TYPE_METADATA)
            else
                utils.decrypt_params(plugin.decrypt_conf, data)
            end
        end

        -- 设置 API 版本和响应过滤
        if v3_adapter.enable_v3() then
            core.response.set_header("X-API-VERSION", "v3")
        else
            core.response.set_header("X-API-VERSION", "v2")
        end
        if resource.need_v3_filter then
            data = v3_adapter.filter(data)
        end

        -- 清理 Etcd 响应数据
        data = strip_etcd_resp(data)

        -- 发送响应
        core.response.exit(code, data)
    end
end


local function get_plugins_list()
    set_ctx_and_check_token()
    local args = get_uri_args()
    local subsystem = args["subsystem"]
    -- If subsystem is passed then it should be either http or stream.
    -- If it is not passed/nil then http will be default.
    subsystem = subsystem or "http"
    if subsystem == "http" or subsystem == "stream" then
        local plugins = resources.plugins.get_plugins_list(subsystem)
        core.response.exit(200, plugins)
    end
    core.response.exit(400,"invalid subsystem passed")
end

-- Handle unsupported request methods for the virtual "reload" plugin
local function unsupported_methods_reload_plugin()
    set_ctx_and_check_token()

    core.response.exit(405, {
        error_msg = "please use PUT method to reload the plugins, "
                    .. get_method() .. " method is not allowed."
    })
end


local function post_reload_plugins()
    set_ctx_and_check_token()

    local success, err = events:post(reload_event, get_method(), ngx_time())
    if not success then
        core.response.exit(503, err)
    end

    core.response.exit(200, "done")
end


local function plugins_eq(old, new)
    local old_set = {}
    for _, p in ipairs(old) do
        old_set[p.name] = p
    end

    local new_set = {}
    for _, p in ipairs(new) do
        new_set[p.name] = p
    end

    return core.table.set_eq(old_set, new_set)
end


local function sync_local_conf_to_etcd(reset)
    local local_conf = core.config.local_conf()

    local plugins = {}
    for _, name in ipairs(local_conf.plugins) do
        core.table.insert(plugins, {
            name = name,
        })
    end

    for _, name in ipairs(local_conf.stream_plugins) do
        core.table.insert(plugins, {
            name = name,
            stream = true,
        })
    end

    if reset then
        local res, err = core.etcd.get("/plugins")
        if not res then
            core.log.error("failed to get current plugins: ", err)
            return
        end

        if res.status == 404 then
            -- nothing need to be reset
            return
        end

        if res.status ~= 200 then
            core.log.error("failed to get current plugins, status: ", res.status)
            return
        end

        local stored_plugins = res.body.node.value
        local revision = res.body.node.modifiedIndex
        if plugins_eq(stored_plugins, plugins) then
            core.log.info("plugins not changed, don't need to reset")
            return
        end

        core.log.warn("sync local conf to etcd")

        local res, err = core.etcd.atomic_set("/plugins", plugins, nil, revision)
        if not res then
            core.log.error("failed to set plugins: ", err)
        end

        return
    end

    core.log.warn("sync local conf to etcd")

    -- need to store all plugins name into one key so that it can be updated atomically
    local res, err = core.etcd.set("/plugins", plugins)
    if not res then
        core.log.error("failed to set plugins: ", err)
    end
end


local function reload_plugins(data, event, source, pid)
    core.log.info("start to hot reload plugins")
    plugin.load()

    if ngx_worker_id() == 0 then
        sync_local_conf_to_etcd()
    end
end


local function schema_validate()
    local uri_segs = core.utils.split_uri(ngx.var.uri)
    core.log.info("uri: ", core.json.delay_encode(uri_segs))

    local seg_res = uri_segs[6]
    local resource = resources[seg_res]
    if not resource then
        core.response.exit(404, {error_msg = "Unsupported resource type: ".. seg_res})
    end

    local req_body, err = core.request.get_body(MAX_REQ_BODY)
    if err then
        core.log.error("failed to read request body: ", err)
        core.response.exit(400, {error_msg = "invalid request body: " .. err})
    end

    if req_body then
        local data, err = core.json.decode(req_body)
        if err then
            core.log.error("invalid request body: ", req_body, " err: ", err)
            core.response.exit(400, {error_msg = "invalid request body: " .. err,
                                     req_body = req_body})
        end

        req_body = data
    end

    local ok, err = core.schema.check(resource.schema, req_body)
    if ok then
        core.response.exit(200)
    end
    core.response.exit(400, {error_msg = err})
end


local uri_route = {
    {
        paths = [[/nwpuapi/admin]],
        methods = {"HEAD"},
        handler = head,
    },
    {
        paths = [[/nwpuapi/admin/*]],
        methods = {"GET", "PUT", "POST", "DELETE", "PATCH"},
        handler = run,
    },
    {
        paths = [[/nwpuapi/admin/plugins/list]],
        methods = {"GET"},
        handler = get_plugins_list,
    },
    {
        paths = [[/nwpuapi/admin/schema/validate/*]],
        methods = {"POST"},
        handler = schema_validate,
    },
    {
        paths = reload_event,
        methods = {"PUT"},
        handler = post_reload_plugins,
    },
    -- Handle methods other than "PUT" on "/plugin/reload" to inform user
    {
        paths = reload_event,
        methods = { "GET", "POST", "DELETE", "PATCH" },
        handler = unsupported_methods_reload_plugin,
    },
}


function _M.init_worker()
    local local_conf = core.config.local_conf()
    if not local_conf.apisix or not local_conf.apisix.enable_admin then
        return
    end

    router = route.new(uri_route)

    -- register reload plugin handler
    events = require("apisix.events")
    events:register(reload_plugins, reload_event, "PUT")

    if ngx_worker_id() == 0 then
        -- check if admin_key is required
        if local_conf.deployment.admin.admin_key_required == false then
            core.log.warn("Admin key is bypassed! ",
                "If you are deploying APISIX in a production environment, ",
                "please enable `admin_key_required` and set a secure admin key!")
        end

        local ok, err = ngx_timer_at(0, function(premature)
            if premature then
                return
            end

            -- try to reset the /plugins to the current configuration in the admin
            sync_local_conf_to_etcd(true)
        end)

        if not ok then
            error("failed to sync local configure to etcd: " .. err)
        end
    end
end


function _M.get()
    return router
end


return _M
