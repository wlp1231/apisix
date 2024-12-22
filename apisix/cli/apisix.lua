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

-- 用于加载 C 扩展库（.so 文件）路径
local pkg_cpath_org = package.cpath
-- 用于加载 Lua 文件（.lua）路径
local pkg_path_org = package.path

-- 检查 package.path 末尾是否有分号
local _, find_pos_end = string.find(pkg_path_org, ";", -1, true)
if not find_pos_end then
    pkg_path_org = pkg_path_org .. ";"
end

-- 定义 APISIX 的加载路径
local apisix_home = "/usr/local/apisix"
local pkg_cpath = apisix_home .. "/deps/lib64/lua/5.1/?.so;"
                  .. apisix_home .. "/deps/lib/lua/5.1/?.so;"
local pkg_path_deps = apisix_home .. "/deps/share/lua/5.1/?.lua;"
local pkg_path_env = apisix_home .. "/?.lua;"

-- modify the load path to load our dependencies
package.cpath = pkg_cpath .. pkg_cpath_org
package.path  = pkg_path_deps .. pkg_path_org .. pkg_path_env

-- pass path to construct the final result
-- 加载 env 模块并初始化环境
local env = require("apisix.cli.env")(apisix_home, pkg_cpath_org, pkg_path_org)
-- 加载 ops 模块并执行命令
local ops = require("apisix.cli.ops")

-- Lua 提供的全局变量，表示命令行传入的参数
ops.execute(env, arg)
