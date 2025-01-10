#
# Licensed to the Apache Software Foundation (ASF) under one or more
# contributor license agreements.  See the NOTICE file distributed with
# this work for additional information regarding copyright ownership.
# The ASF licenses this file to You under the Apache License, Version 2.0
# (the "License"); you may not use this file except in compliance with
# the License.  You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#

FROM api7/apisix-runtime:dev AS build

ARG ENABLE_PROXY=false

ENV HTTP_PROXY=http://host.docker.internal:7890
ENV HTTPS_PROXY=http://host.docker.internal:7890
ENV NO_PROXY=localhost,127.0.0.1,.example.com

ENV DEBIAN_FRONTEND noninteractive

# 设置环境变量 LD_LIBRARY_PATH
ENV LD_LIBRARY_PATH=/usr/local/lib:$LD_LIBRARY_PATH

# 更新 apt 源并安装基本依赖
RUN set -x \
    && (test "${ENABLE_PROXY}" != "true" || /bin/sed -i 's,http://deb.debian.org,https://mirrors.aliyun.com,g' /etc/apt/sources.list) \
    && apt-get -y update --fix-missing \
    && apt-get install -y curl \
        gawk \
        git \
        libldap2-dev \
        liblua5.1-0-dev \
        lua5.1 \
        make \
        sudo \
        unzip \
        wget \
        libyaml-dev 

RUN apt-get install -y libyaml-0-2
RUN ldconfig
# 将本地的 apisix-master-0.rockspec 文件复制到容器中
COPY /apisix-master-0.rockspec /tmp/apisix-master-0.rockspec
# COPY /apisix /apisix
# 安装 luarocks 和 apisix 依赖
RUN curl https://raw.githubusercontent.com/apache/apisix/master/utils/linux-install-luarocks.sh -sL | bash - \
    && luarocks install /tmp/apisix-master-0.rockspec --tree=/usr/local/apisix/deps PCRE_DIR=/usr/local/openresty/pcre 

# 配置动态库路径并运行 ldconfig
RUN echo "/usr/local/lib" > /etc/ld.so.conf.d/99local.conf \
    && ldconfig

# 配置 apisix 的执行路径和日志路径
RUN cp -v /usr/local/apisix/deps/lib/luarocks/rocks-5.1/apisix/master-0/bin/apisix /usr/bin/ \
    && mv /usr/local/apisix/deps/share/lua/5.1/apisix /usr/local/apisix \
    && ln -sf /dev/stdout /usr/local/apisix/logs/access.log \
    && ln -sf /dev/stderr /usr/local/apisix/logs/error.log

FROM api7/apisix-runtime:dev AS production-stage

COPY --from=build /usr/local/apisix /usr/local/apisix
COPY --from=build /usr/bin/apisix /usr/bin/apisix

ENV DEBIAN_FRONTEND noninteractive
RUN apt-get -y update --fix-missing \
    && apt-get install -y \
        libldap2-dev \
    && apt-get remove --purge --auto-remove -y

COPY ./install-brotli.sh /install-brotli.sh
RUN chmod +x /install-brotli.sh \  
    && cd / && ./install-brotli.sh && rm -rf /install-brotli.sh

WORKDIR /usr/local/apisix

ENV PATH=$PATH:/usr/local/openresty/luajit/bin:/usr/local/openresty/nginx/sbin:/usr/local/openresty/bin

EXPOSE 9080 9443

COPY ./docker-entrypoint.sh /docker-entrypoint.sh
COPY ./check_standalone_config.sh /check_standalone_config.sh

ENTRYPOINT ["/docker-entrypoint.sh"]
# ENTRYPOINT ["/bin/bash"]
CMD ["docker-start"]
# CMD []

STOPSIGNAL SIGQUIT
