FROM ubuntu:20.04

# 定义构建参数
ARG HTTP_PROXY=http://host.docker.internal:7890
ARG HTTPS_PROXY=http://host.docker.internal:7890

# 设置环境变量
ENV HTTP_PROXY=${HTTP_PROXY}
ENV HTTPS_PROXY=${HTTPS_PROXY}
ENV NO_PROXY=localhost,127.0.0.1,.example.com

ENV LUA_PATH='/usr/local/share/lua/5.1/?.lua;/usr/local/share/lua/5.1/?/init.lua;;'
ENV LUA_CPATH='/usr/local/lib/lua/5.1/?.so;;'

# 设置工作目录
WORKDIR /apisix

# 复制项目文件
COPY . .

# 查看复制后的文件
RUN pwd && ls -la


ENV DEBIAN_FRONTEND=noninteractive
# 安装依赖
USER root
RUN apt-get update \
    && apt-get install -y sudo bash gcc make libc-dev luarocks git 
    
RUN luarocks install luafilesystem
RUN luarocks install penlight

RUN make deps

RUN make install

# 暴露端口
EXPOSE 9080 9443

# 启动 APISIX
CMD ["apisix", "start"]

