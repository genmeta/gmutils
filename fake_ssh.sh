#!/bin/bash

# 检查是否为 -V 参数
if [ "$#" -eq 1 ] && [ "$1" = -V ]
    then
    # 执行原始ssh -V命令
    ssh -V
else
    # 调用genmeta-ssh3并传递所有参数
    genmeta ssh3 "$@" || {
        echo "Custom ssh process failed, falling back to regular ssh..." >&2
        ssh "$@"
    }
fi
