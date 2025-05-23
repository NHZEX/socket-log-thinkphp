# 远程日志客户端 ThinkPHP

thinkphp framework 内置 socket-log 增强替代品

## 完整生态

- [服务端 socket-log-server](https://github.com/nhzex/socket-log-server)
- [浏览器扩展](https://github.com/nhzex/socket-log-chrome)

## 参数
```php
[
    // 日志记录方式
    'type'                => 'SocketV2', // 驱动名称或者使用类名：\think\log\driver\SocketV2::class
    // 服务器地址
    'uri'                 => 'http://127.0.0.1', // 复杂例子：https://127.0.0.1:8443/log-endpoint
    // 是否显示加载的文件列表
    'show_included_files' => false,
    // 日志强制记录到配置的 client_id
    'force_client_ids'    => ['my_develop'],
    // 限制允许读取日志的 client_id
    'allow_client_ids'    => ['my_develop'],
    // client_id 发送方法: path, query, header，推荐使用（query, header）兼容性更好
    'client_id_send_method' => 'path',
    // 日志处理（暂无作用）
    'processor'           => null,
    // 关闭通道日志写入（暂无作用）
    'close'               => false,
    // 使用分组输出模式
    'show_group'            => true,
    // 日志输出格式化，参数：{date}、{level}、{pid}、{message}
    'log_format'            => '', // [{date}][{level}] {message}
    // 时间格式，配置 log_format 后才有效
    'time_format'           => \DATE_RFC3339,
    // 是否实时写入（暂无作用）
    'realtime_write'      => false,
    // 默认展开节点
    'expand_level'        => ['debug'],
    // 自定义日志头
    'format_head'         => function ($uir, App $app) {
        $method      = $app->exists('request') ? $app->request->method() : 'NULL';
        $memory_use  = format_byte(memory_get_usage());
        return "{$uir} [$method] [内存消耗：{$memory_use}kb]";
    },
    // CURL 选项
    'curl_opts'            => [
        CURLOPT_CONNECTTIMEOUT => 3,
        CURLOPT_TIMEOUT        => 10,
    ],
    // 压缩传输
    'compress'            => true,
    // 端到端密钥识别 ID，用于多密钥匹配支持，尽量使用匿名字符串 (比如 uuid), 最大支持长度 127
    'e2e_id'                => null,
    // 端到端加密密钥（最少 8 位长度，不配置为空或移除）
    'e2e_encryption_key'  => 'CTZ4PH9JALN375ZXJDJ4',
    // 发送异常日志（必须确保目录可写，不配置为空或移除）
    'socket_error_log'    => runtime_path() . 'socklog_send.log',
]
```