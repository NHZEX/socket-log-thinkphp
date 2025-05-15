<?php

declare (strict_types=1);

namespace think\log\driver;

use Composer\InstalledVersions;
use Psr\Container\NotFoundExceptionInterface;
use think\App;
use think\contract\LogHandlerInterface;
use Zxin\SocketLog\SocketClient;

class SocketV2 implements LogHandlerInterface
{
    protected array $config = [
        // socket 服务器连接地址
        'uri'                   => 'http://localhost:1116',
        // 是否显示加载的文件列表
        'show_included_files'   => false,
        // 日志强制记录到配置的 client_id
        'force_client_ids'      => [],
        // 限制允许读取日志的 client_id
        'allow_client_ids'      => [],
        // client_id 发送方法: path, query, header
        'client_id_send_method' => 'path',
        // 调试开关
        'debug'                 => false,
        // 输出到浏览器时默认展开的日志级别
        'expand_level'          => ['debug'],
        // 日志头渲染回调
        'format_head'           => null,
        // curl opt
        'curl_opts'             => [
            CURLOPT_CONNECTTIMEOUT => 1,
            CURLOPT_TIMEOUT        => 10,
        ],
        // 压缩传输
        'compress'              => false,
        // 端到端 ID, 尽量使用匿名字符串 (比如 uuid), 最大长度 127
        'e2e_id'                => null,
        // 端到端密钥
        'e2e_encryption_key'    => '',
        // 发送异常日志（必须确保目录可写）
        'socket_error_log' => null,
        // 是否禁用 curl 复用
        'curl_forbid_reuse' => false,
    ];

    protected array $css = [
        'sql'      => 'color:#009bb4;',
        'sql_warn' => 'color:#009bb4;font-size:14px;',
        'error'    => 'color:#f4006b;font-size:14px;',
        'page'     => 'color:#4169e1;background:#dcdcdc;',
        'big'      => 'font-size:20px;color:red;',
    ];

    protected array $allowForceClientIds = []; //配置强制推送且被授权的client_id

    private array $clientArg = [];

    protected App          $app;
    protected SocketClient $client;
    /**
     * 新日志格式的兼容判定
     */
    protected ?bool $newImplement = null;

    public function __construct(App $app, array $config = [])
    {
        $this->app = $app;

        if (!empty($config)) {
            $this->config = array_merge($this->config, $config);
        }

        if (!isset($config['debug'])) {
            $this->config['debug'] = $app->isDebug();
        }

        $this->client = SocketClient::fromUri($this->config['uri']);
        $this->client->setCurlOptions($this->config['curl_opts']);
        $this->client->setEnableCompress($this->config['compress'] ?? false);
        $this->client->setE2eEncryptionKey($this->config['e2e_encryption_key'] ?? '', $this->config['e2e_id'] ?? null);
        $this->client->setParamsMethod($this->config['client_id_send_method'] ?? 'path');
        $this->client->setLogFilePath($this->config['socket_error_log'] ?? null);
        $this->client->setCurlForbidReuse($this->config['curl_forbid_reuse'] ?? false);

        $version = ltrim(InstalledVersions::getPrettyVersion('topthink/framework'), 'v');
        if (preg_match('~^(\d+\.?)+$~', $version)) {
            $this->newImplement = (bool) version_compare($version, '8.1.2', '>');
        }
    }

    protected function logGroupReader(array $log): \Generator
    {
        // 是否启用兼容模式的备用判断
        $newImplement = $this->newImplement ?? array_is_list($log);

        if ($newImplement) {
            $group = [];
            foreach ($log as [$type, $msg]) {
                $group[$type][] = $msg;
            }
            yield from $group;
        } else {
            foreach ($log as $type => $val) {
                yield $type => $val;
            }
        }

    }

    public function save(array $log = []): bool
    {
        if (!$this->check()) {
            return false;
        }

        $trace = [];

        if ($this->config['debug']) {
            if ($this->app->exists('request')) {
                $currentUri = $this->app->request->url(true);
            } else {
                $currentUri = 'cmd:' . implode(' ', $_SERVER['argv'] ?? []);
            }

            if (!empty($this->config['format_head'])) {
                try {
                    $currentUri = $this->app->invoke($this->config['format_head'], [$currentUri]);
                } /** @noinspection PhpRedundantCatchClauseInspection */ catch (NotFoundExceptionInterface $_) {
                    // Ignore exception
                }
            }

            // 基本信息
            $trace[] = [
                'type' => 'group',
                'msg'  => $currentUri,
                'css'  => $this->css['page'],
            ];
        }

        $expandLevel = array_flip($this->config['expand_level']);

        foreach ($this->logGroupReader($log) as $type => $messages) {
            $trace[] = [
                'type' => isset($expandLevel[$type]) ? 'group' : 'groupCollapsed',
                'msg'  => '[ ' . $type . ' ]',
                'css'  => $this->css[$type] ?? '',
            ];

            foreach ($messages as $msg) {
                if (!is_string($msg)) {
                    $msg = var_export($msg, true);
                }
                $trace[] = [
                    'type' => 'log',
                    'msg'  => $msg,
                    'css'  => '',
                ];
            }

            $trace[] = [
                'type' => 'groupEnd',
                'msg'  => '',
                'css'  => '',
            ];
        }

        if ($this->config['show_included_files']) {
            $trace[] = [
                'type' => 'groupCollapsed',
                'msg'  => '[ file ]',
                'css'  => '',
            ];

            $trace[] = [
                'type' => 'log',
                'msg'  => implode("\n", get_included_files()),
                'css'  => '',
            ];

            $trace[] = [
                'type' => 'groupEnd',
                'msg'  => '',
                'css'  => '',
            ];
        }

        $trace[] = [
            'type' => 'groupEnd',
            'msg'  => '',
            'css'  => '',
        ];

        $tabId = (int) $this->getClientArg('tabid');

        if (!$clientId = $this->getClientArg('client_id')) {
            $clientId = '';
        }

        if (!empty($this->allowForceClientIds)) {
            //强制推送到多个client_id
            foreach ($this->allowForceClientIds as $forceClientId) {
                $clientId = $forceClientId;
                $this->sendToClient($tabId, $clientId, $trace, $forceClientId);
            }
        } else {
            $this->sendToClient($tabId, $clientId, $trace, '');
        }

        return true;
    }

    /**
     * 发送给指定客户端
     * @param  $tabid
     * @param  $clientId
     * @param  $logs
     * @param  $forceClientId
     */
    protected function sendToClient($tabId, $clientId, $logs, $forceClientId)
    {
        $logs = [
            'tabid'           => $tabId,
            'client_id'       => $clientId,
            'logs'            => $logs,
            'force_client_id' => $forceClientId,
        ];

        $message = json_encode(
            $logs,
            JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES | JSON_PARTIAL_OUTPUT_ON_ERROR,
        );

        $this->client->send($message, $clientId);
    }

    /**
     * 检测客户授权
     */
    protected function check(): bool
    {
        $tabid = (int) $this->getClientArg('tabid');

        //是否记录日志的检查
        if ($tabid === 0 && !$this->config['force_client_ids']) {
            return false;
        }

        //用户认证
        $allowClientIds = $this->config['allow_client_ids'];

        if (!empty($allowClientIds)) {
            //通过数组交集得出授权强制推送的client_id
            $this->allowForceClientIds = array_intersect($allowClientIds, $this->config['force_client_ids']);
            if (!$tabid && count($this->allowForceClientIds)) {
                return true;
            }

            $clientId = $this->getClientArg('client_id');
            if (!in_array($clientId, $allowClientIds)) {
                return false;
            }
        } else {
            $this->allowForceClientIds = $this->config['force_client_ids'];
        }

        return true;
    }

    /**
     * 获取客户参数
     */
    protected function getClientArg(string $name): string
    {
        if (!$this->app->exists('request')) {
            return '';
        }

        if (empty($this->clientArg)) {
            $clientId = $this->app->request->header('X-Socket-Log-Client-Id');
            if ($clientId) {
                $this->clientArg = [
                    'tabid' => '-1',
                    'client_id' => $clientId,
                ];
            } else {
                $socketLog = $this->app->request->header('User-Agent');
                if (empty($socketLog)) {
                    return '';
                }

                if (!preg_match('/SocketLog\((.*?)\)/', $socketLog, $match)) {
                    $this->clientArg = [
                        'tabid' => '-1',
                        'client_id' => null,
                    ];
                    return '';
                }
                $tmp = [];
                parse_str($match[1] ?? '', $tmp);
                $this->clientArg = [
                    'tabid' => $tmp['tabid'] ?? '-1',
                    'client_id' => $tmp['client_id'] ?? null,
                ];
            }
        }

        return $this->clientArg[$name] ?? '';
    }
}
