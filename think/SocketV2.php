<?php

declare (strict_types=1);

namespace think\log\driver;

use Composer\InstalledVersions;
use Psr\Container\NotFoundExceptionInterface;
use Psr\Log\LogLevel;
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
        // 使用分组输出模式
        'show_group'            => true,
        // 日志输出格式化，参数：{date}、{level}、{pid}、{message}
        'log_format'            => '', // [{date}][{level}] {message}
        // 时间格式
        'time_format'           => \DATE_RFC3339,
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
        'socket_error_log'      => null,
        // 是否禁用 curl 复用
        'curl_forbid_reuse'     => false,
    ];

    protected array $css = [
        'sql'      => 'color:#009bb4;',
        'sql_warn' => 'color:#009bb4;font-size:14px;',
        'error'    => 'color:#f4006b;font-size:14px;',
        'page'     => 'color:#4169e1;background:#dcdcdc;',
        'big'      => 'font-size:20px;color:red;',
    ];
    protected array $css2 = [
        LogLevel::DEBUG     => 'background: rgba(173, 216, 230, 0.15); color: #1e4d8c; padding: 2px 6px; padding: 2px 6px; border-radius: 3px;',
        LogLevel::INFO      => 'background: rgba(144, 238, 144, 0.15); color: #206a3d; padding: 2px 6px;',
        LogLevel::WARNING   => 'background: rgba(255, 228, 181, 0.15); color: #9c6e00; padding: 2px 6px;',
        LogLevel::ERROR     => 'background: rgba(255, 192, 203, 0.15); color: #a31212; padding: 2px 6px;',
        LogLevel::EMERGENCY => 'background: rgba(255, 182, 193, 0.15); color: #6a0016; padding: 2px 6px;',
        LogLevel::ALERT     => 'background: rgba(255, 218, 185, 0.15); color: #cc5500; padding: 2px 6px;',
        LogLevel::CRITICAL  => 'background: rgba(230, 190, 255, 0.15); color: #6a006a; padding: 2px 6px;',
        LogLevel::NOTICE    => 'background: rgba(173, 216, 230, 0.15); color: #004a77; padding: 2px 6px;',
        // 自定义
        'route'             => 'info',
        // 'request'           => 'info',
        'sql'               => 'warning',
    ];

    protected array $allowForceClientIds = []; //配置强制推送且被授权的client_id

    private array $clientArg = [];

    protected App $app;
    protected SocketClient $client;
    /**
     * 新日志格式的兼容判定
     */
    protected ?bool $newImplement = null;

    public const LogLevelSet = [
        LogLevel::EMERGENCY,
        LogLevel::ALERT,
        LogLevel::CRITICAL,
        LogLevel::ERROR,
        LogLevel::WARNING,
        LogLevel::NOTICE,
        LogLevel::INFO,
        LogLevel::DEBUG,
    ];

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
            $this->newImplement = (bool)version_compare($version, '8.1.2', '>');
        }
    }

    protected function logReader(array $log, bool $group): \Generator
    {
        // 是否启用兼容模式的备用判断
        $newImplement = $this->newImplement ?? array_is_list($log);

        if ($newImplement) {
            if ($group) {
                $group = [];
                foreach ($log as [$type, $msg]) {
                    $group[$type][] = $msg;
                }
                yield from $group;
            } else {
                yield from $log;
            }
        } else {
            if ($group) {
                yield from $log;
            } else {
                foreach ($log as $type => $msg) {
                    yield [$type, $msg];
                }
            }
        }
    }

    protected function getCurrentUri(): string
    {
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

        return $currentUri;
    }

    public function save(array $log = []): bool
    {
        if (!$this->check()) {
            return false;
        }

        $trace = [];

        if ($this->config['debug']) {
            // 基本信息
            $trace[] = [
                'type' => 'group',
                'msg'  => $this->getCurrentUri(),
                'css'  => $this->css['page'],
            ];
        }

        $format = trim($this->config['log_format'] ?? '');

        if ($this->config['show_group'] ?? true) {
            $expandLevel = array_flip($this->config['expand_level']);

            foreach ($this->logReader($log, true) as $type => $messages) {
                $trace[] = [
                    'type' => isset($expandLevel[$type]) ? 'group' : 'groupCollapsed',
                    'msg'  => '[ ' . $type . ' ]',
                    'css'  => $this->css[$type] ?? '',
                ];
                foreach ($messages as $msg) {
                    if (!is_string($msg)) {
                        $msg = var_export($msg, true);
                    }
                    $msg = $format ? $this->formatMessage($format, $type, $msg) : "[{$type}] {$msg}";
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
        } else {
            $trace[] = [
                'type' => 'group',
                'msg'  => 'logs',
                'css'  => '',
            ];
            foreach ($this->logReader($log, false) as $item) {
                [$type, $messages] = $item;
                $ctx = $item[2] ?? null;
                if (!is_string($messages)) {
                    $messages = var_export($messages, true);
                }
                $css = $this->css2[$type] ?? '';
                if (in_array($css, self::LogLevelSet, true)) {
                    $css = $this->css2[$css] ?? '';
                }
                $msg = $format ? $this->formatMessage($format, $type, $messages, $ctx) : "[{$type}] {$messages}";
                $trace[] = [
                    'type' => 'log',
                    'msg'  => $msg,
                    'css'  => $css,
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
                'msg'  => '[ included_files ]',
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

        $tabId = (int)$this->getClientArg('tabid');

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

    protected function formatMessage(string $format, string $level, string $messages, ?array $context = null): string
    {
        if (!str_contains($format, '{')) {
            return "[{$level}] {$messages}";
        }
        /** @var \DateTimeInterface|null $date */
        $date = $context["\0_t"] ?? null;
        /** @var int|null $index */
        $index = $context["\0_i"] ?? null;

        $replace = [
            '{date}' => $date ? $date->format($this->config['time_format']) : '',
            '{level}' => $level,
            '{index}' => $index,
            '{pid}' => getmypid(),
            '{message}' => $messages,
        ];

        return strtr($format, $replace);
    }

    /**
     * 发送给指定客户端
     */
    protected function sendToClient(int $tabId, string $clientId, array $logs, string $forceClientId): void
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
        $tabid = (int)$this->getClientArg('tabid');

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
                    'tabid'     => '-1',
                    'client_id' => $clientId,
                ];
            } else {
                $socketLog = $this->app->request->header('User-Agent');
                if (empty($socketLog)) {
                    return '';
                }

                if (!preg_match('/SocketLog\((.*?)\)/', $socketLog, $match)) {
                    $this->clientArg = [
                        'tabid'     => '-1',
                        'client_id' => null,
                    ];
                    return '';
                }
                $tmp = [];
                parse_str($match[1], $tmp);
                $this->clientArg = [
                    'tabid'     => $tmp['tabid'] ?? '-1',
                    'client_id' => $tmp['client_id'] ?? null,
                ];
            }
        }

        return $this->clientArg[$name] ?? '';
    }
}
