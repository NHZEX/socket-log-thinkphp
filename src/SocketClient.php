<?php

declare(strict_types=1);

namespace Zxin\SocketLog;

class SocketClient
{
    private $shareHandle;
    private $curlHandle;
    protected string $protocol;
    protected string $host;
    protected int    $port;
    protected string $path;

    protected array $curlOptions = [
        CURLOPT_CONNECTTIMEOUT => 1,
        CURLOPT_TIMEOUT        => 10,
    ];

    protected const ALLOW_CURL_OPTIONS = [
        CURLOPT_CONNECTTIMEOUT,
        CURLOPT_CONNECTTIMEOUT_MS,
        CURLOPT_TIMEOUT,
        CURLOPT_SSL_VERIFYHOST,
        CURLOPT_SSL_VERIFYPEER,
        CURLOPT_CAINFO,
        CURLOPT_CAPATH,
        CURLOPT_HTTP_VERSION,
        CURLOPT_PROXY,
        CURLOPT_PROXYAUTH,
        CURLOPT_PROXYUSERNAME,
        CURLOPT_PROXYPASSWORD,
    ];

    protected bool $enableCompress = false;
    protected ?string $e2eId = null;
    protected string $e2eEncryptionKey = '';
    protected string $paramsMethod = 'path';
    protected ?string $loggerFile = null;
    protected ?bool $enableCurlShare = true;
    protected bool $curlForbidReuse = false; // 是否禁用 curl 复用
    private bool $isInitialized = false;

    public function __construct(string $protocol, string $host, int $port, string $path)
    {
        $protocol = trim($protocol);
        if (empty($protocol)) {
            $protocol = 'http';
        }
        if ('http' !== $protocol && 'https' !== $protocol) {
            throw new \InvalidArgumentException("invalid protocol value: {$protocol}");
        }
        if ($port < 0) {
            throw new \InvalidArgumentException("invalid port value: {$port}");
        }

        $this->protocol = $protocol;
        $this->host     = trim($host, " \n\r\t\v\0/");
        $this->port     = $port;
        $this->path     = trim($path, " \n\r\t\v\0/");
    }

    public static function fromUri(string $uri): self
    {
        $arr = parse_url($uri);

        return new SocketClient(
            $arr['scheme'] ?? 'http',
            $arr['host'],
            (int) ($arr['port'] ?? 0),
            $arr['path'] ?? '',
        );
    }

    public function setEnableCurlShare(?bool $enableCurlShare): void
    {
        $this->enableCurlShare = $enableCurlShare;

        // 如果已经初始化，则关闭连接
        if ($this->isInitialized && !$enableCurlShare) {
            $this->isInitialized = false;
            $this->closeHandles();
        }
    }

    private function initShareHandles(): void
    {
        if (!$this->isInitialized && $this->enableCurlShare) {
            // 初始化共享句柄
            $this->shareHandle = curl_share_init();
            curl_share_setopt($this->shareHandle, CURLSHOPT_SHARE, CURL_LOCK_DATA_DNS);
            curl_share_setopt($this->shareHandle, CURLSHOPT_SHARE, CURL_LOCK_DATA_SSL_SESSION);
            curl_share_setopt($this->shareHandle, CURLSHOPT_SHARE, CURL_LOCK_DATA_CONNECT);

            // 初始化curl句柄
            $this->curlHandle = curl_init();
            curl_setopt($this->curlHandle, CURLOPT_SHARE, $this->shareHandle);

            // 设置一些固定的优化选项
            curl_setopt($this->curlHandle, CURLOPT_RETURNTRANSFER, true);
            curl_setopt($this->curlHandle, CURLOPT_POST, true);

            // 启用keep-alive，这是关键优化点
            curl_setopt($this->curlHandle, CURLOPT_TCP_KEEPALIVE, 1);
            curl_setopt($this->curlHandle, CURLOPT_TCP_KEEPIDLE, 120);
            curl_setopt($this->curlHandle, CURLOPT_TCP_KEEPINTVL, 60);

            // 启用HTTP/2（如果服务器支持）
            if (defined('CURL_HTTP_VERSION_2_0')) {
                curl_setopt($this->curlHandle, CURLOPT_HTTP_VERSION, CURL_HTTP_VERSION_2_0);
            }

            $this->isInitialized = true;
        }
    }

    public function setCurlForbidReuse(bool $curlForbidReuse): void
    {
        $this->curlForbidReuse = $curlForbidReuse;
    }

    public function setLogFilePath(string $filepath)
    {
        if (empty($filepath)) {
            $this->loggerFile = null;
            return;
        }

        $dir = dirname($filepath);
        if ($dir && (!is_dir($dir) || !is_writable($dir))) {
            return;
        }

        $this->loggerFile = $filepath;
    }

    public function isEnableCompress(): bool
    {
        return $this->enableCompress;
    }

    public function setEnableCompress(bool $enableCompress): void
    {
        $this->enableCompress = $enableCompress;
    }

    public function getE2eEncryptionKey(): string
    {
        return $this->e2eEncryptionKey;
    }

    public function setE2eEncryptionKey(string $e2eEncryptionKey, ?string $e2eId): void
    {
        if (
            null !== $e2eId
            && ($e2eId = trim($e2eId))
            && strlen($e2eId) <= 128
        ) {
            $this->e2eId = $e2eId;
        } else {
            $this->e2eId = null;
        }
        $this->e2eEncryptionKey = trim($e2eEncryptionKey);
    }

    public function getParamsMethod(): string
    {
        return $this->paramsMethod;
    }

    public function setParamsMethod(string $paramsMethod): void
    {
        if (!in_array($paramsMethod, ['path', 'query', 'header'], true)) {
            throw new \InvalidArgumentException("Invalid parameter paramsMethod: {$paramsMethod}");
        }
        $this->paramsMethod = $paramsMethod;
    }

    public function getCurlOptions(): array
    {
        return $this->curlOptions;
    }

    public function setCurlOptions(array $options): void
    {
        $this->curlOptions = array_intersect_key(
            $options,
            array_flip(self::ALLOW_CURL_OPTIONS),
        );
    }

    protected function buildUrl(string $clientId): string
    {
        $url = "{$this->protocol}://{$this->host}";
        if ($this->port > 0) {
            $url .= ":{$this->port}";
        }
        if ($this->path) {
            $url .= "/{$this->path}";
        }

        return $this->getParamsMethod() === 'path'
            ? ($url . "/{$clientId}")
            : (
                $this->getParamsMethod() === 'query'
                ? ($url . "?clientId={$clientId}")
                : $url
            );
    }

    /**
     * @return false|string
     */
    public function send(string $message, string $clientId)
    {
        $this->initShareHandles();

        $url = $this->buildUrl($clientId);

        [$message, $contentType, $headers] = $this->buildPayload($message, $clientId);

        $headers['Content-Type'] = $contentType;
        $headers['Connection'] = 'Keep-Alive';
        $headers['Expect'] = ''; // 禁用 100-continue

        if ($this->getParamsMethod() === 'header') {
            $headers['X-Socket-Log-ClientId'] = $clientId;
        }

        $ch = $this->curlHandle ?? curl_init();

        curl_setopt($ch, CURLOPT_URL, $url);
        curl_setopt($ch, CURLOPT_POST, true);
        curl_setopt($ch, CURLOPT_POSTFIELDS, $message);
        curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
        curl_setopt($ch, CURLOPT_FORBID_REUSE, $this->curlForbidReuse);

        $headersArr = [];
        foreach ($headers as $key => $value) {
            $headersArr[] = $key . ': ' . $value;
        }
        curl_setopt($ch, CURLOPT_HTTPHEADER, $headersArr);

        $options = $this->curlOptions;
        $options[CURLOPT_CONNECTTIMEOUT] ??= 1;
        $options[CURLOPT_TIMEOUT] ??= 10;

        foreach ($options as $option => $value) {
            if (!curl_setopt($ch, $option, $value)) {
                $this->writeLog('warning', $clientId, sprintf('set option(%d) fail, %s', $option, curl_error($ch)));
            }
        }

        $result = curl_exec($ch);

        if (false === $result) {
            $error = curl_error($ch);
            $errno = curl_errno($ch);
            $this->writeLog('error', $clientId, "Curl error ($errno): $error");
        }

        return $result;
    }

    protected function buildPayload(string $message, string $clientId): array
    {
        $headers = [];

        $needCompress = $this->isEnableCompress() && strlen($message) > 128;

        if (\extension_loaded('zlib') && $needCompress) {
            $message = zlib_encode($message, ZLIB_ENCODING_DEFLATE);
            $contentType = 'application/x-compress';
        } else {
            $contentType = 'application/json';
        }

        $e2eEncryptionKey = $this->e2eEncryptionKey;

        if (\extension_loaded('openssl') && $e2eEncryptionKey && strlen($e2eEncryptionKey) >= 8) {
            if ($this->e2eId) {
                $addContent = "SL-E2E_{$this->e2eId}";
                $headers['X-E2E-ID'] = $this->e2eId;
            } else {
                $addContent = "SL-E2E_{$clientId}";
            }
            $add = hash('sha256', $addContent, true);
            $message = $this->encryption($message, $e2eEncryptionKey, $add);

            $contentType = $needCompress
                ? 'application/x-e2e-compress+json'
                : 'application/x-e2e-json';
        }

        return [$message, $contentType, $headers];
    }

    public function writeLog(string $action, string $clientId, string $message): void
    {
        if (null === $this->loggerFile) {
            return;
        }
        $log = sprintf("[%s] %s(%s): %s\n", date('Y-m-dTH:i:s'), $action, $clientId, $message);
        file_put_contents($this->loggerFile, $log, FILE_APPEND);
    }

    private function encryption(string $message, string $key, string $add): string
    {
        // For GCM a 12 byte IV is strongly suggested
        // https://crypto.stackexchange.com/a/41610/100988

        if (!\extension_loaded('openssl')) {
            throw new \LogicException('openssl is not enabled');
        }

        $iv     = openssl_random_pseudo_bytes(12);
        $key    = hash('sha256', $key, true);
        $tag    = '';
        $tagLen = 16;

        $ciphertext = openssl_encrypt($message, 'AES-256-GCM', $key, OPENSSL_RAW_DATA, $iv, $tag, $add, $tagLen);

        if (false === $ciphertext) {
            throw new \LogicException('e2e encryption error: ' . openssl_error_string());
        }

        return $iv . $ciphertext . $tag;
    }

    /**
     * 获取连接信息
     */
    public function getConnectionInfo(): ?array
    {
        if (!$this->curlHandle) {
            return null;
        }

        return [
            'total_time' => curl_getinfo($this->curlHandle, CURLINFO_TOTAL_TIME),
            'connect_time' => curl_getinfo($this->curlHandle, CURLINFO_CONNECT_TIME),
            'num_connects' => curl_getinfo($this->curlHandle, CURLINFO_NUM_CONNECTS),
            'ssl_verifyresult' => curl_getinfo($this->curlHandle, CURLINFO_SSL_VERIFYRESULT),
            'http_code' => curl_getinfo($this->curlHandle, CURLINFO_HTTP_CODE),
            'url' => curl_getinfo($this->curlHandle, CURLINFO_EFFECTIVE_URL),
        ];
    }

    /**
     * 重置连接
     */
    public function resetConnection(): void
    {
        if ($this->curlHandle) {
            curl_reset($this->curlHandle);
            curl_setopt($this->curlHandle, CURLOPT_SHARE, $this->shareHandle);

            // 重新设置基本选项
            curl_setopt($this->curlHandle, CURLOPT_RETURNTRANSFER, true);
            curl_setopt($this->curlHandle, CURLOPT_POST, true);
            curl_setopt($this->curlHandle, CURLOPT_TCP_KEEPALIVE, 1);
            curl_setopt($this->curlHandle, CURLOPT_TCP_KEEPIDLE, 60);
            curl_setopt($this->curlHandle, CURLOPT_TCP_KEEPINTVL, 45);

            if (defined('CURL_HTTP_VERSION_2_0')) {
                curl_setopt($this->curlHandle, CURLOPT_HTTP_VERSION, CURL_HTTP_VERSION_2_0);
            }
        }
    }

    private function closeHandles(): void
    {
        if ($this->curlHandle) {
            curl_close($this->curlHandle);
            $this->curlHandle = null;
        }

        if ($this->shareHandle) {
            curl_share_close($this->shareHandle);
            $this->shareHandle = null;
        }
    }

    public function __destruct()
    {
        $this->closeHandles();
    }
}
