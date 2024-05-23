<?php
declare(strict_types=1);

namespace Zxin\SocketLog;

class SocketClient
{
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
    protected string $e2eEncryptionKey = '';
    protected ?string $loggerFile = null;

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

    public function setE2eEncryptionKey(string $e2eEncryptionKey): void
    {
        $this->e2eEncryptionKey = trim($e2eEncryptionKey);
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
        return $url . "/{$clientId}";
    }

    public function send(string $message, string $clientId): bool
    {
        $url = $this->buildUrl($clientId);

        [$message, $contentType] = $this->createPayload($message, $clientId);

        $ch  = curl_init();

        $headers = [
            "Content-Type: {$contentType}",
        ];

        curl_setopt($ch, CURLOPT_URL, $url);
        curl_setopt($ch, CURLOPT_POST, true);
        curl_setopt($ch, CURLOPT_POSTFIELDS, $message);
        curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
        curl_setopt($ch, CURLOPT_HTTPHEADER, $headers);

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
            $this->writeLog('error', $clientId, curl_error($ch));
        }

        return $result;
    }

    protected function createPayload(string $message, string $clientId): array
    {
        $needCompress = $this->isEnableCompress() && strlen($message) > 128;

        if (\extension_loaded('zlib') && $needCompress) {
            $message = zlib_encode($message, ZLIB_ENCODING_DEFLATE);
            $contentType = 'application/x-compress';
        } else {
            $contentType = 'application/json';
        }

        $e2eEncryptionKey = $this->e2eEncryptionKey;

        if (\extension_loaded('openssl') && $e2eEncryptionKey && strlen($e2eEncryptionKey) >= 8) {
            $add = hash('sha256', "SL-E2E_{$clientId}", true);
            $message = $this->encryption($message, $e2eEncryptionKey, $add);

            $contentType = $needCompress
                ? 'application/x-e2e-compress+json'
                : 'application/x-e2e-json';
        }

        return [$message, $contentType];
    }

    public function writeLog(string $action, string $clientId, string $message)
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
}
