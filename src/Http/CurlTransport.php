<?php

declare(strict_types=1);

namespace RevokeGPT\Firewall\Http;

/**
 * The default API transport: ext-curl, HTTP/HTTPS only, redirects never followed (a 307 or 308
 * would re-send the secret), a hard cap on the response size.
 *
 * Signature of every transport: (method, url, headers, body, timeoutSeconds, maxBytes) returning
 * ['status' => int, 'headers' => array<lower-case name, string>, 'body' => string].
 */
final class CurlTransport
{
    /**
     * @param array<string,string> $headers
     * @return array{status:int,headers:array<string,string>,body:string}
     */
    public function __invoke(string $method, string $url, array $headers, ?string $body, float $timeout, int $maxBytes): array
    {
        $ch = curl_init($url);
        if ($ch === false) {
            throw new TransportException('curl init failed');
        }
        $hdrs = [];
        foreach ($headers as $k => $v) {
            $hdrs[] = $k . ': ' . $v;
        }
        $respHeaders = [];
        $buf = '';
        $tooBig = false;
        curl_setopt_array($ch, [
            CURLOPT_CUSTOMREQUEST => $method,
            CURLOPT_HTTPHEADER => $hdrs,
            CURLOPT_FOLLOWLOCATION => false,
            CURLOPT_PROTOCOLS => CURLPROTO_HTTP | CURLPROTO_HTTPS,
            CURLOPT_CONNECTTIMEOUT_MS => max(1, (int) min($timeout * 1000, 5000)),
            CURLOPT_TIMEOUT_MS => max(1, (int) ($timeout * 1000)), // the whole transfer: connect, send and the full body
            CURLOPT_HTTP_VERSION => CURL_HTTP_VERSION_1_1,
            CURLOPT_NOSIGNAL => true,
            CURLOPT_HEADERFUNCTION => static function ($c, string $line) use (&$respHeaders): int {
                $i = strpos($line, ':');
                if ($i !== false) {
                    $respHeaders[strtolower(trim(substr($line, 0, $i)))] = trim(substr($line, $i + 1));
                }
                return strlen($line);
            },
            CURLOPT_WRITEFUNCTION => static function ($c, string $chunk) use (&$buf, &$tooBig, $maxBytes): int {
                $buf .= $chunk;
                if (strlen($buf) > $maxBytes) {
                    $tooBig = true;
                    return 0; // abort the transfer
                }
                return strlen($chunk);
            },
        ]);
        if ($body !== null) {
            curl_setopt($ch, CURLOPT_POSTFIELDS, $body);
        }
        $ok = curl_exec($ch);
        $errno = curl_errno($ch);
        $status = (int) curl_getinfo($ch, CURLINFO_RESPONSE_CODE);
        $err = curl_error($ch);
        curl_close($ch);
        if ($tooBig) {
            return ['status' => $status, 'headers' => $respHeaders, 'body' => $buf];
        }
        if ($ok === false) {
            $connect = in_array($errno, [CURLE_COULDNT_CONNECT, CURLE_COULDNT_RESOLVE_HOST, CURLE_COULDNT_RESOLVE_PROXY, CURLE_SSL_CONNECT_ERROR], true);
            throw new TransportException($err !== '' ? $err : 'curl error', $errno === CURLE_OPERATION_TIMEDOUT, $connect);
        }
        return ['status' => $status, 'headers' => $respHeaders, 'body' => $buf];
    }
}
