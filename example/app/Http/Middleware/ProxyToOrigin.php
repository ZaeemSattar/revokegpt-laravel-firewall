<?php

namespace App\Http\Middleware;

use Closure;
use Illuminate\Http\Request;
use Symfony\Component\HttpFoundation\Response;

/**
 * Forwards every request that survived the firewall to RG_ORIGIN over a raw HTTP/1.1 socket, with
 * the request target byte for byte as received (REQUEST_URI), the original Host and every header
 * the firewall left in place. Terminal: it never calls $next, so no route is involved.
 */
class ProxyToOrigin
{
    private const HOP = ['connection', 'keep-alive', 'proxy-authenticate', 'proxy-authorization', 'proxy-connection',
        'te', 'trailer', 'transfer-encoding', 'upgrade', 'content-length'];

    public function handle(Request $request, Closure $next): Response
    {
        $origin = parse_url((string) getenv('RG_ORIGIN'));
        if ($origin === false || ($origin['scheme'] ?? '') !== 'http' || !isset($origin['host'])) {
            return new Response('RG_ORIGIN must be an http URL', 500);
        }
        $target = (string) $request->server->get('REQUEST_URI');
        $body = (string) $request->getContent();
        $head = $request->server->get('REQUEST_METHOD') . ' ' . $target . " HTTP/1.1\r\n";
        foreach ($request->headers->all() as $name => $values) {
            if (in_array($name, self::HOP, true)) {
                continue;
            }
            foreach ($values as $v) {
                $head .= $name . ': ' . $v . "\r\n";
            }
        }
        if ($body !== '') {
            $head .= 'Content-Length: ' . strlen($body) . "\r\n";
        }
        $head .= "Connection: close\r\n\r\n";

        $fp = @stream_socket_client('tcp://' . $origin['host'] . ':' . ($origin['port'] ?? 80), $errno, $errstr, 5);
        if ($fp === false) {
            return new Response('bad gateway', 502);
        }
        stream_set_timeout($fp, 10);
        fwrite($fp, $head . $body);
        $raw = stream_get_contents($fp);
        fclose($fp);

        $split = strpos((string) $raw, "\r\n\r\n");
        if ($split === false) {
            return new Response('bad gateway', 502);
        }
        $lines = explode("\r\n", substr($raw, 0, $split));
        $status = (int) (explode(' ', array_shift($lines))[1] ?? 502);
        $out = new Response($request->isMethod('HEAD') ? '' : substr($raw, $split + 4), $status);
        foreach ($lines as $line) {
            $i = strpos($line, ':');
            if ($i === false) {
                continue;
            }
            $name = trim(substr($line, 0, $i));
            if (in_array(strtolower($name), self::HOP, true)) {
                continue;
            }
            $out->headers->set($name, trim(substr($line, $i + 1)), false);
        }
        return $out;
    }
}
