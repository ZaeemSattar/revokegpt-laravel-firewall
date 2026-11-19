<?php
// Test fixture: a TCP server. argv[1] = mode (reset|slow). Prints its port, then serves.
$srv = stream_socket_server('tcp://127.0.0.1:0', $errno, $errstr);
$port = (int) substr(strrchr(stream_socket_get_name($srv, false), ':'), 1);
echo $port, "\n";
fflush(STDOUT);
while (($c = @stream_socket_accept($srv, 15)) !== false) {
    fread($c, 4096); // the request was sent
    if ($argv[1] === 'reset') {
        $raw = socket_import_stream($c);
        socket_set_option($raw, SOL_SOCKET, SO_LINGER, ['l_onoff' => 1, 'l_linger' => 0]);
        fclose($c);
        continue;
    }
    fwrite($c, "HTTP/1.1 200 OK\r\nContent-Length: 100\r\n\r\n{");
    for ($i = 0; $i < 40; $i++) {
        usleep(200000);
        if (@fwrite($c, ' ') === false) {
            break;
        }
    }
    fclose($c);
}
