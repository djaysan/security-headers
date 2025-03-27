# security-headers

'''
function set_security_headers() {
    if (!headers_sent()) {
        header("Strict-Transport-Security: max-age=31536000; includeSubDomains; preload");
        header("X-Frame-Options: DENY");
        header("X-Content-Type-Options: nosniff");
        header("Referrer-Policy: strict-origin");
        header("Permissions-Policy: geolocation=(), microphone=(), camera=(), usb=(), bluetooth=(), payment=()");
        if (function_exists('header_remove')) {
            header_remove("X-Powered-By");
        }
    }
}
add_action('send_headers', 'set_security_headers');
'''
