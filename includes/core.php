<?php
if (!defined('ABSPATH')) { exit; }

class HET_AbuseIPDB_Core {

    public static function init() {
        add_action('init', [__CLASS__, 'maybe_block_request'], 0);
        add_action('wp_login_failed', [__CLASS__, 'on_login_failed'], 10, 1);
        add_action('template_redirect', [__CLASS__, 'on_template_redirect'], 1);
        add_action('wp_footer', [__CLASS__, 'noop'], 99);
    }

    public static function noop(){}

    public static function get_options() {
        $opt = get_option(HET_ABUSEIPDB_OPT, array());
        if (!is_array($opt)) $opt = array();
        return wp_parse_args($opt, array(
            'api_key' => '',
            'enabled' => 1,
            'threshold' => 10,
            'window_minutes' => 30,
            'block_minutes' => 1440,
            'categories' => '18,21',
            'whitelist' => '',
            'log_limit' => 200,
            'report_on_block' => 1,
            'report_on_failed_login' => 0,
            'report_on_404_probe' => 0,
            'confidence' => 60,
        ));
    }

    public static function get_ip() {
        $candidates = array(
            'HTTP_CF_CONNECTING_IP',
            'HTTP_X_FORWARDED_FOR',
            'HTTP_X_REAL_IP',
            'REMOTE_ADDR',
        );
        foreach ($candidates as $k) {
            if (!empty($_SERVER[$k])) {
                $raw = sanitize_text_field(wp_unslash($_SERVER[$k]));
                $parts = array_map('trim', explode(',', $raw));
                $ip = $parts[0] ?? '';
                if (filter_var($ip, FILTER_VALIDATE_IP)) {
                    return $ip;
                }
            }
        }
        return '';
    }

    public static function is_whitelisted($ip, $opt=null) {
        if (!$ip) return true;
        if ($opt === null) $opt = self::get_options();

        if (is_user_logged_in() && current_user_can('manage_options')) return true;
        if (defined('WP_CLI') && WP_CLI) return true;

        $wl = trim((string)$opt['whitelist']);
        if ($wl === '') return false;

        $lines = preg_split('/\r\n|\r|\n/', $wl);
        foreach ($lines as $line) {
            $line = trim($line);
            if ($line === '') continue;
            if (strpos($line, '/') !== false) {
                if (self::ip_in_cidr($ip, $line)) return true;
            } else {
                if ($ip === $line) return true;
            }
        }
        return false;
    }

    private static function ip_in_cidr($ip, $cidr) {
        if (!filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4)) return false;
        $parts = explode('/', $cidr, 2);
        if (count($parts) !== 2) return false;
        [$subnet, $mask] = $parts;
        if (!filter_var($subnet, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4)) return false;
        $mask = (int)$mask;
        if ($mask < 0 || $mask > 32) return false;

        $ip_long = ip2long($ip);
        $subnet_long = ip2long($subnet);
        $mask_long = -1 << (32 - $mask);
        $subnet_long &= $mask_long;
        return ($ip_long & $mask_long) === $subnet_long;
    }

    public static function is_blocked($ip) {
        if (!$ip) return false;
        $blocked = get_option('het_abuseipdb_blocked', array());
        if (!is_array($blocked)) $blocked = array();
        if (!isset($blocked[$ip])) return false;
        $exp = (int)$blocked[$ip];
        if ($exp <= 0) return false;
        if (time() > $exp) {
            unset($blocked[$ip]);
            update_option('het_abuseipdb_blocked', $blocked, false);
            return false;
        }
        return true;
    }

    public static function block_ip($ip, $minutes, $reason='') {
        if (!$ip) return;
        $blocked = get_option('het_abuseipdb_blocked', array());
        if (!is_array($blocked)) $blocked = array();
        $blocked[$ip] = time() + max(1, (int)$minutes) * 60;
        update_option('het_abuseipdb_blocked', $blocked, false);
        self::log_event('BLOCK', $ip, $reason ?: 'Zablokowano IP.');
    }

    public static function maybe_block_request() {
        $opt = self::get_options();
        if (empty($opt['enabled'])) return;

        $ip = self::get_ip();
        if (self::is_whitelisted($ip, $opt)) return;

        if (self::is_blocked($ip)) {
            status_header(403);
            nocache_headers();
            header('Content-Type: text/plain; charset=UTF-8');
            echo "Dostęp zablokowany (403). Jeśli to pomyłka, skontaktuj się z administratorem.\n";
            exit;
        }

        $uri = isset($_SERVER['REQUEST_URI']) ? sanitize_text_field(wp_unslash($_SERVER['REQUEST_URI'])) : '';
        $method = isset($_SERVER['REQUEST_METHOD']) ? sanitize_text_field(wp_unslash($_SERVER['REQUEST_METHOD'])) : '';

        $needle = strtolower($uri);
        $targets = array(
            '/wp-admin/install.php' => 'Próba wejścia w instalator',
            '/wp-admin/upgrade.php' => 'Próba wejścia w upgrade',
            '/xmlrpc.php'           => 'XML-RPC probing',
            '/wp-login.php'         => 'Wejście na stronę logowania',
            '/.env'                 => 'Skan .env',
            '/.git'                 => 'Skan .git',
            '/wp-config.php'        => 'Skan wp-config.php',
        );

        foreach ($targets as $path => $msg) {
            if (strpos($needle, strtolower($path)) !== false) {
                if ($path === '/wp-login.php' && strtoupper($method) === 'GET') {
                    self::log_event('HIT', $ip, $msg . ' (GET)');
                    return;
                }
                self::register_attempt($ip, $msg);
                return;
            }
        }
    }

    public static function on_login_failed($username) {
        $opt = self::get_options();
        if (empty($opt['enabled'])) return;

        $ip = self::get_ip();
        if (self::is_whitelisted($ip, $opt)) return;

        $reason = 'Nieudane logowanie (wp_login_failed) użytkownik: ' . sanitize_text_field((string)$username);
        self::register_attempt($ip, $reason);

        if (!empty($opt['report_on_failed_login'])) {
            self::maybe_report($ip, $reason, '18');
        }
    }

    public static function on_template_redirect() {
        $opt = self::get_options();
        if (empty($opt['enabled'])) return;
        if (!is_404()) return;

        $ip = self::get_ip();
        if (self::is_whitelisted($ip, $opt)) return;

        $uri = isset($_SERVER['REQUEST_URI']) ? sanitize_text_field(wp_unslash($_SERVER['REQUEST_URI'])) : '';
        $needle = strtolower($uri);

        $probe_patterns = array(
            '/wp-content/plugins/',
            '/wp-content/themes/',
            'phpmyadmin',
            'adminer',
            'wp-config.php',
            '.git',
            '.env',
            'composer.json',
            'vendor/phpunit',
        );

        foreach ($probe_patterns as $p) {
            if (strpos($needle, strtolower($p)) !== false) {
                $reason = 'Skan 404/probe: ' . $uri;
                self::register_attempt($ip, $reason);

                if (!empty($opt['report_on_404_probe'])) {
                    self::maybe_report($ip, $reason, (string)$opt['categories']);
                }
                return;
            }
        }
    }

    public static function register_attempt($ip, $reason) {
        $opt = self::get_options();
        if (!$ip) return;

        $threshold = max(1, (int)$opt['threshold']);
        $window = max(1, (int)$opt['window_minutes']);

        $key = 'het_abuseipdb_attempts_' . md5($ip);
        $data = get_transient($key);
        if (!is_array($data)) $data = array('count' => 0, 'first' => time());
        $data['count'] = (int)$data['count'] + 1;
        set_transient($key, $data, $window * 60);

        self::log_event('TRY', $ip, $reason . ' | licznik=' . $data['count'] . '/' . $threshold);

        if ($data['count'] >= $threshold) {
            $block_minutes = max(5, (int)$opt['block_minutes']);
            self::block_ip($ip, $block_minutes, 'Próg przekroczony: ' . $reason);

            if (!empty($opt['report_on_block'])) {
                self::maybe_report($ip, 'Zablokowano po ' . $threshold . ' próbach. Ostatni powód: ' . $reason, (string)$opt['categories']);
            }
        }
    }

    public static function maybe_report($ip, $comment, $categories) {
        $opt = self::get_options();
        $api_key = trim((string)$opt['api_key']);
        if ($api_key === '' || !$ip) return;

        $rk = 'het_abuseipdb_reported_' . md5($ip);
        if (get_transient($rk)) return;

        $ua = isset($_SERVER['HTTP_USER_AGENT']) ? sanitize_text_field(wp_unslash($_SERVER['HTTP_USER_AGENT'])) : '';
        $uri = isset($_SERVER['REQUEST_URI']) ? sanitize_text_field(wp_unslash($_SERVER['REQUEST_URI'])) : '';
        $ref = isset($_SERVER['HTTP_REFERER']) ? sanitize_text_field(wp_unslash($_SERVER['HTTP_REFERER'])) : '';

        $full_comment = trim((string)$comment);
        $full_comment .= "\nURL: " . $uri;
        if ($ref) $full_comment .= "\nRef: " . $ref;
        if ($ua)  $full_comment .= "\nUA: " . $ua;
        if (strlen($full_comment) > 900) $full_comment = substr($full_comment, 0, 900) . '...';

        $body = array(
            'ip' => $ip,
            'categories' => preg_replace('/\s+/', '', (string)$categories),
            'comment' => $full_comment,
        );

        $args = array(
            'timeout' => 12,
            'headers' => array(
                'Key' => $api_key,
                'Accept' => 'application/json',
            ),
            'body' => $body,
        );

        $resp = wp_remote_post('https://api.abuseipdb.com/api/v2/report', $args);
        $code = is_wp_error($resp) ? 0 : (int)wp_remote_retrieve_response_code($resp);
        $ok = ($code >= 200 && $code < 300);

        if ($ok) {
            set_transient($rk, 1, 12 * HOUR_IN_SECONDS);
            self::log_event('REPORT', $ip, 'Zgłoszono do AbuseIPDB (HTTP ' . $code . ').');
        } else {
            $msg = is_wp_error($resp) ? $resp->get_error_message() : ('HTTP ' . $code . ' ' . wp_remote_retrieve_body($resp));
            self::log_event('REPORT_FAIL', $ip, 'Nie udało się zgłosić: ' . substr((string)$msg, 0, 240));
        }
    }

    public static function log_event($type, $ip, $note) {
        $opt = self::get_options();
        $limit = !empty($opt['log_limit']) ? max(50, (int)$opt['log_limit']) : 200;

        $log = get_option(HET_ABUSEIPDB_LOG, array());
        if (!is_array($log)) $log = array();

        $log[] = array(
            'ts' => time(),
            'type' => sanitize_text_field((string)$type),
            'ip' => sanitize_text_field((string)$ip),
            'note' => sanitize_text_field((string)$note),
        );

        if (count($log) > $limit) $log = array_slice($log, -$limit);
        update_option(HET_ABUSEIPDB_LOG, $log, false);
    }

    public static function get_blocked_list() {
        $blocked = get_option('het_abuseipdb_blocked', array());
        if (!is_array($blocked)) $blocked = array();
        $now = time();
        $changed = false;
        foreach ($blocked as $ip => $exp) {
            if ((int)$exp > 0 && $now > (int)$exp) { unset($blocked[$ip]); $changed = true; }
        }
        if ($changed) update_option('het_abuseipdb_blocked', $blocked, false);
        return $blocked;
    }
}

HET_AbuseIPDB_Core::init();
