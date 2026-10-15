<?php
/*
Plugin Name: Heterodyna AbuseIPDB
Description: Raportuje podejrzane próby dostępu/ataku do AbuseIPDB oraz automatycznie blokuje IP po 10 próbach w oknie czasowym.
Version: 01.001.0001
Author: Heterodyna Team Software
Author URI: https://heterodyna.pl
Text Domain: heterodyna-abuseipdb
*/

if (!defined('ABSPATH')) { exit; }

define('HET_ABUSEIPDB_VER', '01.001.0001');
define('HET_ABUSEIPDB_SLUG', 'heterodyna-abuseipdb');
define('HET_ABUSEIPDB_OPT',  'het_abuseipdb_options');
define('HET_ABUSEIPDB_LOG',  'het_abuseipdb_log');

require_once __DIR__ . '/includes/core.php';
require_once __DIR__ . '/includes/admin.php';

register_activation_hook(__FILE__, function(){
    if (!get_option(HET_ABUSEIPDB_OPT)) {
        add_option(HET_ABUSEIPDB_OPT, array(
            'api_key' => '',
            'enabled' => 1,
            'threshold' => 10,
            'window_minutes' => 30,
            'block_minutes' => 1440,
            'categories' => '18,21', // Brute-Force, Web App Attack
            'whitelist' => '',
            'log_limit' => 200,
            'report_on_block' => 1,
            'report_on_failed_login' => 0,
            'report_on_404_probe' => 0,
            'confidence' => 60,
        ));
    }
});

register_deactivation_hook(__FILE__, function(){
    // nic
});
