<?php
if (!defined('ABSPATH')) { exit; }

class HET_AbuseIPDB_Admin {

    public static function init() {
        add_action('admin_menu', [__CLASS__, 'menu']);
        add_action('admin_init', [__CLASS__, 'register_settings']);
        add_action('admin_enqueue_scripts', [__CLASS__, 'assets']);
    }

    public static function menu() {
        add_menu_page(
            'AbuseIPDB',
            'AbuseIPDB',
            'manage_options',
            'het-abuseipdb',
            [__CLASS__, 'page'],
            'dashicons-shield-alt',
            58
        );
    }

    public static function register_settings() {
        register_setting('het_abuseipdb_group', HET_ABUSEIPDB_OPT, [
            'type' => 'array',
            'sanitize_callback' => [__CLASS__, 'sanitize_options'],
            'default' => [],
        ]);
    }

    public static function sanitize_options($in) {
        $in = is_array($in) ? $in : [];
        $out = HET_AbuseIPDB_Core::get_options();

        $out['enabled'] = !empty($in['enabled']) ? 1 : 0;
        $out['api_key'] = sanitize_text_field((string)($in['api_key'] ?? ''));
        $out['threshold'] = max(1, (int)($in['threshold'] ?? 10));
        $out['window_minutes'] = max(1, (int)($in['window_minutes'] ?? 30));
        $out['block_minutes'] = max(5, (int)($in['block_minutes'] ?? 1440));
        $out['categories'] = preg_replace('/[^0-9,]/', '', (string)($in['categories'] ?? '18,21'));
        $out['whitelist'] = (string)($in['whitelist'] ?? '');
        $out['log_limit'] = max(50, (int)($in['log_limit'] ?? 200));
        $out['report_on_block'] = !empty($in['report_on_block']) ? 1 : 0;
        $out['report_on_failed_login'] = !empty($in['report_on_failed_login']) ? 1 : 0;
        $out['report_on_404_probe'] = !empty($in['report_on_404_probe']) ? 1 : 0;
        $out['confidence'] = max(1, min(100, (int)($in['confidence'] ?? 60)));

        return $out;
    }

    public static function assets($hook) {
        if ($hook !== 'toplevel_page_het-abuseipdb') return;
        wp_enqueue_style('het-abuseipdb-admin', plugins_url('../assets/admin.css', __FILE__), [], HET_ABUSEIPDB_VER);
    }

    public static function page() {
        if (!current_user_can('manage_options')) return;

        if (isset($_POST['het_abuseipdb_unblock']) && check_admin_referer('het_abuseipdb_unblock')) {
            $ip = sanitize_text_field(wp_unslash($_POST['ip'] ?? ''));
            $blocked = get_option('het_abuseipdb_blocked', array());
            if (is_array($blocked) && $ip && isset($blocked[$ip])) {
                unset($blocked[$ip]);
                update_option('het_abuseipdb_blocked', $blocked, false);
                HET_AbuseIPDB_Core::log_event('UNBLOCK', $ip, 'Odblokowano ręcznie w panelu.');
                echo '<div class="notice notice-success"><p>Odblokowano IP: <code>' . esc_html($ip) . '</code></p></div>';
            }
        }

        if (isset($_POST['het_abuseipdb_report']) && check_admin_referer('het_abuseipdb_report')) {
            $ip = sanitize_text_field(wp_unslash($_POST['ip'] ?? ''));
            $comment = sanitize_textarea_field(wp_unslash($_POST['comment'] ?? 'Ręczne zgłoszenie z panelu.'));
            $opt = HET_AbuseIPDB_Core::get_options();
            if ($ip) {
                HET_AbuseIPDB_Core::maybe_report($ip, $comment, (string)$opt['categories']);
                echo '<div class="notice notice-info"><p>Wysłano próbę zgłoszenia dla IP: <code>' . esc_html($ip) . '</code></p></div>';
            }
        }

        $opt = HET_AbuseIPDB_Core::get_options();
        $log = get_option(HET_ABUSEIPDB_LOG, array());
        if (!is_array($log)) $log = array();
        $log = array_reverse($log);

        $blocked = HET_AbuseIPDB_Core::get_blocked_list();
        ?>
        <div class="wrap het-abuseipdb">
            <h1>Heterodyna AbuseIPDB – raportowanie i blokady</h1>

            <div class="het-grid">
                <div class="het-card">
                    <h2>Ustawienia</h2>
                    <form method="post" action="options.php">
                        <?php settings_fields('het_abuseipdb_group'); ?>
                        <?php $name = HET_ABUSEIPDB_OPT; ?>
                        <table class="form-table" role="presentation">
                            <tr>
                                <th scope="row">Włącz ochronę</th>
                                <td><label><input type="checkbox" name="<?php echo esc_attr($name); ?>[enabled]" value="1" <?php checked(!empty($opt['enabled'])); ?> /> aktywne</label></td>
                            </tr>
                            <tr>
                                <th scope="row">AbuseIPDB API Key</th>
                                <td>
                                    <input type="password" class="regular-text" name="<?php echo esc_attr($name); ?>[api_key]" value="<?php echo esc_attr($opt['api_key']); ?>" autocomplete="new-password" />
                                    <p class="description">Jeśli puste – raportowanie będzie wyłączone, ale blokady lokalne nadal działają.</p>
                                </td>
                            </tr>
                            <tr>
                                <th scope="row">Próg blokady</th>
                                <td><input type="number" min="1" max="200" name="<?php echo esc_attr($name); ?>[threshold]" value="<?php echo esc_attr((int)$opt['threshold']); ?>" /> <span class="description">domyślnie 10</span></td>
                            </tr>
                            <tr>
                                <th scope="row">Okno liczenia prób (min)</th>
                                <td><input type="number" min="1" max="1440" name="<?php echo esc_attr($name); ?>[window_minutes]" value="<?php echo esc_attr((int)$opt['window_minutes']); ?>" /></td>
                            </tr>
                            <tr>
                                <th scope="row">Czas blokady (min)</th>
                                <td><input type="number" min="5" max="43200" name="<?php echo esc_attr($name); ?>[block_minutes]" value="<?php echo esc_attr((int)$opt['block_minutes']); ?>" /> <span class="description">1440=24h</span></td>
                            </tr>
                            <tr>
                                <th scope="row">Kategorie AbuseIPDB</th>
                                <td>
                                    <input type="text" class="regular-text" name="<?php echo esc_attr($name); ?>[categories]" value="<?php echo esc_attr($opt['categories']); ?>" />
                                    <p class="description">np. <code>18,21</code></p>
                                </td>
                            </tr>
                            <tr>
                                <th scope="row">Whitelist (IP lub CIDR)</th>
                                <td>
                                    <textarea class="large-text code" rows="5" name="<?php echo esc_attr($name); ?>[whitelist]"><?php echo esc_textarea($opt['whitelist']); ?></textarea>
                                    <p class="description">Jeden wpis na linię. CIDR tylko IPv4, np. <code>1.2.3.0/24</code>. Admin zalogowany zawsze pomijany.</p>
                                </td>
                            </tr>
                            <tr>
                                <th scope="row">Raportuj do AbuseIPDB</th>
                                <td>
                                    <label><input type="checkbox" name="<?php echo esc_attr($name); ?>[report_on_block]" value="1" <?php checked(!empty($opt['report_on_block'])); ?> /> przy blokadzie (polecane)</label><br/>
                                    <label><input type="checkbox" name="<?php echo esc_attr($name); ?>[report_on_failed_login]" value="1" <?php checked(!empty($opt['report_on_failed_login'])); ?> /> przy każdym nieudanym logowaniu</label><br/>
                                    <label><input type="checkbox" name="<?php echo esc_attr($name); ?>[report_on_404_probe]" value="1" <?php checked(!empty($opt['report_on_404_probe'])); ?> /> przy probe 404</label>
                                </td>
                            </tr>
                            <tr>
                                <th scope="row">Limit logów</th>
                                <td><input type="number" min="50" max="2000" name="<?php echo esc_attr($name); ?>[log_limit]" value="<?php echo esc_attr((int)$opt['log_limit']); ?>" /></td>
                            </tr>
                        </table>
                        <?php submit_button('Zapisz ustawienia'); ?>
                    </form>
                </div>

                <div class="het-card">
                    <h2>Aktualnie zablokowane IP</h2>
                    <?php if (empty($blocked)): ?>
                        <p class="description">Brak aktywnych blokad 🎉</p>
                    <?php else: ?>
                        <table class="widefat striped">
                            <thead><tr><th>IP</th><th>Wygasa</th><th>Akcja</th></tr></thead>
                            <tbody>
                            <?php foreach ($blocked as $ip => $exp): ?>
                                <tr>
                                    <td><code><?php echo esc_html($ip); ?></code></td>
                                    <td><?php echo esc_html(date_i18n('Y-m-d H:i:s', (int)$exp)); ?></td>
                                    <td>
                                        <form method="post" style="display:inline">
                                            <?php wp_nonce_field('het_abuseipdb_unblock'); ?>
                                            <input type="hidden" name="ip" value="<?php echo esc_attr($ip); ?>"/>
                                            <button class="button" name="het_abuseipdb_unblock" value="1">Odblokuj</button>
                                        </form>
                                    </td>
                                </tr>
                            <?php endforeach; ?>
                            </tbody>
                        </table>
                    <?php endif; ?>

                    <hr/>
                    <h3>Ręczne zgłoszenie IP</h3>
                    <form method="post">
                        <?php wp_nonce_field('het_abuseipdb_report'); ?>
                        <p><input class="regular-text" type="text" name="ip" placeholder="np. 1.2.3.4" /></p>
                        <p><textarea class="large-text" rows="4" name="comment" placeholder="Opis incydentu..."></textarea></p>
                        <p><button class="button button-primary" name="het_abuseipdb_report" value="1">Wyślij zgłoszenie</button></p>
                    </form>
                </div>
            </div>

            <div class="het-card">
                <h2>Log zdarzeń (ostatnie)</h2>
                <?php if (empty($log)): ?>
                    <p class="description">Brak logów.</p>
                <?php else: ?>
                    <table class="widefat striped">
                        <thead><tr><th>Czas</th><th>Typ</th><th>IP</th><th>Notatka</th></tr></thead>
                        <tbody>
                        <?php foreach (array_slice($log, 0, 120) as $row): ?>
                            <tr>
                                <td><?php echo esc_html(date_i18n('Y-m-d H:i:s', (int)($row['ts'] ?? time()))); ?></td>
                                <td><code><?php echo esc_html($row['type'] ?? ''); ?></code></td>
                                <td><code><?php echo esc_html($row['ip'] ?? ''); ?></code></td>
                                <td><?php echo esc_html($row['note'] ?? ''); ?></td>
                            </tr>
                        <?php endforeach; ?>
                        </tbody>
                    </table>
                <?php endif; ?>
            </div>

            <p class="description">Wskazówka: jeśli jesteś za Cloudflare/reverse proxy, sprawdź czy IP klienta jest poprawnie przekazywane (CF-Connecting-IP).</p>
        </div>
        <?php
    }
}

HET_AbuseIPDB_Admin::init();
