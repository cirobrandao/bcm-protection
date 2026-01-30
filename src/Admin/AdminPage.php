<?php
namespace BCMProtection\Admin;

final class AdminPage {
  private const OPT = 'bcm_protection_settings';

  public function hooks(): void {
    add_action('admin_menu', [$this, 'admin_menu']);
    add_action('admin_init', [$this, 'register_settings']);
    add_action('admin_enqueue_scripts', [$this, 'enqueue_assets']);
  }

  public function enqueue_assets(string $hook): void {
    // Tools → BCM Protection
    if ($hook !== 'tools_page_bcm-protection') {
      return;
    }

    wp_enqueue_style(
      'bcm-protection-admin',
      plugins_url('assets/admin.css', BCM_PROTECTION_FILE),
      [],
      BCM_PROTECTION_VERSION
    );
  }

  public function admin_menu(): void {
    add_management_page(
      __('BCM Protection', 'bcm-protection'),
      __('BCM Protection', 'bcm-protection'),
      'manage_options',
      'bcm-protection',
      [$this, 'render']
    );
  }

  public static function defaults(): array {
    return [
      'enabled_comments' => 1,
      'enabled_register' => 1,
      'min_seconds' => 3,
      'max_age_hours' => 12,
      'whitelist_ips' => "",
      'error_spam' => 'Spam detected.',
      'error_nonce' => 'Security check failed. Please try again.',
      'error_fast' => 'Submission too fast. Please try again.',
      'error_expired' => 'Form expired. Please reload and try again.',
      'log_enabled' => 1,
    ];
  }

  public static function get_settings(): array {
    $raw = get_option(self::OPT, []);
    if (!is_array($raw)) {
      $raw = [];
    }
    return array_merge(self::defaults(), $raw);
  }

  public function register_settings(): void {
    register_setting('bcm_protection', self::OPT, [
      'type' => 'array',
      'sanitize_callback' => [$this, 'sanitize'],
      'default' => self::defaults(),
    ]);
  }

  public function sanitize($input): array {
    $in = is_array($input) ? $input : [];
    $out = self::defaults();

    $out['enabled_comments'] = !empty($in['enabled_comments']) ? 1 : 0;
    $out['enabled_register'] = !empty($in['enabled_register']) ? 1 : 0;
    $out['min_seconds'] = max(1, min(120, (int)($in['min_seconds'] ?? $out['min_seconds'])));
    $out['max_age_hours'] = max(1, min(168, (int)($in['max_age_hours'] ?? $out['max_age_hours'])));
    $out['whitelist_ips'] = sanitize_textarea_field((string)($in['whitelist_ips'] ?? ''));

    $out['error_spam'] = sanitize_text_field((string)($in['error_spam'] ?? $out['error_spam']));
    $out['error_nonce'] = sanitize_text_field((string)($in['error_nonce'] ?? $out['error_nonce']));
    $out['error_fast'] = sanitize_text_field((string)($in['error_fast'] ?? $out['error_fast']));
    $out['error_expired'] = sanitize_text_field((string)($in['error_expired'] ?? $out['error_expired']));

    $out['log_enabled'] = !empty($in['log_enabled']) ? 1 : 0;

    return $out;
  }

  public function render(): void {
    if (!current_user_can('manage_options')) {
      return;
    }

    $tab = isset($_GET['tab']) ? sanitize_key((string)$_GET['tab']) : 'protection';
    if (!in_array($tab, ['protection', 'messages', 'logs'], true)) {
      $tab = 'protection';
    }

    $s = self::get_settings();

    echo '<div class="wrap bcmpro-wrap">';
    echo '<h1>BCM Protection</h1>';

    echo '<p class="bcmpro-help">Anti-bot/spam protection for Comments and User Registration. No external services.</p>';

    // Tabs
    $base = admin_url('tools.php?page=bcm-protection');
    echo '<h2 class="nav-tab-wrapper">';
    $this->tab_link($base, 'protection', $tab, 'Protection');
    $this->tab_link($base, 'messages', $tab, 'Messages');
    $this->tab_link($base, 'logs', $tab, 'Logs');
    echo '</h2>';

    if ($tab === 'logs') {
      $this->render_logs();
      echo '</div>';
      return;
    }

    echo '<form method="post" action="options.php">';
    settings_fields('bcm_protection');

    echo '<div class="bcmpro-grid">';

    if ($tab === 'protection') {
      echo '<div class="bcmpro-card">';
      echo '<h2>Protection</h2>';
      echo '<p class="bcmpro-help">Choose where to apply the protection and tune the timing checks.</p>';

      $this->checkbox(self::OPT . '[enabled_comments]', !empty($s['enabled_comments']), 'Enable on comments');
      echo '<br>';
      $this->checkbox(self::OPT . '[enabled_register]', !empty($s['enabled_register']), 'Enable on registration');

      echo '<hr />';

      $this->number(self::OPT . '[min_seconds]', (int)$s['min_seconds'], 1, 120, 'Minimum submit time (seconds)');
      echo '<p class="bcmpro-help">Bots often submit instantly. Default: 3 seconds.</p>';

      $this->number(self::OPT . '[max_age_hours]', (int)$s['max_age_hours'], 1, 168, 'Max form age (hours)');
      echo '<p class="bcmpro-help">Helps prevent replay of cached/old forms. Default: 12 hours.</p>';
      echo '</div>';

      echo '<div class="bcmpro-card">';
      echo '<h2>Allowlist</h2>';
      echo '<p class="bcmpro-help">Requests from allowlisted IPs will bypass checks (useful for your own testing).</p>';
      $this->textarea(self::OPT . '[whitelist_ips]', (string)$s['whitelist_ips'], 'Allowlist IPs (one per line)');
      echo '<p class="bcmpro-warn"><strong>Tip:</strong> do not allowlist wide ranges unless you really trust them.</p>';

      echo '<hr />';
      $this->checkbox(self::OPT . '[log_enabled]', !empty($s['log_enabled']), 'Enable logs (recommended)');
      echo '<p class="bcmpro-help">Keeps last 200 block events. View them in the Logs tab.</p>';
      echo esc_html($line) . "\n";
    }
    echo '</code></div>';

    echo '</div>';
  }
}
