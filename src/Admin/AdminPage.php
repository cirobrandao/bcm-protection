<?php
namespace BCMProtection\Admin;

final class AdminPage {
  private const OPT = 'bcm_protection_settings';

  public function hooks(): void {
    add_action('admin_menu', [$this, 'admin_menu']);
    add_action('admin_init', [$this, 'register_settings']);
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

    add_settings_section('bcm_protection_main', __('Protection', 'bcm-protection'), function () {
      echo '<p>Anti-bot checks for comment and registration forms. Default settings are safe for most sites.</p>';
    }, 'bcm-protection');

    $this->add_checkbox('enabled_comments', 'Enable on comments');
    $this->add_checkbox('enabled_register', 'Enable on registration');
    $this->add_number('min_seconds', 'Minimum submit time (seconds)', 1, 120);
    $this->add_number('max_age_hours', 'Max form age (hours)', 1, 168);
    $this->add_textarea('whitelist_ips', 'Allowlist IPs (one per line)');

    add_settings_section('bcm_protection_messages', __('Messages', 'bcm-protection'), function () {
      echo '<p>Customize the messages shown when a request is blocked.</p>';
    }, 'bcm-protection');

    $this->add_text('error_spam', 'Spam message');
    $this->add_text('error_nonce', 'Nonce/CSRF message');
    $this->add_text('error_fast', 'Too-fast message');
    $this->add_text('error_expired', 'Expired message');

    add_settings_section('bcm_protection_logs', __('Logging', 'bcm-protection'), function () {
      echo '<p>Logs are stored locally (last 200 entries). Useful for debugging.</p>';
    }, 'bcm-protection');
    $this->add_checkbox('log_enabled', 'Enable logs');
  }

  private function add_checkbox(string $key, string $label): void {
    add_settings_field('bcm_' . $key, esc_html($label), function () use ($key) {
      $s = self::get_settings();
      $val = !empty($s[$key]) ? 1 : 0;
      echo '<label><input type="checkbox" name="' . esc_attr(self::OPT) . '[' . esc_attr($key) . ']" value="1" ' . checked(1, $val, false) . '> ' . esc_html__('Enabled', 'bcm-protection') . '</label>';
    }, 'bcm-protection', 'bcm_protection_main');
  }

  private function add_number(string $key, string $label, int $min, int $max): void {
    add_settings_field('bcm_' . $key, esc_html($label), function () use ($key, $min, $max) {
      $s = self::get_settings();
      $val = isset($s[$key]) ? (int)$s[$key] : 0;
      echo '<input type="number" name="' . esc_attr(self::OPT) . '[' . esc_attr($key) . ']" value="' . esc_attr((string)$val) . '" min="' . esc_attr((string)$min) . '" max="' . esc_attr((string)$max) . '" class="small-text">';
    }, 'bcm-protection', 'bcm_protection_main');
  }

  private function add_textarea(string $key, string $label): void {
    add_settings_field('bcm_' . $key, esc_html($label), function () use ($key) {
      $s = self::get_settings();
      $val = isset($s[$key]) ? (string)$s[$key] : '';
      echo '<textarea name="' . esc_attr(self::OPT) . '[' . esc_attr($key) . ']" rows="5" class="large-text code">' . esc_textarea($val) . '</textarea>';
      echo '<p class="description">If your IP is allowlisted, protection checks are skipped for you.</p>';
    }, 'bcm-protection', 'bcm_protection_main');
  }

  private function add_text(string $key, string $label): void {
    add_settings_field('bcm_' . $key, esc_html($label), function () use ($key) {
      $s = self::get_settings();
      $val = isset($s[$key]) ? (string)$s[$key] : '';
      echo '<input type="text" name="' . esc_attr(self::OPT) . '[' . esc_attr($key) . ']" value="' . esc_attr($val) . '" class="large-text">';
    }, 'bcm-protection', 'bcm_protection_messages');
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

    $logs = get_option('bcm_protection_logs', []);
    if (!is_array($logs)) {
      $logs = [];
    }

    echo '<div class="wrap">';
    echo '<h1>BCM Protection</h1>';
    echo '<form method="post" action="options.php">';
    settings_fields('bcm_protection');
    do_settings_sections('bcm-protection');
    submit_button();
    echo '</form>';

    echo '<hr />';
    echo '<h2>Recent blocks</h2>';

    if (!$logs) {
      echo '<p>No logs yet.</p>';
    } else {
      echo '<table class="widefat striped"><thead><tr><th>Time (UTC)</th><th>Context</th><th>Reason</th><th>IP</th><th>UA</th></tr></thead><tbody>';
      foreach (array_slice($logs, 0, 50) as $row) {
        if (!is_array($row)) continue;
        echo '<tr>';
        echo '<td>' . esc_html(gmdate('Y-m-d H:i:s', (int)($row['ts'] ?? 0))) . '</td>';
        echo '<td>' . esc_html((string)($row['context'] ?? '')) . '</td>';
        echo '<td>' . esc_html((string)($row['reason'] ?? '')) . '</td>';
        echo '<td><code>' . esc_html((string)($row['ip'] ?? '')) . '</code></td>';
        echo '<td style="max-width:520px; overflow:hidden; text-overflow:ellipsis; white-space:nowrap;">' . esc_html((string)($row['ua'] ?? '')) . '</td>';
        echo '</tr>';
      }
      echo '</tbody></table>';
      echo '<p class="description">Showing last 50 entries.</p>';
    }

    echo '</div>';
  }
}
