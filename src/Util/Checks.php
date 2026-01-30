<?php
namespace BCMProtection\Util;

use BCMProtection\Admin\AdminPage;

final class Checks {
  public static function is_enabled(string $feature): bool {
    $s = AdminPage::get_settings();
    if ($feature === 'comments') {
      return !empty($s['enabled_comments']);
    }
    if ($feature === 'register') {
      return !empty($s['enabled_register']);
    }
    return true;
  }

  public static function validate_request(string $context): ?string {
    // Only enforce on POST requests.
    if (($_SERVER['REQUEST_METHOD'] ?? '') !== 'POST') {
      return null;
    }

    // If it's CLI, skip.
    if (defined('WP_CLI') && WP_CLI) {
      return null;
    }

    // Allowlist IPs.
    $ip = self::client_ip();
    if (self::ip_is_allowlisted($ip)) {
      return null;
    }

    $s = AdminPage::get_settings();

    // Honeypot.
    $hp = isset($_POST['bcm_hp']) ? (string)$_POST['bcm_hp'] : '';
    if (trim($hp) !== '') {
      self::log_block($context, 'honeypot');
      return (string)$s['error_spam'];
    }

    // Nonce.
    $nonce = isset($_POST['bcm_nonce']) ? (string)$_POST['bcm_nonce'] : '';
    if (!$nonce || !wp_verify_nonce($nonce, 'bcm_protection')) {
      self::log_block($context, 'nonce');
      return (string)$s['error_nonce'];
    }

    // Timing.
    $ts = isset($_POST['bcm_ts']) ? (int)$_POST['bcm_ts'] : 0;
    if ($ts > 0) {
      $delta = time() - $ts;

      $min = max(1, (int)$s['min_seconds']);
      if ($delta < $min) {
        self::log_block($context, 'too_fast');
        return (string)$s['error_fast'];
      }

      $maxAge = max(1, (int)$s['max_age_hours']) * HOUR_IN_SECONDS;
      if ($delta > $maxAge) {
        self::log_block($context, 'expired');
        return (string)$s['error_expired'];
      }
    }

    // Basic heuristics: empty UA is suspicious.
    $ua = isset($_SERVER['HTTP_USER_AGENT']) ? (string)$_SERVER['HTTP_USER_AGENT'] : '';
    if ($ua === '') {
      self::log_block($context, 'empty_ua');
      return (string)$s['error_spam'];
    }

    return null;
  }

  private static function ip_is_allowlisted(string $ip): bool {
    if (!$ip) return false;
    $s = AdminPage::get_settings();
    $raw = (string)($s['whitelist_ips'] ?? '');
    $lines = preg_split('/\r\n|\r|\n/', $raw);
    if (!is_array($lines)) return false;
    foreach ($lines as $line) {
      $line = trim((string)$line);
      if ($line === '') continue;
      if ($line === $ip) return true;
    }
    return false;
  }

  private static function client_ip(): string {
    return isset($_SERVER['REMOTE_ADDR']) ? (string)$_SERVER['REMOTE_ADDR'] : '';
  }

  private static function log_block(string $context, string $reason): void {
    $s = AdminPage::get_settings();
    if (empty($s['log_enabled'])) {
      return;
    }

    $logs = get_option('bcm_protection_logs', []);
    if (!is_array($logs)) {
      $logs = [];
    }

    array_unshift($logs, [
      'ts' => time(),
      'context' => $context,
      'reason' => $reason,
      'ip' => self::client_ip(),
      'ua' => isset($_SERVER['HTTP_USER_AGENT']) ? (string)$_SERVER['HTTP_USER_AGENT'] : '',
    ]);

    // Keep last 200.
    $logs = array_slice($logs, 0, 200);
    update_option('bcm_protection_logs', $logs, false);
  }
}
