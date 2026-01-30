<?php
namespace BCMProtection\Util;

final class Checks {
  public static function validate_request(string $context): ?string {
    // Only enforce on POST requests.
    if (($_SERVER['REQUEST_METHOD'] ?? '') !== 'POST') {
      return null;
    }

    // If it's a REST/API flow or CLI, skip.
    if (defined('WP_CLI') && WP_CLI) {
      return null;
    }

    // Honeypot.
    $hp = isset($_POST['bcm_hp']) ? (string)$_POST['bcm_hp'] : '';
    if (trim($hp) !== '') {
      return 'Spam detected.';
    }

    // Nonce.
    $nonce = isset($_POST['bcm_nonce']) ? (string)$_POST['bcm_nonce'] : '';
    if (!$nonce || !wp_verify_nonce($nonce, 'bcm_protection')) {
      return 'Security check failed. Please try again.';
    }

    // Timing.
    $ts = isset($_POST['bcm_ts']) ? (int)$_POST['bcm_ts'] : 0;
    if ($ts > 0) {
      $delta = time() - $ts;
      // Too fast usually means bot.
      if ($delta < 3) {
        return 'Submission too fast. Please try again.';
      }
      // Too old (stale cached form or replay).
      if ($delta > 12 * HOUR_IN_SECONDS) {
        return 'Form expired. Please reload and try again.';
      }
    }

    // Basic heuristics: empty UA is suspicious.
    $ua = isset($_SERVER['HTTP_USER_AGENT']) ? (string)$_SERVER['HTTP_USER_AGENT'] : '';
    if ($ua === '') {
      return 'Spam detected.';
    }

    return null;
  }
}
