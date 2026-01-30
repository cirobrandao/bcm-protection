<?php
namespace BCMProtection\Frontend;

final class Honeypot {
  public function hooks(): void {
    // Start session timing for front-end forms.
    add_action('init', [$this, 'init']);

    // Comment form field.
    add_action('comment_form_after_fields', [$this, 'render_fields']);
    add_action('comment_form_logged_in_after', [$this, 'render_fields']);

    // Registration form field.
    add_action('register_form', [$this, 'render_fields']);
  }

  public function init(): void {
    if (!session_id() && !headers_sent()) {
      // Low-risk: only used for timestamp. If host forbids sessions, plugin still works (it falls back).
      @session_start();
    }

    if (empty($_SESSION['bcm_protection_started'])) {
      $_SESSION['bcm_protection_started'] = time();
    }
  }

  public function render_fields(): void {
    // Honeypot (hidden). Bots often fill all inputs.
    echo '<p style="display:none">';
    echo '<label for="bcm_hp">Leave this field empty</label>';
    echo '<input type="text" name="bcm_hp" id="bcm_hp" value="" autocomplete="off" tabindex="-1" />';
    echo '</p>';

    // Timestamp (hidden). Helps detect ultra-fast submissions.
    $ts = time();
    echo '<input type="hidden" name="bcm_ts" value="' . esc_attr((string)$ts) . '">';

    // Nonce.
    wp_nonce_field('bcm_protection', 'bcm_nonce');
  }
}
