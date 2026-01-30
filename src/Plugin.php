<?php
namespace BCMProtection;

use BCMProtection\Frontend\Honeypot;
use BCMProtection\Util\Checks;

final class Plugin {
  private static ?Plugin $instance = null;

  public static function instance(): Plugin {
    if (self::$instance === null) {
      self::$instance = new self();
    }
    return self::$instance;
  }

  public function boot(): void {
    (new Honeypot())->hooks();

    // Comments
    add_filter('preprocess_comment', function ($commentdata) {
      $err = Checks::validate_request('comment');
      if ($err) {
        // Using wp_die blocks spam before insert.
        wp_die(esc_html($err), 'BCM Protection', ['response' => 403]);
      }
      return $commentdata;
    });

    // Registrations (wp-login.php?action=register)
    add_filter('registration_errors', function ($errors, $sanitized_user_login, $user_email) {
      $err = Checks::validate_request('register');
      if ($err) {
        $errors->add('bcm_protection', $err);
      }
      return $errors;
    }, 10, 3);
  }
}
