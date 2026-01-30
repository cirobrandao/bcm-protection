<?php
namespace BCMProtection;

use BCMProtection\Admin\AdminPage;
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

    if (is_admin()) {
      (new AdminPage())->hooks();
    }

    // Comments
    add_filter('preprocess_comment', function ($commentdata) {
      if (!Checks::is_enabled('comments')) {
        return $commentdata;
      }
      $err = Checks::validate_request('comment');
      if ($err) {
        wp_die(esc_html($err), 'BCM Protection', ['response' => 403]);
      }
      return $commentdata;
    });

    // Registrations (wp-login.php?action=register)
    add_filter('registration_errors', function ($errors, $sanitized_user_login, $user_email) {
      if (!Checks::is_enabled('register')) {
        return $errors;
      }
      $err = Checks::validate_request('register');
      if ($err) {
        $errors->add('bcm_protection', $err);
      }
      return $errors;
    }, 10, 3);
  }
}
