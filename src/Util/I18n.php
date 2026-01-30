<?php
namespace BCMProtection\Util;

final class I18n {
  private const OPT = 'bcm_protection_settings';

  public static function load(): void {
    load_plugin_textdomain('bcm-protection', false, dirname(plugin_basename(BCM_PROTECTION_FILE)) . '/languages');

    $settings = get_option(self::OPT, []);
    $lang = is_array($settings) ? ($settings['ui_language'] ?? 'default') : 'default';
    $lang = is_string($lang) ? $lang : 'default';

    // WP default is en_US. We only ship pt_BR for now.
    if ($lang === 'pt_BR') {
      // Force-load pt_BR catalog for this plugin.
      $mofile = BCM_PROTECTION_DIR . 'languages/bcm-protection-pt_BR.mo';
      if (file_exists($mofile)) {
        unload_textdomain('bcm-protection');
        load_textdomain('bcm-protection', $mofile);
      }
    }
  }
}
