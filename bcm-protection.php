<?php
/**
 * Plugin Name:       BCM Protection
 * Plugin URI:        https://github.com/cirobrandao/bcm-protection
 * Description:       Lightweight anti-bot/spam protection for comments and user registrations (honeypot + timing + basic heuristics).
 * Version:           0.2.0
 * Requires at least: 6.0
 * Requires PHP:      7.4
 * Author:            BCM Network
 * License:           GPL-2.0-or-later
 * License URI:       https://www.gnu.org/licenses/gpl-2.0.html
 * Text Domain:       bcm-protection
 */

if (!defined('ABSPATH')) {
  exit;
}

define('BCM_PROTECTION_VERSION', '0.2.0');
define('BCM_PROTECTION_FILE', __FILE__);
define('BCM_PROTECTION_DIR', plugin_dir_path(__FILE__));

require_once BCM_PROTECTION_DIR . 'src/Plugin.php';
require_once BCM_PROTECTION_DIR . 'src/Util/Checks.php';
require_once BCM_PROTECTION_DIR . 'src/Frontend/Honeypot.php';
require_once BCM_PROTECTION_DIR . 'src/Admin/AdminPage.php';

add_action('plugins_loaded', function () {
  \BCMProtection\Plugin::instance()->boot();
});
