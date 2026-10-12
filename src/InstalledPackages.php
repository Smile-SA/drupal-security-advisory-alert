<?php

namespace Drupal\security_advisory_alert;

use Composer\Autoload\ClassLoader;

/**
 * Reads the packages installed by Composer.
 *
 * Source: vendor/composer/installed.json, written by Composer on every
 * install/update. Unlike composer.lock it is always deployed with vendor/,
 * and it lists what is actually installed (no dev packages on a --no-dev
 * build).
 */
final class InstalledPackages {

  /**
   * Installed version keyed by package name.
   *
   * @var array<string, string>
   */
  private array $packages = [];

  /**
   * Repository ("notification-url") keyed by package name.
   *
   * @var array<string, string>
   */
  private array $sources = [];

  /**
   * Constructs an InstalledPackages.
   *
   * @param string $path
   *   Path of vendor/composer/installed.json.
   */
  public function __construct(private string $path) {
    $data = json_decode((string) @file_get_contents($path), TRUE) ?: [];
    // Composer 2 format; Composer 1 wrote the package list at the top level.
    foreach ($data['packages'] ?? (array_is_list($data) ? $data : []) as $package) {
      if (!isset($package['name'])) {
        continue;
      }
      $this->packages[$package['name']] = ltrim($package['version'] ?? '', 'v');
      $this->sources[$package['name']] = $package['notification-url'] ?? '';
    }
  }

  /**
   * Returns the packages of the vendor directory of a Composer autoloader.
   *
   * @param \Composer\Autoload\ClassLoader $loader
   *   The autoloader the site runs with (service "class_loader"). Several
   *   Composer autoloaders may be loaded (e.g. a global Drush): the site's
   *   one tells which vendor/ is deployed.
   *
   * @return static|null
   *   The installed packages, or NULL if installed.json was not found.
   */
  public static function fromLoader(ClassLoader $loader): ?static {
    $vendorDir = array_search($loader, ClassLoader::getRegisteredLoaders(), TRUE);
    $path = $vendorDir !== FALSE ? $vendorDir . '/composer/installed.json' : NULL;
    return $path && file_exists($path) ? new static($path) : NULL;
  }

  /**
   * Returns the md5 hash of installed.json, which identifies an install.
   */
  public function hash(): string {
    return (string) md5_file($this->path);
  }

  /**
   * Returns the installed version keyed by package name.
   *
   * @return array<string, string>
   *   Versions without a leading "v".
   */
  public function packages(): array {
    return $this->packages;
  }

  /**
   * Returns the repository each package was installed from.
   *
   * @return array<string, string>
   *   Composer "notification-url" keyed by package name.
   */
  public function sources(): array {
    return $this->sources;
  }

}
