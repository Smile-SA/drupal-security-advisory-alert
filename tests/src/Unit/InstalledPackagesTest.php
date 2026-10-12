<?php

namespace Drupal\Tests\security_advisory_alert\Unit;

use Composer\Autoload\ClassLoader;
use Drupal\security_advisory_alert\InstalledPackages;
use Drupal\Tests\UnitTestCase;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\Group;

/**
 * Tests reading vendor/composer/installed.json.
 *
 * @coversDefaultClass \Drupal\security_advisory_alert\InstalledPackages
 * @group security_advisory_alert
 */
#[CoversClass(InstalledPackages::class)]
#[Group('security_advisory_alert')]
class InstalledPackagesTest extends UnitTestCase {

  /**
   * A temporary installed.json.
   */
  protected string $file;

  /**
   * {@inheritdoc}
   */
  protected function setUp(): void {
    parent::setUp();
    $this->file = sys_get_temp_dir() . '/security_advisory_alert_test_' . getmypid() . '.json';
  }

  /**
   * {@inheritdoc}
   */
  protected function tearDown(): void {
    @unlink($this->file);
    parent::tearDown();
  }

  /**
   * Tests reading the packages and their repositories (Composer 2 format).
   */
  public function testRead(): void {
    file_put_contents($this->file, json_encode([
      'packages' => [
        [
          'name' => 'drupal/webform',
          'version' => '6.3.0-beta2',
          'notification-url' => 'https://packages.drupal.org/8/downloads',
        ],
        [
          'name' => 'symfony/console',
          'version' => 'v7.1.0',
          'notification-url' => 'https://packagist.org/downloads/',
        ],
        ['name' => 'bgrins/spectrum', 'version' => '1.8.0'],
      ],
      'dev' => FALSE,
      'dev-package-names' => [],
    ]));
    $installed = new InstalledPackages($this->file);

    $this->assertSame([
      'drupal/webform' => '6.3.0-beta2',
      'symfony/console' => '7.1.0',
      'bgrins/spectrum' => '1.8.0',
    ], $installed->packages(), 'Leading "v" removed.');
    $this->assertSame('https://packages.drupal.org/8/downloads', $installed->sources()['drupal/webform']);
    $this->assertSame('', $installed->sources()['bgrins/spectrum'], 'Inline package without repository.');
    $this->assertSame(md5_file($this->file), $installed->hash());
  }

  /**
   * Tests the Composer 1 format (package list at the top level).
   */
  public function testComposerOneFormat(): void {
    file_put_contents($this->file, json_encode([['name' => 'drupal/core', 'version' => '9.5.0']]));
    $this->assertSame(['drupal/core' => '9.5.0'], (new InstalledPackages($this->file))->packages());
  }

  /**
   * Tests a missing or broken file.
   */
  public function testMissing(): void {
    $this->assertSame([], (new InstalledPackages($this->file))->packages());
  }

  /**
   * Tests locating installed.json from the site's Composer autoloader.
   */
  public function testFromLoader(): void {
    $vendor = sys_get_temp_dir() . '/security_advisory_alert_vendor_' . getmypid();
    @mkdir($vendor . '/composer', 0777, TRUE);
    file_put_contents($vendor . '/composer/installed.json', json_encode([
      'packages' => [['name' => 'drupal/core', 'version' => '11.4.8']],
    ]));
    $loader = new ClassLoader($vendor);
    $loader->register();
    try {
      $installed = InstalledPackages::fromLoader($loader);
      $this->assertNotNull($installed);
      $this->assertSame(['drupal/core' => '11.4.8'], $installed->packages(), 'The given loader\'s vendor/ is used, not the first loaded one.');
      $this->assertNull(InstalledPackages::fromLoader(new ClassLoader($vendor . '-unregistered')));
    }
    finally {
      $loader->unregister();
      @unlink($vendor . '/composer/installed.json');
      @rmdir($vendor . '/composer');
      @rmdir($vendor);
    }
  }

}
