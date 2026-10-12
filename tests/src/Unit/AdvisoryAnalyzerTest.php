<?php

namespace Drupal\Tests\security_advisory_alert\Unit;

use Drupal\security_advisory_alert\AdvisoryAnalyzer;
use Drupal\Tests\UnitTestCase;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Group;

/**
 * Tests the interpretation of OSV vulnerability objects.
 *
 * @coversDefaultClass \Drupal\security_advisory_alert\AdvisoryAnalyzer
 * @group security_advisory_alert
 */
#[CoversClass(AdvisoryAnalyzer::class)]
#[Group('security_advisory_alert')]
class AdvisoryAnalyzerTest extends UnitTestCase {

  /**
   * A drupal/webform advisory fixed in the 6.2 and 6.3 branches.
   */
  protected const WEBFORM = [
    'affected' => [
      [
        'package' => ['name' => 'drupal/webform', 'ecosystem' => 'Packagist'],
        'ranges' => [
          ['type' => 'ECOSYSTEM', 'events' => [['introduced' => '0'], ['fixed' => '6.2.12']]],
          ['type' => 'ECOSYSTEM', 'events' => [['introduced' => '6.3.0'], ['fixed' => '6.3.1']]],
          ['type' => 'GIT', 'events' => [['introduced' => '0'], ['fixed' => 'abc123']]],
        ],
      ],
      [
        'package' => ['name' => 'drupal/other', 'ecosystem' => 'Packagist'],
        'ranges' => [['type' => 'ECOSYSTEM', 'events' => [['introduced' => '0'], ['fixed' => '9.9.9']]]],
      ],
    ],
  ];

  /**
   * Tests the severity of an advisory.
   *
   * @dataProvider providerSeverity
   */
  #[DataProvider('providerSeverity')]
  public function testSeverity(array $vuln, string $expected): void {
    $this->assertSame($expected, (new AdvisoryAnalyzer())->severity($vuln));
  }

  /**
   * Data provider for testSeverity().
   */
  public static function providerSeverity(): array {
    return [
      'GitHub reviewed label' => [['database_specific' => ['severity' => 'HIGH']], 'high'],
      'GitHub MODERATE is medium' => [['database_specific' => ['severity' => 'MODERATE']], 'medium'],
      'label wins over CVSS' => [
        [
          'database_specific' => ['severity' => 'LOW'],
          'severity' => [['type' => 'CVSS_V3', 'score' => 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H']],
        ],
        'low',
      ],
      'CVSS v3 network, high impacts' => [
        ['severity' => [['type' => 'CVSS_V3', 'score' => 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H']]],
        'critical',
      ],
      'CVSS v4 impacts are VC/VI/VA' => [
        [
          'severity' => [
            ['type' => 'CVSS_V4', 'score' => 'CVSS:4.0/AV:L/AC:L/AT:P/PR:N/UI:P/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N'],
          ],
        ],
        'medium',
      ],
      'CVSS no high impact' => [
        ['severity' => [['type' => 'CVSS_V3', 'score' => 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N']]],
        'low',
      ],
      'SA Critical' => [['summary' => 'Webform - Critical - Remote Code Execution - SA-CONTRIB-1'], 'critical'],
      'SA Moderately critical' => [['summary' => 'Webform - Moderately critical - Access bypass'], 'high'],
      'SA Less critical' => [['summary' => 'Webform - Less critical - Denial of service'], 'medium'],
      'SA Not critical' => [['summary' => 'Foo - Not critical - Information disclosure'], 'low'],
      'vulnerability type' => [['details' => 'Allows cross-site scripting (XSS).'], 'medium'],
      'no signal' => [['details' => 'Something happened.'], 'unknown'],
    ];
  }

  /**
   * Tests the extraction of the fixed versions.
   */
  public function testFixedVersions(): void {
    $analyzer = new AdvisoryAnalyzer();
    $this->assertSame(['6.2.12', '6.3.1'], $analyzer->fixedVersions(static::WEBFORM, 'drupal/webform'));
    $this->assertSame(['6.2.12', '6.3.1'], $analyzer->fixedVersions(static::WEBFORM, 'Drupal/Webform'));
    $this->assertSame([], $analyzer->fixedVersions(static::WEBFORM, 'drupal/unknown'));
  }

  /**
   * Tests whether a version is affected.
   *
   * @dataProvider providerIsAffected
   */
  #[DataProvider('providerIsAffected')]
  public function testIsAffected(array $vuln, string $version, bool $expected): void {
    $this->assertSame($expected, (new AdvisoryAnalyzer())->isAffected($vuln, 'drupal/webform', $version));
  }

  /**
   * Data provider for testIsAffected().
   */
  public static function providerIsAffected(): array {
    $open = [
      'affected' => [
        [
          'package' => ['name' => 'drupal/webform'],
          'ranges' => [['type' => 'ECOSYSTEM', 'events' => [['introduced' => '7.0.0']]]],
        ],
      ],
    ];
    return [
      'old branch, before fix' => [static::WEBFORM, '6.2.11', TRUE],
      'old branch, fixed' => [static::WEBFORM, '6.2.12', FALSE],
      'between branches' => [static::WEBFORM, '6.2.99', FALSE],
      'new branch, before fix' => [static::WEBFORM, '6.3.0', TRUE],
      'new branch, fixed' => [static::WEBFORM, '6.3.1', FALSE],
      'open range, affected' => [$open, '7.5.0', TRUE],
      'open range, before' => [$open, '6.9.0', FALSE],
    ];
  }

}
