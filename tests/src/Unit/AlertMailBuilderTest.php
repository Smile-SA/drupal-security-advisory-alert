<?php

namespace Drupal\Tests\security_advisory_alert\Unit;

use Drupal\Core\DependencyInjection\ContainerBuilder;
use Drupal\Core\Render\Markup;
use Drupal\Core\Render\RendererInterface;
use Drupal\Core\Routing\UrlGeneratorInterface;
use Drupal\security_advisory_alert\Service\AlertMailBuilder;
use Drupal\Tests\UnitTestCase;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\Group;

/**
 * Tests the preparation of the alert email.
 *
 * @coversDefaultClass \Drupal\security_advisory_alert\Service\AlertMailBuilder
 * @group security_advisory_alert
 */
#[CoversClass(AlertMailBuilder::class)]
#[Group('security_advisory_alert')]
class AlertMailBuilderTest extends UnitTestCase {

  /**
   * The render array passed to the renderer.
   */
  protected array $build = [];

  /**
   * Tests the subject and the template variables.
   */
  public function testBuild(): void {
    $urlGenerator = $this->createMock(UrlGeneratorInterface::class);
    $urlGenerator->method('generateFromRoute')->willReturn('https://example.com/');
    $container = new ContainerBuilder();
    $container->set('url_generator', $urlGenerator);
    \Drupal::setContainer($container);

    $renderer = $this->createMock(RendererInterface::class);
    $renderer->method('renderInIsolation')->willReturnCallback(function (array $build) {
      $this->build = $build;
      return Markup::create('<p>body</p>');
    });
    $builder = new AlertMailBuilder(
      $this->getConfigFactoryStub(['system.site' => ['name' => 'My site']]),
      $renderer,
    );
    $builder->setStringTranslation($this->getStringTranslationStub());

    $high = [
      'id' => 'DRUPAL-CONTRIB-1',
      'summary' => 'Webform - Moderately critical - Access bypass',
      'references' => [['url' => 'javascript:alert(1)']],
      '_severity' => 'high',
      '_fix' => ['6.3.1', '6.2.12'],
      '_latest_safe' => '6.3.2',
    ];
    $critical = [
      'id' => 'DRUPAL-CONTRIB-2',
      'details' => "## Heading\n\nSee [the advisory](https://example.com) for details.",
      'references' => [['url' => 'https://example.com/advisory/2']],
      '_severity' => 'critical',
      '_fix' => [],
      '_latest_safe' => NULL,
    ];
    $low = ['id' => 'GHSA-1', 'summary' => 'Low', '_severity' => 'low', '_fix' => ['1.0.0']];
    $coreHigh = ['id' => 'DRUPAL-CORE-1', 'summary' => 'Core high', '_severity' => 'high'];

    $email = $builder->build([
      'matching' => ['drupal/core' => [$coreHigh, $coreHigh], 'drupal/webform' => [$high, $critical]],
      'count' => 4,
      'all_vulns' => [
        'symfony/x' => [$low],
        'drupal/core' => [$coreHigh, $coreHigh, $coreHigh],
        'drupal/webform' => [$high, $critical],
      ],
      'installed' => ['drupal/webform' => '6.3.0', 'drupal/core' => '11.0.0', 'symfony/x' => '2.0.0'],
      'psas' => [['title' => 'PSA-1', 'url' => 'data:text/html,x']],
    ]);

    $this->assertSame('[My site] SECURITY: 4 advisories in 2 packages + 1 upcoming security release announced', $email['subject']);
    $this->assertSame('<p>body</p>', (string) $email['body']);

    $this->assertSame('security_advisory_alert_email', $this->build['#theme']);
    $this->assertSame('https://example.com', $this->build['#site_url']);
    $this->assertSame(['CRITICAL', 'HIGH', 'LOW'], array_column($this->build['#counts'], 'label'));
    $this->assertSame('https://www.drupal.org/security/psa', $this->build['#psas'][0]['url'], 'Non-http PSA link replaced.');

    // Alerting packages first, the one with a critical advisory before the one
    // with more (but only high) advisories; information-only packages last.
    [$webform, $core, $other] = $this->build['#packages'];
    $this->assertSame(['drupal/webform', TRUE], [$webform['name'], $webform['alert']]);
    $this->assertSame(['drupal/core', TRUE], [$core['name'], $core['alert']]);
    $this->assertSame(['symfony/x', FALSE], [$other['name'], $other['alert']]);

    // Most severe first.
    [$first, $second] = $webform['vulns'];
    $this->assertSame('CRITICAL', $first['severity']['label']);
    $this->assertSame('See the advisory for details.', $first['description'], 'Markdown heading and link removed.');
    $this->assertSame('https://example.com/advisory/2', $first['url']);
    $this->assertSame([], $first['upgrades']);
    $this->assertFalse($first['fix_exists']);

    $this->assertSame('Webform - Moderately critical - Access bypass', $second['description'], 'The title is preferred to the details.');
    $this->assertSame('https://osv.dev/vulnerability/DRUPAL-CONTRIB-1', $second['url'], 'javascript: link replaced.');
    $this->assertSame(['6.3.1', '6.3.2 (latest)'], $second['upgrades'], 'Older branch fix dropped, latest appended.');

    // Fix only for an older branch.
    $this->assertSame([], $other['vulns'][0]['upgrades']);
    $this->assertTrue($other['vulns'][0]['fix_exists']);
  }

}
