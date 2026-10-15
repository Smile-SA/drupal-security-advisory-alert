<?php

namespace Drupal\Tests\security_advisory_alert\Unit;

use Drupal\security_advisory_alert\Service\AdvisoryFetcher;
use Drupal\Tests\UnitTestCase;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\Group;

/**
 * Tests the parsing of the drupal.org PSA RSS feed.
 *
 * @coversDefaultClass \Drupal\security_advisory_alert\Service\AdvisoryFetcher
 * @group security_advisory_alert
 */
#[CoversClass(AdvisoryFetcher::class)]
#[Group('security_advisory_alert')]
class AdvisoryFetcherTest extends UnitTestCase {

  /**
   * A PSA is current until its release day ends, or for 7 days without one.
   */
  public function testParsePsaFeed(): void {
    $rss = <<<XML
      <?xml version="1.0" encoding="utf-8"?>
      <rss version="2.0"><channel>
        <item>
          <title>Upcoming critical Drupal core release on October 14, 2026 - PSA-2026-10-12</title>
          <link>https://www.drupal.org/psa-2026-10-12</link>
          <pubDate>Mon, 12 Oct 2026 16:10:00 +0000</pubDate>
        </item>
        <item>
          <title>Upcoming critical contributed project security release on September 23, 2026 - PSA-2026-09-21</title>
          <link>https://www.drupal.org/psa-2026-09-21</link>
          <pubDate>Mon, 21 Sep 2026 09:56:09 +0000</pubDate>
        </item>
        <item>
          <title>Security advisory coverage removed - QA Accounts - PSA-2026-07-22</title>
          <link>https://www.drupal.org/psa-2026-07-22</link>
          <pubDate>Wed, 22 Jul 2026 17:59:58 +0000</pubDate>
        </item>
      </channel></rss>
      XML;
    $urls = fn(string $now) => array_column(AdvisoryFetcher::parsePsaFeed($rss, strtotime($now . ' UTC')), 'url');

    $this->assertSame(['https://www.drupal.org/psa-2026-10-12'], $urls('2026-10-13 12:00:00'));
    $this->assertSame(['https://www.drupal.org/psa-2026-10-12'], $urls('2026-10-14 23:59:59'), 'Current during the release day.');
    $this->assertSame([], $urls('2026-10-15 00:00:00'), 'Obsolete once the release day is over.');
    $this->assertSame(['https://www.drupal.org/psa-2026-07-22'], $urls('2026-07-29 17:00:00'), 'No release date: 7 days.');
    $this->assertSame([], $urls('2026-07-29 18:00:00'));
  }

  /**
   * An invalid feed throws, so the checker logs it instead of reporting none.
   */
  public function testParseInvalidPsaFeed(): void {
    $this->expectException(\RuntimeException::class);
    AdvisoryFetcher::parsePsaFeed('<html>maintenance</html', time());
  }

}
