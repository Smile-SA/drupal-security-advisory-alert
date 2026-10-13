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
   * Only PSAs published in the last 7 days are returned.
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
      </channel></rss>
      XML;
    $now = strtotime('2026-10-13 12:00:00 UTC');

    $this->assertSame([
      [
        'title' => 'Upcoming critical Drupal core release on October 14, 2026 - PSA-2026-10-12',
        'url' => 'https://www.drupal.org/psa-2026-10-12',
      ],
    ], AdvisoryFetcher::parsePsaFeed($rss, $now));
  }

  /**
   * An invalid feed throws, so the checker logs it instead of reporting none.
   */
  public function testParseInvalidPsaFeed(): void {
    $this->expectException(\RuntimeException::class);
    AdvisoryFetcher::parsePsaFeed('<html>maintenance</html', time());
  }

}
