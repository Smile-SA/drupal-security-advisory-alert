<?php

namespace Drupal\security_advisory_alert\Service;

use Drupal\Core\Http\ClientFactory;
use GuzzleHttp\ClientInterface;
use Psr\Log\LoggerInterface;

/**
 * Fetches advisory data from OSV, drupal.org and Packagist.
 *
 * Uses https://api.osv.dev (no composer binary required, version range
 * matching done server-side), drupal.org's Composer advisory API for the SA
 * risk labels, and the package repositories for the latest stable versions.
 */
class AdvisoryFetcher {

  /**
   * Constructs an AdvisoryFetcher.
   *
   * @param \Drupal\Core\Http\ClientFactory $httpClientFactory
   *   The HTTP client factory.
   * @param \Psr\Log\LoggerInterface $logger
   *   The module's logger channel.
   */
  public function __construct(
    protected ClientFactory $httpClientFactory,
    protected LoggerInterface $logger,
  ) {}

  /**
   * Queries OSV for the installed packages and returns full vulnerabilities.
   *
   * Step 1: querybatch to discover which packages/versions are affected (OSV
   * returns only {id, modified} per vuln at this stage).
   * Step 2: GET /v1/vulns/{id} for each unique affected vuln to get full data
   * including severity and details.
   *
   * @param array<string, string> $installed
   *   Package name => installed version.
   *
   * @return array<string, array>
   *   Full vulnerability objects keyed by package name.
   *
   * @throws \GuzzleHttp\Exception\GuzzleException
   */
  public function fetchVulnerabilities(array $installed): array {
    $client = $this->httpClientFactory->fromOptions(['timeout' => 30]);

    // Step 1: querybatch.
    $entries = [];
    foreach ($installed as $name => $version) {
      $entries[] = ['name' => $name, 'version' => $version];
      // OSV uses strict semver (6.3.0-beta2 < 6.3.0) whereas Composer treats a
      // pre-release as part of its base version: ">=6.3.0 <6.3.1" matches
      // 6.3.0-beta2. Query the base version too so these are not missed.
      if (preg_match('/^(\d+\.\d+\.\d+)-(alpha|beta|rc)/i', $version, $m)) {
        $entries[] = ['name' => $name, 'version' => $m[1]];
      }
    }

    // Maps package name => [vuln IDs].
    $affectedIds = [];
    foreach (array_chunk($entries, 100) as $batch) {
      $queries = array_map(fn($e) => [
        'version' => $e['version'],
        'package' => ['name' => $e['name'], 'ecosystem' => 'Packagist'],
      ], $batch);

      $response = $client->post('https://api.osv.dev/v1/querybatch', [
        'json' => ['queries' => $queries],
      ]);
      $body = json_decode((string) $response->getBody(), TRUE);

      foreach ($body['results'] ?? [] as $i => $result) {
        foreach ($result['vulns'] ?? [] as $v) {
          $affectedIds[$batch[$i]['name']][] = $v['id'];
        }
      }
    }
    if (empty($affectedIds)) {
      return [];
    }
    $affectedIds = array_map('array_unique', $affectedIds);

    // Step 2: full details for the unique vuln IDs.
    $uniqueIds = array_unique(array_merge(...array_values($affectedIds)));
    $details = $this->fetchVulnDetails($client, $uniqueIds);

    $results = [];
    foreach ($affectedIds as $package => $ids) {
      foreach ($ids as $id) {
        if (!empty($details[$id])) {
          $results[$package][] = $details[$id];
        }
      }
    }

    // OSV's Drupal entries have neither severity nor title: take the SA title,
    // which carries the risk label ("Webform - Moderately critical - ..."),
    // from drupal.org's Composer advisory API.
    // DRUPAL-CONTRIB-x <=> SA-CONTRIB-x.
    $drupalPackages = array_filter(
      array_keys($results),
      fn($p) => str_starts_with($p, 'drupal/'),
    );
    if ($drupalPackages) {
      $titles = $this->fetchDrupalAdvisoryTitles($client, $drupalPackages);
      foreach ($results as &$vulns) {
        foreach ($vulns as &$vuln) {
          $saId = preg_replace('/^DRUPAL-/', 'SA-', $vuln['id']);
          $vuln['summary'] ??= $titles[$saId] ?? NULL;
        }
      }
      unset($vulns, $vuln);
    }

    return $results;
  }

  /**
   * Returns the latest stable version of a package, or NULL on failure.
   *
   * Only the repository the package was installed from is queried: most
   * drupal/* are on packages.drupal.org only, but drupal/core & co are on
   * packagist.org. Other repositories (asset-packagist, inline): no lookup.
   *
   * @param string $package
   *   The package name.
   * @param string $source
   *   The package's Composer notification-url.
   *
   * @return string|null
   *   The latest stable version, or NULL.
   */
  public function fetchLatestStable(string $package, string $source): ?string {
    $url = match (parse_url($source, PHP_URL_HOST)) {
      'packages.drupal.org' => "https://packages.drupal.org/files/packages/8/p2/{$package}.json",
      'packagist.org' => "https://packagist.org/packages/{$package}.json",
      default => NULL,
    };
    if (!$url) {
      return NULL;
    }

    try {
      $client = $this->httpClientFactory->fromOptions(['timeout' => 10]);
      $data = json_decode((string) $client->get($url)->getBody(), TRUE);
    }
    catch (\Exception $e) {
      return NULL;
    }

    // packagist.org REST: data['package']['versions'][version => {...}].
    // packages.drupal.org p2: data['packages'][name][{version, ...}].
    $versions = !empty($data['package']['versions'])
      ? array_keys($data['package']['versions'])
      : array_column($data['packages'][$package] ?? [], 'version');
    $stable = array_filter($versions, fn($v) => !preg_match('/(dev|alpha|beta|rc)/i', $v));
    if (!$stable) {
      return NULL;
    }
    usort($stable, fn($a, $b) => version_compare($b, $a));
    return $stable[0];
  }

  /**
   * Fetches the drupal.org PSAs published in the last 7 days.
   *
   * Reads the RSS feed: updates.drupal.org/psa.json (core's sa_fetcher) has
   * not been updated since May 2026 and misses every PSA since.
   *
   * @return array<int, array{title: string, url: string}>
   *   The recent PSAs.
   *
   * @throws \GuzzleHttp\Exception\GuzzleException
   */
  public function fetchPsas(): array {
    $client = $this->httpClientFactory->fromOptions(['timeout' => 10]);
    $rss = (string) $client->get('https://www.drupal.org/security/psa/rss.xml')->getBody();
    return static::parsePsaFeed($rss, time());
  }

  /**
   * Extracts the current PSAs from the RSS feed.
   *
   * PSAs come out a few days before the release they announce and the feed
   * has no project field, so every current PSA is returned, like psa.json did.
   * A PSA announcing a release date ("... release on October 14, 2026") is
   * current until the end of that day (UTC): the advisory is then published
   * and reported by OSV. Other PSAs are current for 7 days.
   * ponytail: date read from the title, fixed 7-day window otherwise.
   *
   * @param string $rss
   *   The RSS feed XML.
   * @param int $now
   *   The current timestamp.
   *
   * @return array<int, array{title: string, url: string}>
   *   The recent PSAs.
   */
  public static function parsePsaFeed(string $rss, int $now): array {
    $xml = @simplexml_load_string($rss);
    if ($xml === FALSE) {
      throw new \RuntimeException('invalid PSA RSS feed.');
    }
    $psas = [];
    foreach ($xml->channel->item as $item) {
      $title = (string) $item->title;
      $release = preg_match('/\bon (\w+ \d{1,2}, \d{4})\b/', $title, $m) ? strtotime($m[1] . ' UTC') : FALSE;
      $published = strtotime((string) $item->pubDate);
      $current = $published && $published <= $now && ($release
        ? $now < $release + 86400
        : $published >= $now - 7 * 86400);
      if ($current) {
        $psas[] = ['title' => $title, 'url' => (string) $item->link];
      }
    }
    return $psas;
  }

  /**
   * Fetches full OSV vulnerability objects for a list of IDs.
   *
   * @param \GuzzleHttp\ClientInterface $client
   *   The HTTP client.
   * @param string[] $ids
   *   The OSV vulnerability IDs.
   *
   * @return array<string, array>
   *   Full vuln objects keyed by ID.
   */
  protected function fetchVulnDetails(ClientInterface $client, array $ids): array {
    $details = [];
    foreach ($ids as $id) {
      try {
        $response = $client->get('https://api.osv.dev/v1/vulns/' . rawurlencode($id));
        $details[$id] = json_decode((string) $response->getBody(), TRUE);
      }
      catch (\Exception $e) {
        $this->logger->warning('could not fetch OSV vuln @id: @msg', [
          '@id' => $id,
          '@msg' => $e->getMessage(),
        ]);
      }
    }
    return $details;
  }

  /**
   * Returns drupal.org security advisory titles keyed by SA id.
   *
   * @param \GuzzleHttp\ClientInterface $client
   *   The HTTP client.
   * @param string[] $packages
   *   The drupal/* package names.
   *
   * @return array<string, string>
   *   Advisory titles keyed by SA id.
   */
  protected function fetchDrupalAdvisoryTitles(ClientInterface $client, array $packages): array {
    try {
      $response = $client->post('https://packages.drupal.org/8/security-advisories', [
        'form_params' => ['packages' => array_values($packages)],
      ]);
      $data = json_decode((string) $response->getBody(), TRUE);
    }
    catch (\Exception $e) {
      $this->logger->warning('could not fetch drupal.org advisories: @msg', [
        '@msg' => $e->getMessage(),
      ]);
      return [];
    }
    $titles = [];
    foreach ($data['advisories'] ?? [] as $advisories) {
      foreach ($advisories as $advisory) {
        $titles[$advisory['advisoryId']] = $advisory['title'];
      }
    }
    return $titles;
  }

}
