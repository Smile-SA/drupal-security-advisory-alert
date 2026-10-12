<?php

namespace Drupal\security_advisory_alert\Service;

use Drupal\Core\Config\ConfigFactoryInterface;
use Drupal\Core\Render\RendererInterface;
use Drupal\Core\StringTranslation\StringTranslationTrait;
use Drupal\Core\Url;
use Drupal\security_advisory_alert\AdvisoryAnalyzer;

/**
 * Builds the subject and HTML body of the alert email.
 *
 * The body is rendered with the security_advisory_alert_email theme hook
 * (templates/security-advisory-alert-email.html.twig), which a theme can
 * override.
 */
class AlertMailBuilder {

  use StringTranslationTrait;

  /**
   * Badge colour of each severity.
   */
  protected const COLORS = [
    'critical' => '#c0392b',
    'high' => '#e67e22',
    'medium' => '#f39c12',
    'low' => '#27ae60',
    'unknown' => '#95a5a6',
  ];

  /**
   * Constructs an AlertMailBuilder.
   *
   * @param \Drupal\Core\Config\ConfigFactoryInterface $configFactory
   *   The config factory.
   * @param \Drupal\Core\Render\RendererInterface $renderer
   *   The renderer.
   */
  public function __construct(
    protected ConfigFactoryInterface $configFactory,
    protected RendererInterface $renderer,
  ) {}

  /**
   * Builds the email.
   *
   * @param array $params
   *   The hook_mail() parameters:
   *   - matching: advisories at the configured severities, keyed by package.
   *   - count: number of those advisories.
   *   - all_vulns: all annotated advisories, keyed by package.
   *   - installed: installed version keyed by package.
   *   - psas: [title, url, project] of the applicable PSAs.
   *
   * @return array
   *   'subject' (string) and 'body' (\Drupal\Component\Render\MarkupInterface).
   */
  public function build(array $params): array {
    $matching = $params['matching'] ?? [];
    $allVulns = $params['all_vulns'] ?? [];
    $installed = $params['installed'] ?? [];
    $psas = $params['psas'] ?? [];
    $siteName = (string) $this->configFactory->get('system.site')->get('name');

    $subject = [];
    if ($matching) {
      $subject[] = $this->t('@count advisory/ies in @pkg package(s)', [
        '@count' => $params['count'] ?? 0,
        '@pkg' => count($matching),
      ]);
    }
    if ($psas) {
      $subject[] = $this->t('@n upcoming security release(s) announced', ['@n' => count($psas)]);
    }

    $counts = [];
    foreach (AdvisoryAnalyzer::SEVERITIES as $severity) {
      $n = 0;
      foreach ($allVulns as $vulns) {
        $n += count(array_filter($vulns, fn($v) => ($v['_severity'] ?? 'unknown') === $severity));
      }
      if ($n) {
        $counts[] = $this->severity($severity) + ['count' => $n];
      }
    }

    // Packages that triggered the alert first, then the others (information);
    // within each group, most severe advisory first, then most advisories.
    $packages = [];
    foreach (array_keys($allVulns + $matching) as $package) {
      $packages[] = $this->package($package, $allVulns[$package] ?? [], $installed[$package] ?? '?', isset($matching[$package]));
    }
    $rank = fn(array $p) => [
      !$p['alert'],
      $p['vulns'] ? array_search(strtolower($p['vulns'][0]['severity']['label']), AdvisoryAnalyzer::SEVERITIES, TRUE) : 99,
      -count($p['vulns']),
      $p['name'],
    ];
    usort($packages, fn($a, $b) => $rank($a) <=> $rank($b));

    $build = [
      '#theme' => 'security_advisory_alert_email',
      '#site_name' => $siteName,
      '#site_url' => rtrim(Url::fromRoute('<front>', [], ['absolute' => TRUE])->toString(), '/'),
      '#counts' => $counts,
      '#package_count' => count($allVulns),
      '#psas' => array_map(fn($psa) => [
        'title' => $psa['title'],
        'project' => $psa['project'],
        'url' => $this->safeUrl($psa['url'] ?? '', 'https://www.drupal.org/security/psa'),
      ], $psas),
      '#packages' => $packages,
    ];

    return [
      'subject' => '[' . $siteName . '] SECURITY: ' . implode(' + ', array_map('strval', $subject)),
      'body' => $this->renderer->renderInIsolation($build),
    ];
  }

  /**
   * Prepares one package section.
   *
   * @param string $name
   *   The package name.
   * @param array $vulns
   *   The package's annotated advisories.
   * @param string $version
   *   The installed version.
   * @param bool $alert
   *   Whether the package triggered the alert.
   *
   * @return array
   *   The template variables of the package.
   */
  protected function package(string $name, array $vulns, string $version, bool $alert): array {
    $order = array_flip(AdvisoryAnalyzer::SEVERITIES);
    usort($vulns, fn($a, $b) => ($order[$a['_severity'] ?? 'unknown'] ?? 4) <=> ($order[$b['_severity'] ?? 'unknown'] ?? 4));

    $rows = [];
    foreach ($vulns as $vuln) {
      $fixes = $vuln['_fix'] ?? [];
      usort($fixes, 'version_compare');
      // Fixes for older branches are irrelevant.
      $upgrades = array_values(array_filter($fixes, fn($v) => version_compare($v, $version, '>=')));
      $latest = $vuln['_latest_safe'] ?? NULL;
      if ($latest && (!$upgrades || version_compare($latest, end($upgrades), '>'))) {
        $upgrades[] = $latest . ' (latest)';
      }
      $id = $vuln['id'] ?? 'N/A';
      $rows[] = [
        'severity' => $this->severity($vuln['_severity'] ?? 'unknown'),
        'id' => $id,
        'aliases' => $vuln['aliases'] ?? [],
        // The title (drupal.org SA title with its risk label, GitHub summary)
        // says more than the first line of the details, which for Drupal
        // advisories only describes the module.
        'description' => $this->firstLine($vuln['summary'] ?? '') ?: $this->firstLine($vuln['details'] ?? '') ?: $id,
        'url' => $this->safeUrl($this->firstReference($vuln), 'https://osv.dev/vulnerability/' . rawurlencode($id)),
        'upgrades' => $upgrades,
        // No upgrade: either no fix for this branch, or no fix at all.
        'fix_exists' => (bool) $fixes,
      ];
    }

    return [
      'name' => $name,
      'version' => $version,
      'alert' => $alert,
      'vulns' => $rows,
    ];
  }

  /**
   * Returns the label and colour of a severity.
   *
   * @param string $severity
   *   The severity.
   *
   * @return array
   *   'label' and 'color'.
   */
  protected function severity(string $severity): array {
    return [
      'label' => strtoupper($severity),
      'color' => static::COLORS[$severity] ?? static::COLORS['unknown'],
    ];
  }

  /**
   * Returns the first reference URL of an advisory.
   *
   * @param array $vuln
   *   The OSV vulnerability.
   *
   * @return string
   *   The URL, or an empty string.
   */
  protected function firstReference(array $vuln): string {
    foreach ($vuln['references'] ?? [] as $reference) {
      $url = rtrim($reference['url'] ?? '', '"\'');
      if ($this->safeUrl($url, '') !== '') {
        return $url;
      }
    }
    return '';
  }

  /**
   * Returns the URL if it is http(s), the fallback otherwise.
   *
   * The URLs come from external feeds: this keeps javascript:, data: and
   * the like out of the email links.
   *
   * @param string $url
   *   The URL.
   * @param string $fallback
   *   The fallback URL.
   *
   * @return string
   *   A safe URL.
   */
  protected function safeUrl(string $url, string $fallback): string {
    return preg_match('#^https?://#i', $url) ? $url : $fallback;
  }

  /**
   * Returns the first meaningful line of a Markdown advisory text.
   *
   * @param string $text
   *   The advisory details or summary.
   *
   * @return string
   *   The line without Markdown headings and links.
   */
  protected function firstLine(string $text): string {
    foreach (explode("\n", $text) as $line) {
      $line = trim($line);
      if ($line === '' || preg_match('/^#{1,6}\s+/', $line)) {
        continue;
      }
      return preg_replace('/\[([^\]]+)\]\([^)]+\)/', '$1', $line);
    }
    return '';
  }

}
