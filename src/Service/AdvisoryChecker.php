<?php

namespace Drupal\security_advisory_alert\Service;

use Composer\Autoload\ClassLoader;
use Drupal\Core\Config\ConfigFactoryInterface;
use Drupal\Core\Language\LanguageManagerInterface;
use Drupal\Core\Logger\LoggerChannelFactoryInterface;
use Drupal\Core\Mail\MailManagerInterface;
use Drupal\security_advisory_alert\AdvisoryAnalyzer;
use Drupal\security_advisory_alert\InstalledPackages;
use Drupal\system\SecurityAdvisories\SecurityAdvisoriesFetcher;
use Psr\Log\LoggerInterface;

/**
 * Runs the security advisory audit and sends the alert email.
 *
 * Checks the installed Composer packages for published advisories (OSV,
 * drupal.org) and drupal.org PSAs, once for all the sites of a codebase.
 */
class AdvisoryChecker {

  /**
   * The module's logger channel.
   */
  protected LoggerInterface $logger;

  /**
   * The OSV data interpreter.
   */
  protected AdvisoryAnalyzer $analyzer;

  /**
   * Constructs an AdvisoryChecker.
   *
   * @param \Drupal\Core\Config\ConfigFactoryInterface $configFactory
   *   The config factory.
   * @param \Drupal\Core\Mail\MailManagerInterface $mailManager
   *   The mail manager.
   * @param \Drupal\Core\Language\LanguageManagerInterface $languageManager
   *   The language manager.
   * @param \Drupal\Core\Logger\LoggerChannelFactoryInterface $loggerFactory
   *   The logger channel factory.
   * @param \Drupal\system\SecurityAdvisories\SecurityAdvisoriesFetcher $psaFetcher
   *   Core's drupal.org security advisories (PSA) feed fetcher.
   * @param \Drupal\security_advisory_alert\Service\AdvisoryFetcher $fetcher
   *   The OSV / drupal.org / Packagist fetcher.
   * @param \Drupal\security_advisory_alert\Service\AuditStorage $storage
   *   The lock, cache and last result shared by all sites.
   * @param \Composer\Autoload\ClassLoader $classLoader
   *   The site's Composer autoloader, which locates vendor/.
   */
  public function __construct(
    protected ConfigFactoryInterface $configFactory,
    protected MailManagerInterface $mailManager,
    protected LanguageManagerInterface $languageManager,
    LoggerChannelFactoryInterface $loggerFactory,
    protected SecurityAdvisoriesFetcher $psaFetcher,
    protected AdvisoryFetcher $fetcher,
    protected AuditStorage $storage,
    protected ClassLoader $classLoader,
  ) {
    $this->logger = $loggerFactory->get('security_advisory_alert');
    $this->analyzer = new AdvisoryAnalyzer();
  }

  /**
   * Runs the audit and sends an alert if matching advisories are found.
   *
   * A run that actually audited (not just reused another site's cached
   * result) is stored as the codebase-wide last result (getLastResult()).
   *
   * @return array
   *   'status': sent | already_sent | clean | not_sent | error,
   *   'error': message when status is error,
   *   'counts': [severity => n] for all advisories found,
   *   'alert_count' / 'alert_packages': advisories at configured severities,
   *   'psas': PSA titles, 'time': run timestamp, 'site': site that ran it,
   *   'from_cache': TRUE when the findings came from another run's cache.
   */
  public function runAudit(): array {
    // Sites share the filesystem but not their DB, so Drupal's lock service
    // can't serialise them: a file lock makes concurrent crons wait for the
    // first one, then read its cache instead of sending the alert again.
    $lock = $this->storage->acquireLock();
    if (!$lock) {
      $result = $this->error('cannot acquire the lock, skipped (see previous log entry).');
    }
    else {
      try {
        $result = $this->audit();
      }
      finally {
        $this->storage->releaseLock($lock);
      }
    }

    $result += [
      'counts' => [],
      'alert_count' => 0,
      'alert_packages' => [],
      'psas' => [],
      'time' => time(),
      'site' => $this->configFactory->get('system.site')->get('name'),
      'from_cache' => FALSE,
    ];
    if (!$result['from_cache'] || in_array($result['status'], ['sent', 'not_sent'], TRUE)) {
      $this->storage->setLastResult($result);
    }
    return $result;
  }

  /**
   * Returns the last audit result of the codebase, or NULL.
   */
  public function getLastResult(): ?array {
    return $this->storage->getLastResult();
  }

  /**
   * Audit body, run under the cross-site lock.
   *
   * @return array
   *   The audit result, see runAudit().
   */
  protected function audit(): array {
    $config = $this->configFactory->get('security_advisory_alert.settings');

    $packages = InstalledPackages::fromLoader($this->classLoader);
    if (!$packages) {
      return $this->error('vendor/composer/installed.json not found.');
    }
    $installed = $packages->packages();
    if (!$installed) {
      return $this->error('no packages found in vendor/composer/installed.json.');
    }

    // Same codebase = same vendor/: the first site does the lookups, the
    // others reuse its result within the same daily run.
    $hash = $packages->hash();
    $cached = $this->storage->getCache($hash);
    if ($cached !== NULL) {
      $vulns = $cached['vulns'];
    }
    else {
      try {
        $vulns = $this->annotate($this->fetcher->fetchVulnerabilities($installed), $packages->sources());
      }
      catch (\Exception $e) {
        return $this->error('OSV API error: ' . $e->getMessage());
      }
      $this->storage->setCache($hash, $vulns, FALSE);
    }

    $matching = $this->filterBySeverity($vulns, $config->get('severities') ?: ['critical', 'high']);
    $psas = $this->fetchPsas();
    $alertCount = array_sum(array_map('count', $matching));

    $counts = [];
    foreach ($vulns as $packageVulns) {
      foreach ($packageVulns as $vuln) {
        $counts[$vuln['_severity']] = ($counts[$vuln['_severity']] ?? 0) + 1;
      }
    }
    $result = [
      'counts' => $counts,
      'alert_count' => $alertCount,
      'alert_packages' => array_keys($matching),
      'psas' => array_column($psas, 'title'),
      'from_cache' => $cached !== NULL,
    ];

    if (!$matching && !$psas) {
      $this->logger->info('security advisory alert: no vulnerabilities at configured severity levels and no PSA.');
      return ['status' => 'clean'] + $result;
    }
    if (!empty($cached['email_sent'])) {
      $this->logger->info('security advisory alert: skipped, email already sent for this install in the current cycle.');
      return ['status' => 'already_sent'] + $result;
    }

    $this->logger->warning('security advisory alert: found @count advisory/ies in @pkg package(s) and @psa PSA(s).', [
      '@count' => $alertCount,
      '@pkg' => count($matching),
      '@psa' => count($psas),
    ]);
    $params = [
      'matching' => $matching,
      'count' => $alertCount,
      'all_vulns' => $vulns,
      'installed' => $installed,
      'psas' => $psas,
    ];
    // Claim the cycle before sending: a send that throws or reports failure
    // after the mail went out must not make every other site resend it.
    // ponytail: at most one alert per cycle, a real failure is only logged
    // and retried by the next daily run.
    $this->storage->setCache($hash, $vulns, TRUE);
    if (!$this->sendAlert($params, $config->get('recipients') ?? '')) {
      return ['status' => 'not_sent'] + $result;
    }
    return ['status' => 'sent'] + $result;
  }

  /**
   * Adds the severity, fix versions and latest safe version to each advisory.
   *
   * '_latest_safe' is the package's latest stable release when that release
   * is not affected by the advisory, NULL otherwise.
   *
   * @param array<string, array> $vulnsByPackage
   *   OSV vulnerabilities keyed by package name.
   * @param array<string, string> $sources
   *   Package name => Composer notification-url.
   *
   * @return array<string, array>
   *   The same, with '_severity', '_fix' and '_latest_safe' keys added.
   */
  protected function annotate(array $vulnsByPackage, array $sources): array {
    $annotated = [];
    foreach ($vulnsByPackage as $package => $vulns) {
      // Once per package, not once per advisory.
      $latest = $this->fetcher->fetchLatestStable($package, $sources[$package] ?? '');
      foreach ($vulns as $vuln) {
        $safe = $latest && !$this->analyzer->isAffected($vuln, $package, $latest);
        $annotated[$package][] = $vuln + [
          '_severity' => $this->analyzer->severity($vuln),
          '_fix' => $this->analyzer->fixedVersions($vuln, $package),
          '_latest_safe' => $safe ? $latest : NULL,
        ];
      }
    }
    return $annotated;
  }

  /**
   * Keeps the advisories whose severity is one of the configured levels.
   *
   * @param array<string, array> $vulnsByPackage
   *   Annotated vulnerabilities keyed by package name.
   * @param string[] $severities
   *   The severity levels to keep.
   *
   * @return array<string, array>
   *   The matching vulnerabilities keyed by package name.
   */
  protected function filterBySeverity(array $vulnsByPackage, array $severities): array {
    $matching = [];
    foreach ($vulnsByPackage as $package => $vulns) {
      foreach ($vulns as $vuln) {
        if (in_array($vuln['_severity'] ?? 'unknown', $severities, TRUE)) {
          $matching[$package][] = $vuln;
        }
      }
    }
    return $matching;
  }

  /**
   * Returns drupal.org PSAs for projects present in the codebase.
   *
   * PSAs announce upcoming security releases: they have no affected versions
   * yet, so OSV / composer audit can't see them. Core's fetcher reads
   * https://updates.drupal.org/psa.json (stored for
   * system.advisories:interval_hours) and keeps only projects in the codebase.
   *
   * @return array<int, array{title: string, url: string, project: string}>
   *   The applicable PSAs.
   */
  protected function fetchPsas(): array {
    try {
      $advisories = $this->psaFetcher->getSecurityAdvisories(TRUE, 10) ?? [];
    }
    catch (\Exception $e) {
      $this->logger->warning('security advisory alert: could not fetch drupal.org PSA feed: @msg', [
        '@msg' => $e->getMessage(),
      ]);
      return [];
    }
    $psas = [];
    foreach ($advisories as $advisory) {
      if ($advisory->isPsa()) {
        $psas[] = [
          'title' => $advisory->getTitle(),
          'url' => $advisory->getUrl(),
          'project' => $advisory->getProject(),
        ];
      }
    }
    return $psas;
  }

  /**
   * Sends the alert email to every recipient.
   *
   * @param array $params
   *   The hook_mail() parameters (see AlertMailBuilder::build()).
   * @param string $recipients
   *   Email addresses, one per line or comma-separated.
   *
   * @return bool
   *   TRUE if at least one email was sent.
   */
  protected function sendAlert(array $params, string $recipients): bool {
    $recipients = array_filter(array_map('trim', preg_split('/[\r\n,]+/', $recipients)));
    if (!$recipients) {
      $this->logger->warning('security advisory alert: vulnerabilities found but no recipients configured.');
      return FALSE;
    }

    $langcode = $this->languageManager->getDefaultLanguage()->getId();
    $sent = FALSE;
    foreach ($recipients as $email) {
      $result = $this->mailManager->mail('security_advisory_alert', 'vulnerabilities_alert', $email, $langcode, $params);
      if (!$result['result']) {
        $this->logger->error('security advisory alert: failed to send alert to @email.', [
          '@email' => $email,
        ]);
      }
      $sent = $sent || $result['result'];
    }
    return $sent;
  }

  /**
   * Logs an error and returns it as an audit result.
   *
   * @param string $message
   *   The error message.
   *
   * @return array
   *   The error result.
   */
  protected function error(string $message): array {
    $this->logger->error('security advisory alert: @msg', ['@msg' => $message]);
    return ['status' => 'error', 'error' => $message];
  }

}
