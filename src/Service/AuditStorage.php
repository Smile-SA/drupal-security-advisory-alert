<?php

namespace Drupal\security_advisory_alert\Service;

use Drupal\Component\FileSecurity\FileSecurity;
use Drupal\Core\Logger\LoggerChannelFactoryInterface;
use Psr\Log\LoggerInterface;

/**
 * Lock, cache and last result shared by all sites of a codebase.
 *
 * Sites of a multisite share the filesystem but not their database, so the
 * state lives in a private temporary directory, one per project: mode 2770,
 * so only its owner and group (e.g. www-data) can use it, and new files
 * inherit the group so PHP-FPM and cron can share it. /tmp is world-writable:
 * the directory is refused if it is a symlink or belongs neither to the
 * current user nor to its group, since another account could otherwise
 * pre-create it to read or tamper with the files.
 *
 * Several front servers each have their own /tmp, so sites/ (shared storage
 * across fronts on prod) is used first, /tmp only when sites/ is not
 * writable (e.g. local dev). sites/ is in the webroot: a deny-all .htaccess
 * is written in the directory.
 */
class AuditStorage {

  /**
   * Cache lifetime: spans one daily run across all sites, expired by the next.
   */
  protected const CACHE_TTL = 43200;

  /**
   * The module's logger channel.
   */
  protected LoggerInterface $logger;

  /**
   * Constructs an AuditStorage.
   *
   * @param \Drupal\Core\Logger\LoggerChannelFactoryInterface $loggerFactory
   *   The logger channel factory.
   * @param string $root
   *   The Drupal root, identifies the project.
   */
  public function __construct(
    LoggerChannelFactoryInterface $loggerFactory,
    protected string $root,
  ) {
    $this->logger = $loggerFactory->get('security_advisory_alert');
  }

  /**
   * Acquires the exclusive cross-site lock, waiting for it if needed.
   *
   * @return resource|null
   *   The lock handle, or NULL if it could not be acquired (logged).
   */
  public function acquireLock() {
    $path = $this->path('lock');
    $lock = $path ? @fopen($path, 'c') : FALSE;
    if (!$lock || !flock($lock, LOCK_EX)) {
      $this->logger->error('security advisory alert: cannot acquire the lock.');
      return NULL;
    }
    @chmod($path, 0660);
    return $lock;
  }

  /**
   * Releases a lock acquired with acquireLock().
   *
   * @param resource $lock
   *   The lock handle.
   */
  public function releaseLock($lock): void {
    flock($lock, LOCK_UN);
    fclose($lock);
  }

  /**
   * Returns cached audit data for an install, if fresh.
   *
   * @param string $lockHash
   *   The md5 hash of vendor/composer/installed.json.
   *
   * @return array|null
   *   ['vulns' => [...], 'email_sent' => bool], or NULL if expired/absent.
   */
  public function getCache(string $lockHash): ?array {
    $path = $this->path($lockHash . '.json');
    if (!$path || !file_exists($path) || time() - filemtime($path) >= static::CACHE_TTL) {
      return NULL;
    }
    $data = json_decode((string) file_get_contents($path), TRUE);
    return isset($data['vulns']) ? $data : NULL;
  }

  /**
   * Stores audit data for an install.
   *
   * @param string $lockHash
   *   The md5 hash of vendor/composer/installed.json.
   * @param array<string, array> $vulns
   *   Annotated vulnerabilities keyed by package name.
   * @param bool $emailSent
   *   Whether the alert email was sent in this cycle.
   */
  public function setCache(string $lockHash, array $vulns, bool $emailSent): void {
    $data = json_encode(['vulns' => $vulns, 'email_sent' => $emailSent]);
    if (!$this->write($lockHash . '.json', $data)) {
      $this->logger->warning('security advisory alert: cannot write the cache, other sites may send the alert again.');
    }
  }

  /**
   * Returns the last audit result of the codebase, or NULL.
   */
  public function getLastResult(): ?array {
    $path = $this->path('last.json');
    $data = $path ? @file_get_contents($path) : FALSE;
    return $data ? json_decode($data, TRUE) : NULL;
  }

  /**
   * Stores the last audit result of the codebase.
   *
   * @param array $result
   *   The result returned by AdvisoryChecker::runAudit().
   */
  public function setLastResult(array $result): void {
    $this->write('last.json', json_encode($result));
  }

  /**
   * Writes a file readable and writable by owner and group only.
   *
   * @param string $name
   *   The file name.
   * @param string $data
   *   The content.
   *
   * @return bool
   *   TRUE on success.
   */
  protected function write(string $name, string $data): bool {
    $path = $this->path($name);
    if (!$path || @file_put_contents($path, $data) === FALSE) {
      return FALSE;
    }
    @chmod($path, 0660);
    return TRUE;
  }

  /**
   * Returns the path of a file in the project's private directory.
   *
   * @param string $name
   *   The file name.
   *
   * @return string|null
   *   The path, or NULL if the directory is unsafe or cannot be created.
   */
  protected function path(string $name): ?string {
    $dir = $this->directory();
    return $dir ? $dir . '/' . $name : NULL;
  }

  /**
   * Returns the project's private directory, creating it if needed.
   *
   * @return string|null
   *   The directory, or NULL if it is unsafe or cannot be created (logged).
   */
  protected function directory(): ?string {
    $dir = $this->root . '/sites/.security_advisory_alert';
    if (!is_dir($dir) && !is_writable($this->root . '/sites')) {
      // Keyed by project path so several projects on a server stay separate.
      // Ansistrano's "releases/<id>" is stripped: the key survives deploys.
      $project = preg_replace('#/releases/[^/]+#', '', dirname($this->root));
      $dir = sys_get_temp_dir() . '/security_advisory_alert_' . substr(md5($project), 0, 12);
    }
    if (!file_exists($dir) && @mkdir($dir, 0770)) {
      @chmod($dir, 02770);
    }
    if (is_dir($dir) && !is_link($dir)) {
      FileSecurity::writeHtaccess($dir);
    }
    clearstatcache(TRUE, $dir);
    $trusted = !function_exists('posix_geteuid')
      || fileowner($dir) === posix_geteuid()
      || filegroup($dir) === posix_getegid();
    if (is_link($dir) || !is_dir($dir) || !$trusted || !is_writable($dir)) {
      $this->logger->error('security advisory alert: temporary directory @dir is not safe (symlink, foreign owner/group) or not writable.', [
        '@dir' => $dir,
      ]);
      return NULL;
    }
    return $dir;
  }

}
