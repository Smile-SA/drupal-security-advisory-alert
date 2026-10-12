<?php

namespace Drupal\security_advisory_alert;

/**
 * Interprets OSV vulnerability objects: severity, fix versions, ranges.
 *
 * Pure logic, no I/O.
 *
 * @see https://ossf.github.io/osv-schema/
 */
final class AdvisoryAnalyzer {

  /**
   * Severity levels, most severe first.
   */
  public const SEVERITIES = ['critical', 'high', 'medium', 'low', 'unknown'];

  /**
   * Derives a normalised severity level for an OSV vulnerability.
   *
   * Tries the source database label, then the CVSS vector, then keyword
   * analysis of the text (summary carries drupal.org SA risk labels).
   *
   * @param array $vuln
   *   The OSV vulnerability.
   *
   * @return string
   *   One of self::SEVERITIES.
   */
  public function severity(array $vuln): string {
    // 1. Reviewed label from the source database
    // (GitHub: LOW/MODERATE/HIGH/CRITICAL).
    $label = strtolower($vuln['database_specific']['severity'] ?? '');
    if ($label) {
      $label = $label === 'moderate' ? 'medium' : $label;
      return in_array($label, self::SEVERITIES, TRUE) ? $label : 'unknown';
    }

    // 2. CVSS vector (e.g. "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H").
    foreach ($vuln['severity'] ?? [] as $severity) {
      if (in_array($severity['type'] ?? '', ['CVSS_V3', 'CVSS_V4'], TRUE)) {
        return $this->cvssVectorToSeverity($severity['score'] ?? '');
      }
    }

    // 3. Text search in details / summary.
    $text = strtolower(($vuln['details'] ?? '') . ' ' . ($vuln['summary'] ?? ''));
    return $this->severityFromText($text);
  }

  /**
   * Extracts the fixed versions for a package from an OSV vulnerability.
   *
   * Collects every 'fixed' event from ECOSYSTEM ranges targeting the package.
   *
   * @param array $vuln
   *   The OSV vulnerability.
   * @param string $package
   *   The package name.
   *
   * @return string[]
   *   The fixed versions.
   */
  public function fixedVersions(array $vuln, string $package): array {
    $fixed = [];
    foreach ($this->ecosystemRanges($vuln, $package) as $range) {
      foreach ($range['events'] ?? [] as $event) {
        if (isset($event['fixed'])) {
          $fixed[] = $event['fixed'];
        }
      }
    }
    return array_values(array_unique($fixed));
  }

  /**
   * Checks whether a version is affected by an OSV vulnerability.
   *
   * @param array $vuln
   *   The OSV vulnerability.
   * @param string $package
   *   The package name.
   * @param string $version
   *   The version to check.
   *
   * @return bool
   *   TRUE if the version falls in an open or closed affected range.
   */
  public function isAffected(array $vuln, string $package, string $version): bool {
    foreach ($this->ecosystemRanges($vuln, $package) as $range) {
      $introduced = NULL;
      foreach ($range['events'] ?? [] as $event) {
        if (isset($event['introduced'])) {
          $introduced = $event['introduced'] === '0' ? '0.0.0' : $event['introduced'];
        }
        elseif (isset($event['fixed']) && $introduced !== NULL) {
          if (version_compare($version, $introduced, '>=') && version_compare($version, $event['fixed'], '<')) {
            return TRUE;
          }
          $introduced = NULL;
        }
      }
      // Open range (introduced but no fixed yet = still vulnerable branch).
      if ($introduced !== NULL && version_compare($version, $introduced, '>=')) {
        return TRUE;
      }
    }
    return FALSE;
  }

  /**
   * Returns the ECOSYSTEM version ranges of a vulnerability for a package.
   *
   * @param array $vuln
   *   The OSV vulnerability.
   * @param string $package
   *   The package name.
   *
   * @return array[]
   *   The OSV range objects.
   */
  private function ecosystemRanges(array $vuln, string $package): array {
    $ranges = [];
    foreach ($vuln['affected'] ?? [] as $affected) {
      if (strtolower($affected['package']['name'] ?? '') !== strtolower($package)) {
        continue;
      }
      foreach ($affected['ranges'] ?? [] as $range) {
        if (($range['type'] ?? '') === 'ECOSYSTEM') {
          $ranges[] = $range;
        }
      }
    }
    return $ranges;
  }

  /**
   * Converts a CVSS v3/v4 vector string to a normalised severity label.
   *
   * Applies a lightweight heuristic on C/I/A impact + attack vector rather
   * than implementing the full CVSS scoring algorithm.
   *
   * @param string $vector
   *   The CVSS vector.
   *
   * @return string
   *   One of self::SEVERITIES.
   */
  private function cvssVectorToSeverity(string $vector): string {
    preg_match_all('/([A-Z]{1,3}):([A-Z]+)/', $vector, $m);
    if (empty($m[1])) {
      return 'unknown';
    }
    $metrics = array_combine($m[1], $m[2]);

    // CVSS v4 names the vulnerable-system impacts VC/VI/VA (v3: C/I/A).
    $impacts = [
      $metrics['C'] ?? $metrics['VC'] ?? 'N',
      $metrics['I'] ?? $metrics['VI'] ?? 'N',
      $metrics['A'] ?? $metrics['VA'] ?? 'N',
    ];
    $highImpact = count(array_keys($impacts, 'H', TRUE));
    $network = ($metrics['AV'] ?? 'L') === 'N';
    $lowPrivileges = in_array($metrics['PR'] ?? 'H', ['N', 'L'], TRUE);

    if ($highImpact >= 2 && $network && $lowPrivileges) {
      return 'critical';
    }
    if ($highImpact >= 1 && $network) {
      return 'high';
    }
    return $highImpact >= 1 ? 'medium' : 'low';
  }

  /**
   * Extracts a normalised severity from free-form advisory text.
   *
   * Priority order: explicit SA labels > known critical patterns > known
   * vuln-type heuristics.
   *
   * @param string $text
   *   The lower-cased advisory details and summary.
   *
   * @return string
   *   One of self::SEVERITIES; 'unknown' when no signal is found.
   */
  private function severityFromText(string $text): string {
    $patterns = [
      // Explicit drupal.org SA risk labels (most specific first).
      '/\bhighly\s+critical\b/' => 'critical',
      '/\bmoderately\s+critical\b/' => 'high',
      '/\bless\s+critical\b/' => 'medium',
      '/\bnot\s+critical\b/' => 'low',
      '/\bcritical\b/' => 'critical',
      // Vulnerability types.
      '/remote\s+code\s+exec|arbitrary\s+(php\s+)?code\s+exec|sql\s+injection/' => 'critical',
      '/php\s+object\s+injection|deserialization|authentication\s+bypass|privilege\s+escalat/' => 'high',
      '/server.side\s+request|ssrf\b|open\s+redirect/' => 'high',
      '/cross.site\s+scripting|\bxss\b|cache\s+poison|access\s+bypass|csrf\b/' => 'medium',
      '/information\s+disclosure|path\s+traversal|arbitrary\s+file\s+read/' => 'medium',
      '/denial\s+of\s+service|\bdos\b|brute\s+force|information\s+leak/' => 'low',
    ];
    foreach ($patterns as $pattern => $severity) {
      if (preg_match($pattern . 'i', $text)) {
        return $severity;
      }
    }
    return 'unknown';
  }

}
